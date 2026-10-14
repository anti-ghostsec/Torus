//! Converting visitors' videos, in a process apart.
//!
//! Decoding video means running a very large decoder on a stranger's file.
//! That happens in a second copy of this program which the editor starts in
//! a container with no network and no files, and which runs the converter
//! as its only child. The host hands it a video over a pipe and gets back a
//! picture or a smaller video over another. If a file ever takes over the
//! decoder, what it has taken over can talk to nobody and read nothing.
//!
//! On the pipes, both ways, data travels in pieces: a four-byte length and
//! that many bytes, ended by a length of zero. A request starts with what
//! to make; an answer ends with one byte saying whether it worked.

use std::fs::File;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use torus_host_api::{pipe_ends, CONVERTER_LINK, CONVERTER_PROGRAM, CONVERTER_ROLE};
use torus_runtime::{Converter, Job};

const PIECE: usize = 64 * 1024;
/// A conversion still running after this long is stopped.
const LONGEST: Duration = Duration::from_secs(3 * 60 * 60);
const LONGEST_STILL: Duration = Duration::from_secs(120);

fn send(to: &mut impl Write, data: &[u8]) -> io::Result<()> {
    for piece in data.chunks(PIECE) {
        to.write_all(&(piece.len() as u32).to_le_bytes())?;
        to.write_all(piece)?;
    }
    Ok(())
}

fn end(to: &mut impl Write) -> io::Result<()> {
    to.write_all(&0u32.to_le_bytes())?;
    to.flush()
}

/// The next piece, or `None` at the end of the data.
fn receive(from: &mut impl Read, piece: &mut Vec<u8>) -> io::Result<Option<()>> {
    let mut length = [0u8; 4];
    from.read_exact(&mut length)?;
    let length = u32::from_le_bytes(length) as usize;
    if length > PIECE {
        return Err(io::ErrorKind::InvalidData.into());
    }
    piece.resize(length, 0);
    from.read_exact(piece)?;
    Ok((length > 0).then_some(()))
}

// The host's side

/// A converter at the far end of a pair of pipes.
pub struct Piped(Mutex<(File, File)>);

impl Piped {
    /// The converter the editor started beside this host, if it did.
    pub fn from_surroundings() -> Option<Self> {
        pipe_ends(CONVERTER_LINK).map(|ends| Self(Mutex::new(ends)))
    }
}

impl Converter for Piped {
    fn convert(
        &self,
        job: Job,
        input: &mut (dyn Iterator<Item = torus_runtime::Bytes> + Send),
        output: &mut (dyn FnMut(&[u8]) -> bool + Send),
    ) -> bool {
        let mut ends = self.0.lock().unwrap_or_else(|e| e.into_inner());
        let (from, to) = &mut *ends;
        let (kind, pixels) = match job {
            Job::Still => (1u8, 0u32),
            Job::Smaller(pixels) => (2, pixels),
            Job::Whole => (3, 0),
        };
        let asked = to.write_all(&[kind]).and_then(|()| to.write_all(&pixels.to_le_bytes()));
        if asked.is_err() {
            return false;
        }
        // The video goes out while the result comes back: waiting for one
        // before the other would leave both sides stuck on a full pipe.
        std::thread::scope(|scope| {
            scope.spawn(move || {
                let mut sending = true;
                for piece in input {
                    sending = sending && send(to, &piece).is_ok();
                }
                let _ = end(to);
            });
            let mut wanted = true;
            let mut piece = Vec::new();
            loop {
                match receive(from, &mut piece) {
                    Ok(Some(())) => wanted = wanted && output(&piece),
                    Ok(None) => break,
                    Err(_) => return false,
                }
            }
            let mut worked = [0u8];
            from.read_exact(&mut worked).is_ok() && worked[0] == 1 && wanted
        })
    }
}

// The converter's side

fn arguments(kind: u8, pixels: u32) -> Option<Vec<String>> {
    let mut all: Vec<String> = ["-hide_banner", "-loglevel", "error", "-nostats", "-protocol_whitelist", "pipe", "-i", "pipe:0"]
        .map(String::from)
        .to_vec();
    let mut add = |more: &[&str]| all.extend(more.iter().map(|one| (*one).to_owned()));
    // Only the first picture and sound tracks are read; subtitles, data
    // tracks, descriptions and chapters are never carried over.
    let video = |add: &mut dyn FnMut(&[&str]), scale: &str, quality: &str, sound: &str| {
        add(&["-map", "0:v:0", "-map", "0:a:0?", "-sn", "-dn", "-map_metadata", "-1", "-map_chapters", "-1"]);
        add(&["-vf", scale, "-c:v", "libvpx-vp9", "-crf", quality, "-b:v", "0", "-deadline", "good", "-cpu-used", "5"]);
        add(&["-row-mt", "1", "-pix_fmt", "yuv420p", "-c:a", "libopus", "-b:a", sound, "-ac", "2"]);
        add(&["-bitexact", "-f", "webm", "pipe:1"]);
    };
    match (kind, pixels) {
        (1, _) => add(&["-map", "0:v:0", "-vf", "thumbnail=90", "-frames:v", "1", "-an", "-sn", "-dn", "-map_metadata", "-1", "-f", "image2pipe", "-c:v", "png", "pipe:1"]),
        (2, 360) => video(&mut add, "scale='if(gt(iw,ih),-2,360)':'if(gt(iw,ih),360,-2)'", "36", "64k"),
        (2, 720) => video(&mut add, "scale='if(gt(iw,ih),-2,720)':'if(gt(iw,ih),720,-2)'", "34", "96k"),
        (3, _) => video(&mut add, "scale=trunc(iw/2)*2:trunc(ih/2)*2", "33", "128k"),
        _ => return None,
    }
    Some(all)
}

/// Does one conversion. `Err` only when the pipes to the host have failed.
fn serve_one(from: &mut File, to: &mut File, program: &Path, kind: u8, pixels: u32) -> io::Result<()> {
    let mut launch = Command::new(program);
    launch.env_clear().stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null());
    if let Some(root) = std::env::var_os("SystemRoot") {
        launch.env("SystemRoot", root);
    }
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        launch.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    let child = arguments(kind, pixels).and_then(|arguments| launch.args(arguments).spawn().ok());
    let mut piece = Vec::new();
    let Some(mut child) = child else {
        // Nothing to convert with: the video is still read to its end, so
        // that the two sides stay in step.
        while receive(from, &mut piece)?.is_some() {}
        end(to)?;
        return to.write_all(&[0]);
    };
    let (mut feed, mut result) = (child.stdin.take(), child.stdout.take().expect("piped above"));
    let child = Mutex::new(child);
    let finished = AtomicBool::new(false);
    let longest = if kind == 1 { LONGEST_STILL } else { LONGEST };

    let passed = std::thread::scope(|scope| -> io::Result<()> {
        // Feeds the video in.
        let feeding = scope.spawn(|| -> io::Result<()> {
            let mut piece = Vec::new();
            while receive(from, &mut piece)?.is_some() {
                // Once the converter has stopped reading, the rest is read and dropped.
                if feed.as_mut().is_some_and(|feed| feed.write_all(&piece).is_err()) {
                    feed = None;
                }
            }
            drop(feed.take());
            Ok(())
        });
        // Stops a conversion that will not end.
        scope.spawn(|| {
            let started = Instant::now();
            while !finished.load(Ordering::Relaxed) {
                if started.elapsed() > longest {
                    let _ = child.lock().unwrap_or_else(|e| e.into_inner()).kill();
                    return;
                }
                std::thread::sleep(Duration::from_millis(200));
            }
        });
        // Passes the result back.
        let mut passing = Ok(());
        let mut buffer = vec![0u8; PIECE];
        loop {
            match result.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(count) => {
                    if passing.is_ok() {
                        passing = send(to, &buffer[..count]);
                    }
                }
            }
        }
        finished.store(true, Ordering::Relaxed);
        feeding.join().unwrap_or(Ok(())).and(passing)
    });
    let worked = child.lock().unwrap_or_else(|e| e.into_inner()).wait().is_ok_and(|status| status.success());
    passed?;
    end(to)?;
    to.write_all(&[u8::from(worked)])?;
    to.flush()
}

/// What a process can reach: a listener on this machine at `port`, the
/// internet, and the file at `path`. The converter answers this about
/// itself so that its confinement can be checked from outside.
pub fn reach(port: u16, path: &Path) -> [bool; 3] {
    use std::net::{SocketAddr, TcpStream};
    let connects = |to: SocketAddr| TcpStream::connect_timeout(&to, Duration::from_secs(4)).is_ok();
    [connects(([127, 0, 0, 1], port).into()), connects(([1, 1, 1, 1], 443).into()), File::open(path).is_ok()]
}

/// Answers a request to say what this process can reach.
fn probe(from: &mut File, to: &mut File, port: u32) -> io::Result<()> {
    let (mut path, mut piece) = (Vec::new(), Vec::new());
    while receive(from, &mut piece)?.is_some() {
        if path.len() < 4096 {
            path.extend_from_slice(&piece);
        }
    }
    let reached = reach(port as u16, Path::new(&String::from_utf8_lossy(&path).into_owned()));
    send(to, &reached.map(u8::from))?;
    end(to)?;
    to.write_all(&[1])?;
    to.flush()
}

/// The request that asks a converter what it can reach.
pub const PROBE: u8 = 9;

/// Runs as a converter if this program was started as one: serves requests
/// until the host goes away, and returns the code to exit with.
pub fn serve_if_converter() -> Option<i32> {
    let (mut from, mut to) = pipe_ends(CONVERTER_ROLE)?;
    let program = PathBuf::from(std::env::var_os(CONVERTER_PROGRAM)?);
    loop {
        let mut request = [0u8; 5];
        if from.read_exact(&mut request).is_err() {
            return Some(0);
        }
        let pixels = u32::from_le_bytes([request[1], request[2], request[3], request[4]]);
        let served = match request[0] {
            PROBE => probe(&mut from, &mut to, pixels),
            kind => serve_one(&mut from, &mut to, &program, kind, pixels),
        };
        if served.is_err() {
            return Some(1);
        }
    }
}
