//! Publishes a web app that is already running on this machine (Fauna, say)
//! as a Tor onion service, with Tor running inside this process (Arti). There
//! is no Tor daemon to install and no listening socket for visitors: their
//! streams arrive from the Tor network and are passed to the app's loopback
//! port.
//!
//!   torus-gateway address --key FILE              print the address (makes a key if there is none)
//!   torus-gateway mine --key FILE PREFIX...       find a key whose address starts with PREFIX
//!   torus-gateway serve --key FILE --data DIR --to 127.0.0.1:3000 [--with-parent]
//!
//! With --with-parent, serve exits as soon as its stdin closes: the program
//! that started it holds the other end, so the onion service never outlives it.
//!
//! The key file is the service's secret identity: 64 bytes, readable only by
//! its owner. Whoever has it owns the address, so back it up and keep it private.

use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

type Identity = Zeroizing<[u8; 64]>;

const USAGE: &str = "usage:
  torus-gateway address --key FILE
  torus-gateway mine --key FILE [--threads N] [--replace] PREFIX...
  torus-gateway serve --key FILE --data DIR --to HOST:PORT [--with-parent]";

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let result = match args.first().map(String::as_str) {
        Some("address") => address(&args[1..]),
        Some("mine") => mine(&args[1..]),
        Some("serve") => serve(&args[1..]),
        _ => Err(USAGE.to_owned()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("torus-gateway: {message}");
            ExitCode::FAILURE
        }
    }
}

/// `--name value` options and the words left over.
struct Args {
    options: Vec<(String, Option<String>)>,
    rest: Vec<String>,
}

impl Args {
    fn parse(args: &[String], flags: &[&str]) -> Self {
        let mut options = Vec::new();
        let mut rest = Vec::new();
        let mut it = args.iter();
        while let Some(a) = it.next() {
            if let Some(name) = a.strip_prefix("--") {
                if flags.contains(&name) {
                    options.push((name.to_owned(), None));
                } else {
                    options.push((name.to_owned(), it.next().cloned()));
                }
            } else {
                rest.push(a.clone());
            }
        }
        Self { options, rest }
    }

    fn get(&self, name: &str) -> Option<&str> {
        self.options.iter().find(|(n, _)| n == name).and_then(|(_, v)| v.as_deref())
    }

    fn need(&self, name: &str) -> Result<&str, String> {
        self.get(name).ok_or_else(|| format!("--{name} is needed\n{USAGE}"))
    }

    fn flag(&self, name: &str) -> bool {
        self.options.iter().any(|(n, _)| n == name)
    }
}

fn read_key(path: &Path) -> Result<Option<Identity>, String> {
    let mut file = match File::open(path) {
        Ok(f) => f,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot read {}: {e}", path.display())),
    };
    private_file(path, &file)?;
    let mut key = Zeroizing::new([0u8; 64]);
    let mut extra = [0u8; 1];
    file.read_exact(key.as_mut()).map_err(|_| format!("{} is not an onion key", path.display()))?;
    if file.read(&mut extra).map_err(|e| e.to_string())? != 0 {
        return Err(format!("{} is not an onion key", path.display()));
    }
    // Rejects bytes that aren't a valid key before anything is published with them.
    torus_tor::address(&key).map_err(|e| e.to_string())?;
    Ok(Some(key))
}

/// Like Tor, refuses a key that other users of this machine could read or
/// swap: anyone who can read it owns the address.
#[cfg(unix)]
fn private_file(path: &Path, file: &File) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;
    let meta = file.metadata().map_err(|e| format!("cannot check {}: {e}", path.display()))?;
    if meta.mode() & 0o077 != 0 {
        return Err(format!(
            "{} can be read by other users of this machine; make it private first: chmod 600 {}",
            path.display(),
            path.display()
        ));
    }
    // SAFETY: getuid cannot fail and touches no memory.
    if meta.uid() != unsafe { libc_getuid() } {
        return Err(format!("{} belongs to another user", path.display()));
    }
    Ok(())
}

#[cfg(unix)]
extern "C" {
    #[link_name = "getuid"]
    fn libc_getuid() -> u32;
}

/// On Windows a key's permissions are not checked when it is read: telling
/// whether an access list lets anyone else in needs more than this program
/// carries. Keys this program writes are made private as they are written
/// (see [`write_key`]); one copied in from elsewhere keeps whatever access
/// list it was given, so keep it in a folder only you can open.
#[cfg(not(unix))]
fn private_file(_: &Path, _: &File) -> Result<(), String> {
    Ok(())
}

/// Makes a folder (and its parents) that only this user can enter.
fn private_dir(dir: &Path) -> Result<(), String> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
        builder.mode(0o700);
        builder.create(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
        // An existing folder keeps its mode; tighten it.
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700)).map_err(|e| format!("cannot protect {}: {e}", dir.display()))?;
    }
    #[cfg(not(unix))]
    {
        let new = !dir.exists();
        builder.create(dir).map_err(|e| format!("cannot make {}: {e}", dir.display()))?;
        // A folder made here gets nothing from the folders above: this user
        // alone. One that was already there, which may be a folder of the
        // user's own such as Documents, keeps its access list; the key
        // written into it is made private by itself.
        if new {
            torus_host_api::make_private(dir).map_err(|e| format!("cannot protect {}: {e}", dir.display()))?;
        }
    }
    Ok(())
}

/// Writes the key readable by its owner only, through a temporary file so a
/// half-written key never replaces a good one.
fn write_key(path: &Path, key: &Identity) -> Result<(), String> {
    if let Some(dir) = path.parent().filter(|d| !d.as_os_str().is_empty()) {
        private_dir(dir)?;
    }
    let tmp = path.with_extension("tmp");
    // A leftover from an interrupted write; never written through.
    let _ = fs::remove_file(&tmp);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    // Windows has no mode to create it with: it is made private while still
    // empty, before the key is written, and keeps that through the rename.
    #[cfg(not(unix))]
    torus_host_api::make_file_private(&tmp).map_err(|e| format!("cannot protect {}: {e}", tmp.display()))?;
    file.write_all(key.as_ref()).and_then(|_| file.sync_all()).map_err(|e| format!("cannot write {}: {e}", tmp.display()))?;
    fs::rename(&tmp, path).map_err(|e| format!("cannot save {}: {e}", path.display()))
}

fn key_or_new(path: &Path) -> Result<Identity, String> {
    if let Some(key) = read_key(path)? {
        return Ok(key);
    }
    let key = torus_onion_key::new_identity().map_err(|e| format!("no secure randomness: {e}"))?;
    write_key(path, &key)?;
    eprintln!("made a new onion key at {}", path.display());
    Ok(key)
}

fn address(args: &[String]) -> Result<(), String> {
    let args = Args::parse(args, &[]);
    let key = key_or_new(Path::new(args.need("key")?))?;
    println!("{}", torus_onion_key::address(&key));
    Ok(())
}

fn mine(args: &[String]) -> Result<(), String> {
    let args = Args::parse(args, &["replace"]);
    let path = PathBuf::from(args.need("key")?);
    if !args.flag("replace") && read_key(&path)?.is_some() {
        return Err(format!(
            "{} already holds a key, and replacing it changes the site's address for good. Add --replace if that is what you want.",
            path.display()
        ));
    }
    if args.rest.is_empty() {
        return Err(format!("say what the address should start with\n{USAGE}"));
    }
    let prefixes = args
        .rest
        .iter()
        .map(|p| torus_onion_key::Prefix::new(p).map_err(|e| format!("{p}: {e}")))
        .collect::<Result<Vec<_>, _>>()?;
    let threads = match args.get("threads") {
        Some(n) => n.parse::<usize>().map_err(|_| "--threads takes a number".to_owned())?.max(1),
        // Leaves one core for everything else.
        None => std::thread::available_parallelism().map(|n| n.get().saturating_sub(1).max(1)).unwrap_or(1),
    };
    let expected = torus_onion_key::expected_tries_any(&prefixes);
    eprintln!("mining on {threads} threads: about {expected:.0} keys to try on average");

    let stop = Arc::new(AtomicBool::new(false));
    let tried = Arc::new(AtomicU64::new(0));
    let (found_tx, found_rx) = std::sync::mpsc::channel::<Identity>();
    for _ in 0..threads {
        let (stop, tried, prefixes, found_tx) = (stop.clone(), tried.clone(), prefixes.clone(), found_tx.clone());
        std::thread::spawn(move || {
            if let Some(key) = torus_onion_key::mine_any(&prefixes, &stop, &tried) {
                stop.store(true, Ordering::Relaxed);
                let _ = found_tx.send(key);
            }
        });
    }
    drop(found_tx);

    let started = Instant::now();
    let key = loop {
        match found_rx.recv_timeout(Duration::from_secs(5)) {
            Ok(key) => break key,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                let n = tried.load(Ordering::Relaxed) as f64;
                let rate = n / started.elapsed().as_secs_f64().max(0.001);
                let left = ((expected - n).max(0.0) / rate.max(1.0)) as u64;
                eprintln!("{n:.0} tried, {rate:.0}/s, typically about {left}s more (luck varies a lot)");
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return Err("mining stopped without a result".into()),
        }
    };
    stop.store(true, Ordering::Relaxed);
    write_key(&path, &key)?;
    eprintln!("found after {:.0?}; saved to {}", started.elapsed(), path.display());
    println!("{}", torus_onion_key::address(&key));
    Ok(())
}

/// One gateway per Tor folder. Tor's own lock would stop a second one too,
/// but only after connecting, and with a message that doesn't say why.
/// The lock goes away with the process, however it ends.
fn lock(data: &Path) -> Result<File, String> {
    private_dir(data)?;
    let path = data.join("gateway.lock");
    let file = File::create(&path).map_err(|e| format!("cannot write {}: {e}", path.display()))?;
    match file.try_lock() {
        Ok(()) => Ok(file),
        Err(fs::TryLockError::WouldBlock) => Err(format!(
            "another gateway is already publishing from {} (is an older Fauna still running? stop it first)",
            data.display()
        )),
        Err(fs::TryLockError::Error(e)) => Err(format!("cannot lock {}: {e}", path.display())),
    }
}

fn serve(args: &[String]) -> Result<(), String> {
    let args = Args::parse(args, &["with-parent"]);
    let key = key_or_new(Path::new(args.need("key")?))?;
    let data = PathBuf::from(args.need("data")?);
    let target: SocketAddr = args.need("to")?.parse().map_err(|_| "--to takes HOST:PORT, like 127.0.0.1:3000".to_owned())?;
    if !target.ip().is_loopback() {
        return Err("--to must be a loopback address (127.0.0.1 or ::1), so the app is reachable only through Tor".into());
    }
    let _lock = lock(&data)?;
    if args.flag("with-parent") {
        std::thread::spawn(|| {
            let mut sink = [0u8; 64];
            while matches!(std::io::stdin().read(&mut sink), Ok(n) if n > 0) {}
            std::process::exit(0);
        });
    }

    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| e.to_string())?;
    runtime.block_on(async move {
        let address = torus_tor::address(&key).map_err(|e| e.to_string())?;
        // The first line on stdout is the address, for whoever started this.
        println!("{address}");
        eprintln!("connecting to Tor (the first time takes a minute or two)");
        let tor = torus_tor::Tor::connect(&data.join("state"), &data.join("cache")).await.map_err(|e| e.to_string())?;
        let onion = tor.launch_forward("site", &key, target).map_err(|e| e.to_string())?;
        eprintln!("publishing http://{address} -> {target}");

        let mut last = String::new();
        let mut was_reachable = false;
        loop {
            tokio::time::sleep(Duration::from_secs(5)).await;
            if onion.broken() {
                return Err(format!("the onion service stopped: {}", onion.state()));
            }
            let reachable = onion.reachable();
            if reachable && !was_reachable {
                println!("reachable");
                eprintln!("reachable at http://{address}");
            }
            was_reachable = reachable;
            let state = onion.state();
            if state != last {
                eprintln!("state: {state}");
                last = state;
            }
        }
    })
}
