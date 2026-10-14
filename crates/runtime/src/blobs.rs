//! Uploaded files.
//!
//! A file is stored in pieces of 64 KiB, each encrypted on its own, so any
//! part can be read without decrypting the rest: that is what lets a visitor
//! skip around in a video. Pictures are decoded and re-encoded on arrival,
//! which drops everything a camera or editing program wrote into the file.

use std::fs::File;
use std::io::{self, Cursor, Read, Seek, SeekFrom, Write};
use std::path::PathBuf;
use std::sync::Arc;

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hyper::body::Bytes;
use zeroize::Zeroizing;

const CHUNK: usize = 64 * 1024;
const TAG: usize = 16;
const PREFIX: usize = 16;
/// Without storage, files are held in memory, so they are kept small.
pub(crate) const MAX_IN_MEMORY: usize = 32 * 1024 * 1024;

/// Where new files go.
#[derive(Clone)]
pub(crate) enum Target {
    Memory,
    Disk { dir: PathBuf, key: Zeroizing<[u8; 32]> },
}

/// Where one stored file is read from.
#[derive(Clone)]
pub(crate) enum Source {
    Memory(Arc<Vec<u8>>),
    Disk { path: PathBuf, key: Zeroizing<[u8; 32]> },
}

pub(crate) fn random_id() -> io::Result<String> {
    let mut random = [0u8; 12];
    getrandom::getrandom(&mut random).map_err(io::Error::other)?;
    Ok(random.iter().map(|b| format!("{b:02x}")).collect())
}

fn nonce(prefix: &[u8; PREFIX], index: u64) -> XNonce {
    let mut nonce = [0u8; 24];
    nonce[..PREFIX].copy_from_slice(prefix);
    nonce[PREFIX..].copy_from_slice(&index.to_le_bytes());
    nonce.into()
}

/// A file that has arrived but is not yet part of any record.
pub(crate) struct Staged {
    pub id: String,
    pub size: u64,
    /// The contents, when files are held in memory.
    pub memory: Option<Vec<u8>>,
}

/// Receives a file piece by piece. Dropped before `finish`, it leaves nothing behind.
pub(crate) struct Writer {
    target: Target,
    id: String,
    prefix: [u8; PREFIX],
    file: Option<(File, PathBuf)>,
    pending: Vec<u8>,
    index: u64,
    size: u64,
    memory: Vec<u8>,
}

impl Writer {
    pub fn new(target: Target) -> io::Result<Self> {
        let id = random_id()?;
        let mut prefix = [0u8; PREFIX];
        getrandom::getrandom(&mut prefix).map_err(io::Error::other)?;
        let file = match &target {
            Target::Memory => None,
            Target::Disk { dir, .. } => {
                std::fs::create_dir_all(dir)?;
                let path = dir.join(format!("{id}.new"));
                let mut file = File::create(&path)?;
                file.write_all(&prefix)?;
                Some((file, path))
            }
        };
        Ok(Self { target, id, prefix, file, pending: Vec::new(), index: 0, size: 0, memory: Vec::new() })
    }

    fn seal(&mut self, piece: &[u8]) -> io::Result<()> {
        let (Target::Disk { key, .. }, Some((file, _))) = (&self.target, &mut self.file) else { return Ok(()) };
        let sealed = XChaCha20Poly1305::new(key.as_ref().into())
            .encrypt(&nonce(&self.prefix, self.index), piece)
            .map_err(|_| io::Error::other("could not encrypt a file"))?;
        self.index += 1;
        file.write_all(&sealed)
    }

    pub fn write(&mut self, data: &[u8]) -> io::Result<()> {
        self.size += data.len() as u64;
        if self.file.is_none() {
            if self.memory.len() + data.len() > MAX_IN_MEMORY {
                return Err(io::Error::other("the file is too large to hold in memory"));
            }
            self.memory.extend_from_slice(data);
            return Ok(());
        }
        self.pending.extend_from_slice(data);
        while self.pending.len() >= CHUNK {
            let piece: Vec<u8> = self.pending.drain(..CHUNK).collect();
            self.seal(&piece)?;
        }
        Ok(())
    }

    pub fn finish(mut self) -> io::Result<Staged> {
        let rest = std::mem::take(&mut self.pending);
        if !rest.is_empty() {
            self.seal(&rest)?;
        }
        let memory = match self.file.take() {
            None => Some(std::mem::take(&mut self.memory)),
            Some((file, path)) => {
                file.sync_all()?;
                drop(file);
                std::fs::rename(&path, path.with_extension(""))?;
                None
            }
        };
        Ok(Staged { id: self.id.clone(), size: self.size, memory })
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        if let Some((file, path)) = self.file.take() {
            drop(file);
            let _ = std::fs::remove_file(path);
        }
    }
}

/// Removes a stored file that no record ended up using.
pub(crate) fn discard(target: &Target, id: &str) {
    if let Target::Disk { dir, .. } = target {
        let _ = std::fs::remove_file(dir.join(id));
    }
}

/// Where a file that has arrived can be read from.
pub(crate) fn staged_source(target: &Target, staged: &Staged) -> Source {
    match target {
        Target::Disk { dir, key } => Source::Disk { path: dir.join(&staged.id), key: key.clone() },
        Target::Memory => Source::Memory(Arc::new(staged.memory.clone().unwrap_or_default())),
    }
}

/// Turns a frame taken from a video into the small picture shown on cards,
/// and tells how large the frame was. Decoded and encoded afresh like any
/// other picture, so nothing a converter might have added survives.
pub(crate) fn still(frame: &[u8]) -> Option<(Vec<u8>, u32, u32)> {
    let mut reader = image::ImageReader::new(Cursor::new(frame)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8_000);
    limits.max_image_height = Some(8_000);
    limits.max_alloc = Some(256 * 1024 * 1024);
    reader.limits(limits);
    let picture = reader.decode().ok()?;
    let (width, height) = (picture.width(), picture.height());
    let mut out = Cursor::new(Vec::new());
    let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 80);
    picture.thumbnail(480, 480).to_rgb8().write_with_encoder(encoder).ok()?;
    Some((out.into_inner(), width, height))
}

/// Stores a whole file at once.
pub(crate) fn store(target: &Target, contents: &[u8]) -> io::Result<Staged> {
    let mut writer = Writer::new(target.clone())?;
    writer.write(contents)?;
    writer.finish()
}

/// Yields `length` bytes of a file starting at `start`, decrypting only the
/// pieces that hold them. It ends early if the file is damaged.
pub(crate) fn read(source: Source, start: u64, length: u64) -> Box<dyn Iterator<Item = Bytes> + Send> {
    match source {
        Source::Memory(all) => {
            let from = (start as usize).min(all.len());
            let to = (start.saturating_add(length) as usize).min(all.len());
            // In pieces, so one response never copies a whole file at once.
            let pieces: Vec<Bytes> = all[from..to].chunks(CHUNK).map(Bytes::copy_from_slice).collect();
            Box::new(pieces.into_iter())
        }
        Source::Disk { path, key } => {
            let mut opened: Option<(File, [u8; PREFIX])> = None;
            let mut position = start;
            let end = start.saturating_add(length);
            Box::new(std::iter::from_fn(move || {
                if position >= end {
                    return None;
                }
                if opened.is_none() {
                    let mut file = File::open(&path).ok()?;
                    let mut prefix = [0u8; PREFIX];
                    file.read_exact(&mut prefix).ok()?;
                    opened = Some((file, prefix));
                }
                let (file, prefix) = opened.as_mut()?;
                let index = position / CHUNK as u64;
                file.seek(SeekFrom::Start(PREFIX as u64 + index * (CHUNK + TAG) as u64)).ok()?;
                let mut sealed = Vec::with_capacity(CHUNK + TAG);
                file.take((CHUNK + TAG) as u64).read_to_end(&mut sealed).ok()?;
                let piece =
                    XChaCha20Poly1305::new(key.as_ref().into()).decrypt(&nonce(prefix, index), sealed.as_slice()).ok()?;
                let from = (position - index * CHUNK as u64) as usize;
                let to = piece.len().min(from + (end - position) as usize);
                if from >= to {
                    return None;
                }
                position += (to - from) as u64;
                Some(Bytes::copy_from_slice(&piece[from..to]))
            }))
        }
    }
}

/// Tells an MP4 from a WebM by how the file starts. Anything else is refused,
/// whatever its name or the type the browser claimed for it.
pub(crate) fn video_type(start: &[u8]) -> Option<&'static str> {
    if start.len() >= 12 && &start[4..8] == b"ftyp" {
        Some("video/mp4")
    } else if start.starts_with(&[0x1a, 0x45, 0xdf, 0xa3]) {
        Some("video/webm")
    } else {
        None
    }
}

/// Decodes a picture and encodes it afresh, so that nothing but the pixels
/// survives: no camera model, no location, no editing history. `None` if it
/// is not a picture this server reads, or is unreasonably large.
pub(crate) fn clean_image(bytes: &[u8]) -> Option<(Vec<u8>, &'static str)> {
    let mut reader = image::ImageReader::new(Cursor::new(bytes)).with_guessed_format().ok()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(8_000);
    limits.max_image_height = Some(8_000);
    limits.max_alloc = Some(128 * 1024 * 1024);
    reader.limits(limits);
    let picture = reader.decode().ok()?;
    let mut out = Cursor::new(Vec::new());
    if picture.color().has_alpha() {
        picture.write_to(&mut out, image::ImageFormat::Png).ok()?;
        Some((out.into_inner(), "image/png"))
    } else {
        let encoder = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 85);
        picture.to_rgb8().write_with_encoder(encoder).ok()?;
        Some((out.into_inner(), "image/jpeg"))
    }
}
