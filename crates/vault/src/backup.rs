//! One file holding everything needed to move or restore an installation:
//! the vault and every site's data, exactly as they sit on disk.
//!
//! Nothing here adds or removes encryption. The vault is already sealed with
//! the passphrase, and each site's records, files and Tor bookkeeping are
//! already sealed with keys that live inside the vault. So a backup is a
//! plain archive of those sealed files: without the passphrase it opens
//! nothing, and with it, it restores an identical installation. The archive
//! is written and read as a stream, so a backup of many gigabytes of video
//! never has to fit in memory.
//!
//! Archive: `magic | repeated entries | end marker | digest`. An entry is a
//! 2-byte path length, the path (relative, `/`-separated), an 8-byte content
//! length, and the content. The end marker is a zero path length. The digest
//! is SHA-256 over everything before it, so a damaged or cut-short archive is
//! refused, and what it restored is removed again. (Archives from before the
//! digest, `TORUSBK1`, are still read.)
//!
//! What the digest cannot do is stop someone who holds the archive from
//! writing a new one: a full backup is made without a passphrase, and keying
//! it to the compartment that made it would tell whoever restores it with
//! the other passphrase that there is another. So someone who can change a
//! backup can leave files out, or put back older sealed copies of them, but
//! can never read or forge what is in them: every file is sealed already,
//! with keys only the vault holds. Restores take only the names this app
//! writes. A site file, which has a passphrase of its own, seals the digest
//! of what it carries (see [`export_only`]).

use sha2::{Digest, Sha256};
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Component, Path};

const MAGIC: &[u8; 8] = b"TORUSBK2";
/// Archives written before the digest was added.
const MAGIC_V1: &[u8; 8] = b"TORUSBK1";

/// Passes writes on, hashing them.
struct Hashing<'a, W: Write> {
    inner: &'a mut W,
    hash: Sha256,
}

impl<W: Write> Write for Hashing<'_, W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.hash.update(&buf[..written]);
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

/// Passes reads on, hashing them.
struct Hashed<'a, R: Read> {
    inner: &'a mut R,
    hash: Sha256,
}

impl<R: Read> Read for Hashed<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let read = self.inner.read(buf)?;
        self.hash.update(&buf[..read]);
        Ok(read)
    }
}

/// Every name a compartment's vault has had: the two neutral slots, and
/// the main and alternate names installations used before them.
pub const VAULT_FILES: [&str; 4] = ["a.vault", "b.vault", "project.vault", "alt.vault"];

/// Which names a whole installation's backup may restore: the vault files
/// and the sites' folders, nothing else.
pub fn installation_file(rel: &str) -> bool {
    VAULT_FILES.contains(&rel) || ["a-sites/", "b-sites/", "sites/", "alt-sites/", "tor/"].iter().any(|top| rel.starts_with(top))
}

/// Which names a site file may restore into the site's folder: what
/// visitors added, and its files.
pub fn site_file(rel: &str) -> bool {
    rel == "records.bin" || rel.starts_with("records.bin.files/")
}
/// A sane ceiling on a single path and a single file, to reject nonsense
/// from a damaged or hostile archive early.
const MAX_PATH: usize = 4096;
const MAX_FILE: u64 = 64 * 1024 * 1024 * 1024;
const CHUNK: usize = 1024 * 1024;

/// Which files, relative to `root`, a backup includes: everything the app
/// keeps, so that both the main and any alternate compartment are carried,
/// except the window's throwaway browser-engine folder and the readable Tor
/// folders. Carrying every compartment keeps a backup from revealing whether
/// a second passphrase exists, just as the files on disk do not.
fn included(root: &Path) -> io::Result<Vec<std::path::PathBuf>> {
    let mut files = Vec::new();
    gather(root, root, &mut files)?;
    files.sort();
    Ok(files)
}

fn gather(root: &Path, at: &Path, out: &mut Vec<std::path::PathBuf>) -> io::Result<()> {
    let entries = match fs::read_dir(at) {
        Ok(entries) => entries,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    for entry in entries {
        let path = entry?.path();
        // Links are never followed: a backup holds this app's own files only.
        let kind = fs::symlink_metadata(&path)?.file_type();
        let rel = path.strip_prefix(root).unwrap_or(&path);
        // Left out: the window's throwaway engine folder, and the readable
        // Tor folders (kept only while a site is online, and rebuilt from
        // the encrypted copy). Everything else is carried.
        let skip = rel
            .components()
            .any(|c| matches!(c.as_os_str().to_str(), Some("webview") | Some("state") | Some("cache")));
        if skip {
            continue;
        }
        if kind.is_dir() {
            gather(root, &path, out)?;
        } else if kind.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .components()
        .map(|c| c.as_os_str().to_string_lossy().into_owned())
        .collect::<Vec<_>>()
        .join("/")
}

/// Writes a backup of everything under `root` to `out`, as a stream.
pub fn export(root: &Path, out: &mut impl Write) -> io::Result<()> {
    export_only(root, out, &|_| true).map(|_| ())
}

/// Like [`export`], carrying only the files whose relative path `keep`
/// accepts. Returns the archive's digest, which [`unpack`] returns too.
pub fn export_only(root: &Path, out: &mut impl Write, keep: &dyn Fn(&str) -> bool) -> io::Result<[u8; 32]> {
    let mut out = Hashing { inner: out, hash: Sha256::new() };
    let out = &mut out;
    out.write_all(MAGIC)?;
    let mut buffer = vec![0u8; CHUNK];
    for path in included(root)? {
        let rel = relative(root, &path);
        if !keep(&rel) {
            continue;
        }
        let mut file = fs::File::open(&path)?;
        let length = file.metadata()?.len();
        out.write_all(&(rel.len() as u16).to_le_bytes())?;
        out.write_all(rel.as_bytes())?;
        out.write_all(&length.to_le_bytes())?;
        let mut left = length;
        while left > 0 {
            let want = left.min(CHUNK as u64) as usize;
            file.read_exact(&mut buffer[..want])?;
            out.write_all(&buffer[..want])?;
            left -= want as u64;
        }
    }
    out.write_all(&0u16.to_le_bytes())?;
    let digest: [u8; 32] = std::mem::take(&mut out.hash).finalize().into();
    out.inner.write_all(&digest)?;
    out.flush()?;
    Ok(digest)
}

/// The digest [`export_only`] would return for these files, without
/// writing them anywhere.
pub fn digest_only(root: &Path, keep: &dyn Fn(&str) -> bool) -> io::Result<[u8; 32]> {
    export_only(root, &mut io::sink(), keep)
}

/// A path from an archive, accepted only if it stays inside `root`: a
/// relative path of plain names, no `..`, no drive, no root.
fn safe_target(root: &Path, rel: &str) -> io::Result<std::path::PathBuf> {
    let path = Path::new(rel);
    let plain = !rel.is_empty() && path.components().all(|c| matches!(c, Component::Normal(_)));
    if !plain {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "a backup entry named a path outside the folder"));
    }
    Ok(root.join(path))
}

fn read_exact_or_none(input: &mut impl Read, buf: &mut [u8]) -> io::Result<bool> {
    match input.read_exact(buf) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => Ok(false),
        Err(e) => Err(e),
    }
}

/// Restores a backup made by [`export`] into `root`, which must not already
/// hold an installation (a restore never overwrites one). Streamed, so a
/// huge backup is written out piece by piece.
pub fn import(root: &Path, input: &mut impl Read) -> io::Result<()> {
    if VAULT_FILES.iter().any(|name| root.join(name).exists()) {
        return Err(io::Error::new(io::ErrorKind::AlreadyExists, "there is already a vault here"));
    }
    unpack(root, input, &installation_file).map(|_| ())
}

/// Writes out an archive made by [`export`] or [`export_only`] into `root`,
/// with the same checks on every path, whatever is already there. Only
/// names `allowed` accepts are taken. Returns the archive's digest (none for
/// one from before digests). On any failure, what it wrote is removed.
pub fn unpack(root: &Path, input: &mut impl Read, allowed: &dyn Fn(&str) -> bool) -> io::Result<Option<[u8; 32]>> {
    let mut written = Vec::new();
    let unpacked = unpack_into(root, input, allowed, &mut written);
    if unpacked.is_err() {
        for file in written.iter().rev() {
            let _ = fs::remove_file(file);
        }
    }
    unpacked
}

fn unpack_into(
    root: &Path,
    input: &mut impl Read,
    allowed: &dyn Fn(&str) -> bool,
    written: &mut Vec<std::path::PathBuf>,
) -> io::Result<Option<[u8; 32]>> {
    let mut input = Hashed { inner: input, hash: Sha256::new() };
    let input = &mut input;
    let mut magic = [0u8; 8];
    input.read_exact(&mut magic)?;
    let digested = match &magic {
        m if m == MAGIC => true,
        m if m == MAGIC_V1 => false,
        _ => return Err(io::Error::new(io::ErrorKind::InvalidData, "this is not a Torus backup")),
    };
    fs::create_dir_all(root)?;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let mut path_len = [0u8; 2];
        if !read_exact_or_none(input, &mut path_len)? {
            // A truncated archive is better reported than silently accepted.
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "the backup ended early"));
        }
        let path_len = u16::from_le_bytes(path_len) as usize;
        if path_len == 0 {
            if !digested {
                return Ok(None);
            }
            let digest: [u8; 32] = std::mem::take(&mut input.hash).finalize().into();
            let mut stated = [0u8; 32];
            input.inner.read_exact(&mut stated)?;
            if stated != digest {
                return Err(io::Error::new(io::ErrorKind::InvalidData, "the backup is damaged: its contents do not match its digest"));
            }
            return Ok(Some(digest));
        }
        if path_len > MAX_PATH {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a backup entry's path is absurdly long"));
        }
        let mut rel = vec![0u8; path_len];
        input.read_exact(&mut rel)?;
        let rel = String::from_utf8(rel).map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "a backup entry's path is not text"))?;
        let target = safe_target(root, &rel)?;
        if !allowed(&rel) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a backup entry is not a file this app keeps"));
        }
        let mut length = [0u8; 8];
        input.read_exact(&mut length)?;
        let mut left = u64::from_le_bytes(length);
        if left > MAX_FILE {
            return Err(io::Error::new(io::ErrorKind::InvalidData, "a backup entry is absurdly large"));
        }
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        let mut out = fs::File::create(&target)?;
        written.push(target.clone());
        while left > 0 {
            let want = left.min(CHUNK as u64) as usize;
            input.read_exact(&mut buffer[..want])?;
            out.write_all(&buffer[..want])?;
            left -= want as u64;
        }
        out.sync_all()?;
        crate::hide_times(&out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_backup_restores_an_identical_installation() {
        let base = std::env::temp_dir().join(format!("torus-backup-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let (from, to) = (base.join("from"), base.join("to"));
        fs::create_dir_all(from.join("sites/site-1/records.bin.files")).unwrap();
        fs::write(from.join("project.vault"), b"SEALED-VAULT").unwrap();
        fs::write(from.join("sites/site-1/records.bin"), b"SEALED-RECORDS").unwrap();
        fs::write(from.join("sites/site-1/records.bin.files/abc"), vec![7u8; 5 * CHUNK + 3]).unwrap();
        fs::write(from.join("sites/site-1/tor-state.bin"), b"SEALED-TOR").unwrap();
        // The readable Tor folder is left out of a backup.
        fs::create_dir_all(from.join("sites/site-1/state")).unwrap();
        fs::write(from.join("sites/site-1/state/guards.json"), b"READABLE").unwrap();

        let mut archive = Vec::new();
        export(&from, &mut archive).unwrap();
        assert!(!archive.windows(8).any(|w| w == b"READABLE"), "a backup carried a readable Tor file");

        import(&to, &mut io::Cursor::new(&archive)).unwrap();
        assert_eq!(fs::read(to.join("project.vault")).unwrap(), b"SEALED-VAULT");
        assert_eq!(fs::read(to.join("sites/site-1/records.bin")).unwrap(), b"SEALED-RECORDS");
        assert_eq!(fs::read(to.join("sites/site-1/records.bin.files/abc")).unwrap(), vec![7u8; 5 * CHUNK + 3]);
        assert!(!to.join("sites/site-1/state").exists());

        // A restore never overwrites an existing installation.
        assert_eq!(import(&to, &mut io::Cursor::new(&archive)).unwrap_err().kind(), io::ErrorKind::AlreadyExists);
        fs::remove_dir_all(&base).unwrap();
    }

    #[test]
    fn a_hostile_archive_cannot_write_outside_the_folder() {
        let base = std::env::temp_dir().join(format!("torus-backup-evil-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let mut archive = MAGIC.to_vec();
        let rel = "../escaped";
        archive.extend_from_slice(&(rel.len() as u16).to_le_bytes());
        archive.extend_from_slice(rel.as_bytes());
        archive.extend_from_slice(&3u64.to_le_bytes());
        archive.extend_from_slice(b"bad");
        assert!(import(&base.join("in"), &mut io::Cursor::new(&archive)).is_err());
        assert!(!base.join("escaped").exists());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn a_damaged_or_foreign_archive_restores_nothing() {
        let base = std::env::temp_dir().join(format!("torus-backup-damaged-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let from = base.join("from");
        fs::create_dir_all(from.join("sites/site-1")).unwrap();
        fs::write(from.join("project.vault"), b"SEALED-VAULT").unwrap();
        fs::write(from.join("sites/site-1/records.bin"), b"SEALED-RECORDS").unwrap();
        let mut archive = Vec::new();
        export(&from, &mut archive).unwrap();

        // One byte changed: refused, and nothing it wrote is left.
        let mut damaged = archive.clone();
        let at = damaged.windows(6).position(|w| w == b"SEALED").unwrap();
        damaged[at] ^= 1;
        let to = base.join("to");
        assert!(import(&to, &mut io::Cursor::new(&damaged)).is_err());
        assert!(!to.join("project.vault").exists());
        // Cut short: refused too.
        assert!(import(&to, &mut io::Cursor::new(&archive[..archive.len() - 1])).is_err());
        assert!(!to.join("project.vault").exists());

        // A name the app never writes is refused.
        let mut planted = MAGIC.to_vec();
        for (rel, body) in [("project.vault", &b"x"[..]), ("webview/Local Storage", &b"y"[..])] {
            planted.extend_from_slice(&(rel.len() as u16).to_le_bytes());
            planted.extend_from_slice(rel.as_bytes());
            planted.extend_from_slice(&(body.len() as u64).to_le_bytes());
            planted.extend_from_slice(body);
        }
        assert!(import(&to, &mut io::Cursor::new(&planted)).is_err());
        assert!(!to.join("webview").exists() && !to.join("project.vault").exists());

        // The digest a site file seals is the one its archive carries.
        let site = from.join("sites/site-1");
        let mut out = Vec::new();
        let digest = export_only(&site, &mut out, &site_file).unwrap();
        assert_eq!(digest_only(&site, &site_file).unwrap(), digest);
        assert_eq!(unpack(&base.join("site"), &mut io::Cursor::new(&out), &site_file).unwrap(), Some(digest));
        fs::remove_dir_all(&base).unwrap();
    }
}
