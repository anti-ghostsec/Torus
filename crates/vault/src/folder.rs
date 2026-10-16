//! Keeps a folder encrypted while nothing is using it.
//!
//! Tor writes its own bookkeeping into an ordinary folder: which relays it
//! guards its connections with, and which relays introduced visitors to a
//! site. Compared with a site's public description, that could tie this
//! device to the site's address. So the folder exists in readable form only
//! while the site is online: before a host starts, it is unpacked from an
//! encrypted file, and afterwards packed back into it and erased.
//!
//! Packed file: `nonce | XChaCha20-Poly1305(entries)`, where an entry is a
//! 2-byte path length, the path (relative, `/`-separated), an 8-byte length
//! and the contents.

use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

const NONCE_LEN: usize = 24;
const CONTEXT: &[u8] = b"torus-folder-v1";
/// Tor's bookkeeping is small; anything larger is not what this is for.
const MAX_TOTAL: u64 = 256 * 1024 * 1024;

fn collect(root: &Path, at: &Path, out: &mut Vec<u8>) -> io::Result<()> {
    for entry in fs::read_dir(at)? {
        let entry = entry?;
        let path = entry.path();
        let kind = entry.file_type()?;
        if kind.is_dir() {
            collect(root, &path, out)?;
            continue;
        }
        if !kind.is_file() {
            continue;
        }
        let name = entry.file_name();
        // Lock files say a program is running; they mean nothing later.
        if name.to_string_lossy().ends_with(".lock") || name == "lock" {
            continue;
        }
        let relative = path.strip_prefix(root).map_err(io::Error::other)?;
        let relative: Vec<String> = relative.components().map(|c| c.as_os_str().to_string_lossy().into_owned()).collect();
        let relative = relative.join("/");
        let contents = Zeroizing::new(fs::read(&path)?);
        if out.len() as u64 + contents.len() as u64 > MAX_TOTAL {
            return Err(io::Error::other("the folder is too large to keep"));
        }
        out.extend_from_slice(&(relative.len() as u16).to_le_bytes());
        out.extend_from_slice(relative.as_bytes());
        out.extend_from_slice(&(contents.len() as u64).to_le_bytes());
        out.extend_from_slice(&contents);
    }
    Ok(())
}

/// Encrypts everything in `folder` into `file`, replacing it only once the
/// new one is completely written. A missing folder packs as empty.
pub fn pack(folder: &Path, key: &[u8; 32], file: &Path) -> io::Result<()> {
    let mut plain = Zeroizing::new(Vec::new());
    if folder.exists() {
        collect(folder, folder, &mut plain)?;
    }
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(io::Error::other)?;
    let sealed = XChaCha20Poly1305::new(key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &plain, aad: CONTEXT })
        .map_err(|_| io::Error::other("could not encrypt the folder"))?;
    let mut temp = file.to_path_buf().into_os_string();
    temp.push(".new");
    let temp = PathBuf::from(temp);
    let mut out = fs::File::create(&temp)?;
    out.write_all(&nonce)?;
    out.write_all(&sealed)?;
    out.sync_all()?;
    drop(out);
    fs::rename(&temp, file)?;
    Ok(())
}

/// Recreates `folder` from what [`pack`] wrote to `file`, after erasing
/// whatever was in it. A missing file leaves an empty folder.
pub fn unpack(file: &Path, key: &[u8; 32], folder: &Path) -> io::Result<()> {
    erase(folder)?;
    fs::create_dir_all(folder)?;
    let sealed = match fs::read(file) {
        Ok(sealed) => sealed,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
    };
    let damaged = || io::Error::new(io::ErrorKind::InvalidData, "the kept folder is damaged or has another key");
    if sealed.len() < NONCE_LEN {
        return Err(damaged());
    }
    let (nonce, body) = sealed.split_at(NONCE_LEN);
    let plain = Zeroizing::new(
        XChaCha20Poly1305::new(key.into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad: CONTEXT })
            .map_err(|_| damaged())?,
    );
    let mut rest: &[u8] = &plain;
    while !rest.is_empty() {
        let take = |rest: &mut &[u8], count: usize| -> io::Result<Vec<u8>> {
            if rest.len() < count {
                return Err(damaged());
            }
            let (this, more) = rest.split_at(count);
            *rest = more;
            Ok(this.to_vec())
        };
        let length = u16::from_le_bytes(take(&mut rest, 2)?.try_into().expect("2 bytes")) as usize;
        let relative = String::from_utf8(take(&mut rest, length)?).map_err(|_| damaged())?;
        let size = u64::from_le_bytes(take(&mut rest, 8)?.try_into().expect("8 bytes"));
        let contents = Zeroizing::new(take(&mut rest, usize::try_from(size).map_err(|_| damaged())?)?);
        // Only plain names below the folder: nothing may land outside it.
        let path = Path::new(&relative);
        if relative.is_empty() || !path.components().all(|c| matches!(c, Component::Normal(_))) {
            return Err(damaged());
        }
        let target = folder.join(path);
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(target, &*contents)?;
    }
    Ok(())
}

/// Erases a folder: each file is overwritten with zeros before it is
/// deleted, so that its contents are not simply left on the disk. (Disks
/// that move data around internally, as most flash storage does, may keep
/// old copies anyway; that is what the encryption is for.)
pub fn erase(folder: &Path) -> io::Result<()> {
    fn overwrite(at: &Path) -> io::Result<()> {
        for entry in fs::read_dir(at)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                overwrite(&entry.path())?;
            } else if kind.is_file() {
                let size = entry.metadata()?.len();
                if let Ok(mut file) = fs::OpenOptions::new().write(true).open(entry.path()) {
                    let zeros = vec![0u8; 64 * 1024];
                    let mut left = size;
                    while left > 0 {
                        let now = left.min(zeros.len() as u64) as usize;
                        if file.write_all(&zeros[..now]).is_err() {
                            break;
                        }
                        left -= now as u64;
                    }
                    let _ = file.sync_all();
                }
            }
        }
        Ok(())
    }
    match fs::metadata(folder) {
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e),
        Ok(_) => {}
    }
    let _ = overwrite(folder);
    fs::remove_dir_all(folder)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_folder_survives_packing_and_nothing_readable_is_left() {
        let base = std::env::temp_dir().join(format!("torus-folder-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        let (folder, file) = (base.join("state"), base.join("state.bin"));
        fs::create_dir_all(folder.join("hss/site")).unwrap();
        fs::write(folder.join("guards.json"), b"SECRET-GUARDS").unwrap();
        fs::write(folder.join("hss/site/iptpub"), b"SECRET-INTRO-POINTS").unwrap();
        fs::write(folder.join("state.lock"), b"pid").unwrap();
        let key = [9u8; 32];

        pack(&folder, &key, &file).unwrap();
        erase(&folder).unwrap();
        assert!(!folder.exists());
        let sealed = fs::read(&file).unwrap();
        assert!(!sealed.windows(6).any(|w| w == b"SECRET"));

        unpack(&file, &key, &folder).unwrap();
        assert_eq!(fs::read(folder.join("guards.json")).unwrap(), b"SECRET-GUARDS");
        assert_eq!(fs::read(folder.join("hss/site/iptpub")).unwrap(), b"SECRET-INTRO-POINTS");
        assert!(!folder.join("state.lock").exists(), "lock files are not kept");
        assert!(unpack(&file, &[8u8; 32], &base.join("other")).is_err(), "another key opened it");

        // Nothing kept yet: an empty folder.
        unpack(&base.join("missing.bin"), &key, &base.join("fresh")).unwrap();
        assert!(base.join("fresh").read_dir().unwrap().next().is_none());
        fs::remove_dir_all(&base).unwrap();
    }
}
