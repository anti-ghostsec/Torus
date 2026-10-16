//! One encrypted file holding everything a project must keep secret.
//!
//! Layout: `magic | salt | argon2 memory, passes, lanes | nonce | ciphertext`.
//! The key is Argon2id over the passphrase; the body is XChaCha20-Poly1305
//! with the header as associated data, so tampering with either is detected.
//! Both are symmetric, 256-bit primitives, which quantum attacks do not break.

use std::fmt;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

pub mod backup;
pub mod folder;
mod locked;

use locked::LockedKey;

const MAGIC: &[u8; 8] = b"TORUSVLT";
const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 24;
const HEADER_LEN: usize = MAGIC.len() + SALT_LEN + 12;

/// Argon2id cost: 256 MiB, 3 passes, 1 lane. Each guess at a passphrase
/// costs an attacker that much memory and time.
const DEFAULT_COST: Cost = Cost { memory_kib: 256 * 1024, passes: 3, lanes: 1 };
/// Refuse absurd costs from a corrupt or hostile file instead of exhausting
/// memory or computing for days.
const MAX_MEMORY_KIB: u32 = 1024 * 1024;
const MAX_PASSES: u32 = 64;
const MAX_LANES: u32 = 64;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    /// Not a vault file, or one this version cannot read.
    Format,
    /// Wrong passphrase, or the file was modified.
    Locked,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "could not access the vault file: {e}"),
            Error::Format => f.write_str("this is not a vault file"),
            Error::Locked => f.write_str("wrong passphrase, or the vault file is damaged"),
        }
    }
}

impl std::error::Error for Error {}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

#[derive(Clone, Copy)]
struct Cost {
    memory_kib: u32,
    passes: u32,
    lanes: u32,
}

/// An unlocked vault. Holds the derived key so saving is instant; the key is
/// wiped from memory when this is dropped.
pub struct Vault {
    path: PathBuf,
    header: [u8; HEADER_LEN],
    key: LockedKey,
}

impl Vault {
    /// Creates a new vault file, replacing any file already at `path`.
    pub fn create(path: &Path, passphrase: &str, contents: &[u8]) -> Result<Self, Error> {
        Self::create_with(path, passphrase, contents, DEFAULT_COST)
    }

    fn create_with(path: &Path, passphrase: &str, contents: &[u8], cost: Cost) -> Result<Self, Error> {
        let mut header = [0u8; HEADER_LEN];
        header[..8].copy_from_slice(MAGIC);
        random(&mut header[8..8 + SALT_LEN])?;
        header[24..28].copy_from_slice(&cost.memory_kib.to_le_bytes());
        header[28..32].copy_from_slice(&cost.passes.to_le_bytes());
        header[32..36].copy_from_slice(&cost.lanes.to_le_bytes());
        let vault = Self { path: path.to_owned(), key: LockedKey::new(derive(passphrase, &header)?), header };
        vault.save(contents)?;
        Ok(vault)
    }

    /// Unlocks an existing vault and returns its contents.
    pub fn open(path: &Path, passphrase: &str) -> Result<(Self, Zeroizing<Vec<u8>>), Error> {
        let file = fs::read(path)?;
        if file.len() < HEADER_LEN + NONCE_LEN || &file[..8] != MAGIC {
            return Err(Error::Format);
        }
        let mut header = [0u8; HEADER_LEN];
        header.copy_from_slice(&file[..HEADER_LEN]);
        let key = derive(passphrase, &header)?;
        let (nonce, body) = file[HEADER_LEN..].split_at(NONCE_LEN);
        let contents = XChaCha20Poly1305::new(key.as_ref().into())
            .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad: &header })
            .map_err(|_| Error::Locked)?;
        Ok((Self { path: path.to_owned(), header, key: LockedKey::new(key) }, Zeroizing::new(contents)))
    }

    /// Whether this vault was made with a lower cost than vaults are made
    /// with now, and so is cheaper to guess passphrases against.
    pub fn weaker_than_default(&self) -> bool {
        let word = |at: usize| u32::from_le_bytes(self.header[at..at + 4].try_into().expect("4 bytes"));
        word(24) < DEFAULT_COST.memory_kib || word(28) < DEFAULT_COST.passes
    }

    /// Replaces the vault's contents. The old file stays intact until the new
    /// one is completely written.
    pub fn save(&self, contents: &[u8]) -> Result<(), Error> {
        let mut nonce = [0u8; NONCE_LEN];
        random(&mut nonce)?;
        let body = XChaCha20Poly1305::new(self.key.bytes().into())
            .encrypt(XNonce::from_slice(&nonce), Payload { msg: contents, aad: &self.header })
            .map_err(|_| Error::Format)?;

        let mut temp = self.path.clone().into_os_string();
        temp.push(".new");
        let temp = PathBuf::from(temp);
        let mut file = fs::File::create(&temp)?;
        file.write_all(&self.header)?;
        file.write_all(&nonce)?;
        file.write_all(&body)?;
        file.sync_all()?;
        hide_times(&file);
        drop(file);
        fs::rename(&temp, &self.path)?;
        // The rename is only durable once the folder is written out.
        #[cfg(unix)]
        if let Some(dir) = self.path.parent() {
            fs::File::open(dir)?.sync_all()?;
        }
        Ok(())
    }
}

/// Seals `contents` under a passphrase, in the vault's own format, without
/// a file: for exports, which carry their own passphrase.
pub fn seal(passphrase: &str, contents: &[u8]) -> Result<Vec<u8>, Error> {
    let mut header = [0u8; HEADER_LEN];
    header[..8].copy_from_slice(MAGIC);
    random(&mut header[8..8 + SALT_LEN])?;
    header[24..28].copy_from_slice(&DEFAULT_COST.memory_kib.to_le_bytes());
    header[28..32].copy_from_slice(&DEFAULT_COST.passes.to_le_bytes());
    header[32..36].copy_from_slice(&DEFAULT_COST.lanes.to_le_bytes());
    let key = derive(passphrase, &header)?;
    let mut nonce = [0u8; NONCE_LEN];
    random(&mut nonce)?;
    let body = XChaCha20Poly1305::new(key.as_ref().into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: contents, aad: &header })
        .map_err(|_| Error::Format)?;
    Ok([&header[..], &nonce, &body].concat())
}

/// Opens what [`seal`] made.
pub fn unseal(sealed: &[u8], passphrase: &str) -> Result<Zeroizing<Vec<u8>>, Error> {
    if sealed.len() < HEADER_LEN + NONCE_LEN || &sealed[..8] != MAGIC {
        return Err(Error::Format);
    }
    let mut header = [0u8; HEADER_LEN];
    header.copy_from_slice(&sealed[..HEADER_LEN]);
    let key = derive(passphrase, &header)?;
    let (nonce, body) = sealed[HEADER_LEN..].split_at(NONCE_LEN);
    XChaCha20Poly1305::new(key.as_ref().into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: body, aad: &header })
        .map(Zeroizing::new)
        .map_err(|_| Error::Locked)
}

fn derive(passphrase: &str, header: &[u8; HEADER_LEN]) -> Result<Zeroizing<[u8; 32]>, Error> {
    let word = |at: usize| u32::from_le_bytes(header[at..at + 4].try_into().unwrap());
    let (memory_kib, passes, lanes) = (word(24), word(28), word(32));
    if memory_kib > MAX_MEMORY_KIB || passes > MAX_PASSES || lanes > MAX_LANES {
        return Err(Error::Format);
    }
    let params = Params::new(memory_kib, passes, lanes, Some(32)).map_err(|_| Error::Format)?;
    let mut key = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), &header[8..8 + SALT_LEN], key.as_mut())
        .map_err(|_| Error::Format)?;
    Ok(key)
}

/// Gives a file the same times as every other file this app writes, so that
/// the disk says nothing about when anything was added or changed.
pub(crate) fn hide_times(file: &std::fs::File) {
    let fixed = std::time::UNIX_EPOCH + std::time::Duration::from_secs(946_684_800); // 2000-01-01
    let times = std::fs::FileTimes::new().set_accessed(fixed).set_modified(fixed);
    #[cfg(windows)]
    let times = {
        use std::os::windows::fs::FileTimesExt;
        times.set_created(fixed)
    };
    let _ = file.set_times(times);
}

/// Pads `bytes` with spaces to a whole number of 64 KiB, so that the size of
/// what is stored says little about how much is in it. JSON readers skip
/// trailing spaces.
pub fn pad_json(bytes: &mut Vec<u8>) {
    const STEP: usize = 64 * 1024;
    let padded = bytes.len().div_ceil(STEP).max(1) * STEP;
    bytes.resize(padded, b' ');
}

fn random(buffer: &mut [u8]) -> Result<(), Error> {
    getrandom::getrandom(buffer).map_err(|e| Error::Io(e.into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: Cost = Cost { memory_kib: 64, passes: 1, lanes: 1 };

    fn temp(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!("torus-vault-test-{}-{name}", std::process::id()))
    }

    #[test]
    fn round_trips_and_resaves() {
        let path = temp("roundtrip");
        let vault = Vault::create_with(&path, "correct horse", b"first", FAST).unwrap();
        let on_disk = fs::read(&path).unwrap();
        assert!(!on_disk.windows(5).any(|w| w == b"first"));

        vault.save(b"second").unwrap();
        // A fresh nonce every save, so equal contents never produce equal files.
        vault.save(b"second").unwrap();
        let again = fs::read(&path).unwrap();
        vault.save(b"second").unwrap();
        assert_ne!(again, fs::read(&path).unwrap());

        let (_, contents) = Vault::open(&path, "correct horse").unwrap();
        assert_eq!(contents.as_slice(), b"second");
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn rejects_wrong_passphrase_tampering_and_foreign_files() {
        let path = temp("reject");
        Vault::create_with(&path, "right", b"secret", FAST).unwrap();
        assert!(matches!(Vault::open(&path, "wrong"), Err(Error::Locked)));

        let mut bytes = fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(Vault::open(&path, "right"), Err(Error::Locked)));

        // Lowering the cost in the header must not unlock the file either.
        bytes[last] ^= 1;
        bytes[28] ^= 1;
        fs::write(&path, &bytes).unwrap();
        assert!(Vault::open(&path, "right").is_err());

        // Nor may a hostile header make opening take forever.
        bytes[28] ^= 1;
        bytes[28..32].copy_from_slice(&u32::MAX.to_le_bytes());
        fs::write(&path, &bytes).unwrap();
        assert!(matches!(Vault::open(&path, "right"), Err(Error::Format)));

        fs::write(&path, b"not a vault").unwrap();
        assert!(matches!(Vault::open(&path, "right"), Err(Error::Format)));
        fs::remove_file(&path).unwrap();
    }
}
