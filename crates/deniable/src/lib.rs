//! Deniable storage: encrypted volumes hidden in one container that, without
//! the right password, is indistinguishable from random bytes.
//!
//! A container is a file or partition of 4 KiB blocks, filled with random
//! bytes when it's formatted. Each volume's blocks are encrypted with
//! XChaCha20-Poly1305 and scattered at random positions, so they look like
//! the random filler around them. Nothing in the container says how many
//! volumes there are, where they are, or how full they are: a wrong
//! password and a password that was never set give the same answer.
//!
//! * A volume's key comes from its password with Argon2id, salted by the
//!   container (or is given directly, for apps that already hold a key).
//! * Its superblock sits at one of a few positions only its key can work
//!   out. There are two, written alternately with a generation number, so a
//!   power cut while saving leaves the previous state intact.
//! * Writes never overwrite live data: every changed block goes to a fresh,
//!   random position, and blocks given up are overwritten with new random
//!   bytes once the change is saved. Nothing about the order data was
//!   written in survives on the disk.
//! * Volumes are layered. A volume can be made "above" others, and unlocking
//!   it unlocks those too. Give the lowest one's password under pressure;
//!   the ones above stay invisible.
//! * Each save also rewrites some free blocks with new random bytes (cover
//!   writes), so that comparing two copies of the disk taken at different
//!   times shows changes that a lower volume can't account for, whatever
//!   volume really made them.
//!
//! # What it doesn't do
//!
//! * Only the volumes that are unlocked are known to be in use. Writing with
//!   only a lower volume unlocked (including the cover writes) can overwrite
//!   the volumes above it. Day to day, always unlock with the top password.
//! * Comparing copies of the disk is hidden only as well as the cover writes
//!   hide it: when a lower volume never changes while the disk does, cover
//!   writes are the only explanation on offer. On flash storage the
//!   controller can keep old copies of blocks the app can't reach.
//! * Someone who can write to the disk can roll a block back to an older
//!   version of itself; that's detected only if it breaks the volume.
//! * The container's size is plain to see, and so is the fact that a
//!   container exists.

use std::collections::HashSet;
use std::fmt;
use std::io;

use argon2::{Algorithm, Argon2, Params, Version};
use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::Blake2bMac;
use chacha20::cipher::{KeyIvInit, StreamCipher};
use chacha20poly1305::aead::{AeadInPlace, KeyInit};
use chacha20poly1305::{Tag, XChaCha20Poly1305, XNonce};
use zeroize::{Zeroize, Zeroizing};

mod device;
mod file;

pub use device::{BlockDevice, FileDevice, MemDevice};
pub use file::VolumeFile;

/// Bytes in a block on the disk.
pub const BLOCK: usize = 4096;
const NONCE: usize = 24;
const TAG: usize = 16;
/// Bytes of a volume's data in each block.
pub const PAYLOAD: usize = BLOCK - NONCE - TAG;
const SALT: usize = 32;
/// Positions tried for a volume's superblock.
const SLOT_CANDIDATES: u64 = 64;
/// Volumes directly below one volume.
pub const MAX_BELOW: usize = 16;
const MAP_ENTRIES: usize = (PAYLOAD - 8) / 4;
/// The smallest container: room for a few volumes and their data.
pub const MIN_BLOCKS: u64 = 64;
const SUPER_MAGIC: &[u8; 8] = b"DNBLVOL1";
const SUPER_HEAD: usize = 8 + 8 + 8 + 4 + 4 + 1;

const KIND_SUPER: u8 = 1;
const KIND_MAP: u8 = 2;
const KIND_DATA: u8 = 3;

/// Argon2id cost of turning a password into a volume's key. The same cost
/// must be given every time the container is opened.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Kdf {
    pub memory_kib: u32,
    pub passes: u32,
    pub lanes: u32,
}

impl Kdf {
    /// 64 MiB and 3 passes: a phone can afford it, and every guess at a
    /// password costs an attacker the same.
    pub const DEFAULT: Kdf = Kdf { memory_kib: 64 * 1024, passes: 3, lanes: 1 };
}

#[derive(Debug)]
pub enum Error {
    Io(io::Error),
    /// No volume opens with that password or key. Deliberately the same
    /// whether the password is wrong or no such volume was ever made.
    NotFound,
    /// A volume with that password or key exists already.
    Exists,
    /// No free blocks are left.
    Full,
    /// A volume's blocks don't decrypt or don't fit together: overwritten
    /// by a session that didn't know about it, or the disk was changed.
    Damaged,
    /// The container is smaller than [`MIN_BLOCKS`] or larger than 16 TiB.
    BadSize,
    /// Not a volume this store has open.
    NoSuchVolume,
    /// More than [`MAX_BELOW`] volumes below one volume.
    TooManyBelow,
    /// The Argon2id cost was refused.
    Kdf,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "storage error: {e}"),
            Error::NotFound => f.write_str("wrong password"),
            Error::Exists => f.write_str("that password is already in use"),
            Error::Full => f.write_str("the container is full"),
            Error::Damaged => f.write_str("the volume is damaged"),
            Error::BadSize => f.write_str("the container's size isn't supported"),
            Error::NoSuchVolume => f.write_str("that volume isn't open"),
            Error::TooManyBelow => f.write_str("too many volumes below one volume"),
            Error::Kdf => f.write_str("invalid key derivation cost"),
        }
    }
}

impl std::error::Error for Error {}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<Error> for io::Error {
    fn from(e: Error) -> Self {
        match e {
            Error::Io(e) => e,
            other => io::Error::other(other),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

/// One open volume, as handed out by a [`Store`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct VolumeId(usize);

struct Keys {
    enc: Zeroizing<[u8; 32]>,
    loc: Zeroizing<[u8; 32]>,
}

struct Volume {
    master: Zeroizing<[u8; 32]>,
    keys: Keys,
    /// The two superblock positions; `slots[current]` holds generation `gen`.
    slots: [u32; 2],
    current: usize,
    gen: u64,
    len: u64,
    /// Logical block to physical block; 0 is a hole that reads as zeros.
    map: Vec<u32>,
    /// Where the saved map is.
    map_blocks: Vec<u32>,
    /// Keys of the volumes below this one.
    below: Vec<Zeroizing<[u8; 32]>>,
    below_ids: Vec<VolumeId>,
    /// Blocks the saved state still uses, to be released once it's replaced.
    retired: Vec<u32>,
    /// Blocks written since the last save, which nothing saved points to:
    /// these can be rewritten in place.
    fresh: HashSet<u32>,
    dirty: bool,
}

/// An open container: the volumes unlocked so far, and which blocks they use.
pub struct Store<D: BlockDevice> {
    dev: D,
    blocks: u32,
    salt: [u8; SALT],
    kdf: Kdf,
    used: Vec<u64>,
    used_count: u32,
    volumes: Vec<Option<Volume>>,
    noise: Noise,
    cover_per_write: u32,
    cover_min: u32,
    writes: u64,
}

impl<D: BlockDevice> Store<D> {
    /// Fills `dev` with random bytes, making it an empty container. Whatever
    /// it held is gone.
    pub fn format(mut dev: D, kdf: Kdf) -> Result<Self> {
        let blocks = checked_size(dev.blocks())?;
        let mut noise = Noise::new()?;
        let mut buf = Zeroizing::new([0u8; BLOCK]);
        for i in 0..blocks as u64 {
            noise.fill(&mut buf[..])?;
            dev.write(i, &buf)?;
        }
        dev.sync()?;
        Self::open(dev, kdf)
    }

    /// Opens a formatted container, with nothing unlocked yet.
    pub fn open(mut dev: D, kdf: Kdf) -> Result<Self> {
        let blocks = checked_size(dev.blocks())?;
        Params::new(kdf.memory_kib, kdf.passes, kdf.lanes, Some(32)).map_err(|_| Error::Kdf)?;
        let mut first = Zeroizing::new([0u8; BLOCK]);
        dev.read(0, &mut first)?;
        let mut salt = [0u8; SALT];
        salt.copy_from_slice(&first[..SALT]);
        let mut store = Self {
            dev,
            blocks,
            salt,
            kdf,
            used: vec![0; blocks as usize / 64 + 1],
            used_count: 0,
            volumes: Vec::new(),
            noise: Noise::new()?,
            cover_per_write: 1,
            cover_min: 8,
            writes: 0,
        };
        // Block 0 holds the salt.
        store.mark(0)?;
        Ok(store)
    }

    /// How many free blocks each save rewrites with random bytes: `per_write`
    /// for every block it really wrote, and at least `min`. 0 and 0 turns
    /// cover writes off.
    pub fn set_cover(&mut self, per_write: u32, min: u32) {
        self.cover_per_write = per_write;
        self.cover_min = min;
    }

    /// The volume's key, from its password.
    pub fn key_for(&self, password: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
        let params = Params::new(self.kdf.memory_kib, self.kdf.passes, self.kdf.lanes, Some(32)).map_err(|_| Error::Kdf)?;
        let mut key = Zeroizing::new([0u8; 32]);
        Argon2::new(Algorithm::Argon2id, Version::V0x13, params).hash_password_into(password, &self.salt, &mut key[..]).map_err(|_| Error::Kdf)?;
        Ok(key)
    }

    /// Unlocks the volume with this password, and every volume below it.
    pub fn unlock(&mut self, password: &[u8]) -> Result<VolumeId> {
        let key = self.key_for(password)?;
        self.unlock_key(&key)
    }

    /// Unlocks the volume with this key, and every volume below it.
    pub fn unlock_key(&mut self, key: &[u8; 32]) -> Result<VolumeId> {
        if let Some(id) = self.find(key) {
            return Ok(id);
        }
        let keys = derive(key);
        let mut found: Vec<(u32, u64, Zeroizing<[u8; PAYLOAD]>)> = Vec::new();
        for slot in self.candidates(&keys) {
            if let Some(payload) = self.read_sealed(&keys, KIND_SUPER, slot)? {
                if &payload[..8] == SUPER_MAGIC {
                    found.push((slot, u64_at(&payload[..], 8), payload));
                }
            }
        }
        found.sort_by_key(|(_, gen, _)| std::cmp::Reverse(*gen));
        let Some((slot, gen, payload)) = found.first() else {
            return Err(Error::NotFound);
        };
        let len = u64_at(&payload[..], 16);
        let map_head = u32_at(&payload[..], 24);
        let map_count = u32_at(&payload[..], 28) as usize;
        let n_below = payload[32] as usize;
        if n_below > MAX_BELOW || len > self.blocks as u64 * PAYLOAD as u64 {
            return Err(Error::Damaged);
        }
        let below = (0..n_below)
            .map(|i| {
                let mut k = Zeroizing::new([0u8; 32]);
                k.copy_from_slice(&payload[SUPER_HEAD + i * 32..SUPER_HEAD + (i + 1) * 32]);
                k
            })
            .collect();
        let (map, map_blocks) = self.load_map(&keys, map_head, map_count, blocks_for(len))?;

        // The other slot: the next newest copy. With only one (a slot was
        // overwritten), a free candidate is picked once the volumes below
        // have claimed their blocks.
        let other = found.get(1).map(|(s, ..)| *s);
        let mut claimed = Vec::new();
        for b in [*slot].into_iter().chain(other).chain(map_blocks.iter().copied()).chain(map.iter().copied().filter(|&b| b != 0)) {
            if let Err(e) = self.mark(b) {
                claimed.into_iter().for_each(|b| self.unmark(b));
                return Err(e);
            }
            claimed.push(b);
        }
        let volume = Volume {
            master: Zeroizing::new(*key),
            keys,
            slots: [*slot, other.unwrap_or(0)],
            current: 0,
            gen: *gen,
            len,
            map,
            map_blocks,
            below,
            below_ids: Vec::new(),
            retired: Vec::new(),
            fresh: HashSet::new(),
            dirty: false,
        };
        let id = VolumeId(self.volumes.len());
        self.volumes.push(Some(volume));
        self.open_below(id)?;
        if other.is_none() {
            let keys = &self.volume(id)?.keys;
            let spare = self.candidates(keys).into_iter().find(|&s| s != *slot && !self.is_used(s)).ok_or(Error::Full)?;
            self.mark(spare)?;
            self.volume_mut(id)?.slots[1] = spare;
        }
        Ok(id)
    }

    fn open_below(&mut self, id: VolumeId) -> Result<()> {
        let below: Vec<Zeroizing<[u8; 32]>> = self.volume(id)?.below.clone();
        let mut ids = Vec::new();
        for key in below.iter() {
            match self.unlock_key(key) {
                Ok(b) => ids.push(b),
                // Destroyed, or overwritten while it wasn't unlocked.
                Err(Error::NotFound) => {}
                Err(e) => return Err(e),
            }
        }
        self.volume_mut(id)?.below_ids = ids;
        Ok(())
    }

    /// Makes a new, empty volume opened by `password`. The volumes in `below`
    /// are unlocked along with it from now on.
    ///
    /// Unlock every existing volume first: blocks of a volume that isn't
    /// unlocked look free, and the new volume may be put on top of them.
    pub fn create(&mut self, password: &[u8], below: &[VolumeId]) -> Result<VolumeId> {
        let key = self.key_for(password)?;
        self.create_key(&key, below)
    }

    /// Makes a new, empty volume opened by `key`. See [`Store::create`].
    pub fn create_key(&mut self, key: &[u8; 32], below: &[VolumeId]) -> Result<VolumeId> {
        if self.find(key).is_some() {
            return Err(Error::Exists);
        }
        if below.len() > MAX_BELOW {
            return Err(Error::TooManyBelow);
        }
        let mut below_ids: Vec<VolumeId> = Vec::new();
        for id in below {
            self.volume(*id)?;
            if !below_ids.contains(id) {
                below_ids.push(*id);
            }
        }
        let keys = derive(key);
        // A volume that exists but isn't unlocked has the same key: making it
        // again would wipe it.
        for slot in self.candidates(&keys) {
            if self.read_sealed(&keys, KIND_SUPER, slot)?.is_some() {
                return Err(Error::Exists);
            }
        }
        let mut slots = self.candidates(&keys).into_iter().filter(|&s| !self.is_used(s));
        let (Some(a), Some(b)) = (slots.next(), slots.next()) else {
            return Err(Error::Full);
        };
        self.mark(a)?;
        self.mark(b)?;
        let below = below_ids.iter().map(|id| Ok(self.volume(*id)?.master.clone())).collect::<Result<Vec<_>>>()?;
        let mut volume = Volume {
            master: Zeroizing::new(*key),
            keys,
            // Saving writes the other slot, so the first save goes to `a`.
            slots: [b, a],
            current: 0,
            gen: 0,
            len: 0,
            map: Vec::new(),
            map_blocks: Vec::new(),
            below,
            below_ids,
            retired: Vec::new(),
            fresh: HashSet::new(),
            dirty: true,
        };
        if let Err(e) = self.save(&mut volume) {
            self.unmark(a);
            self.unmark(b);
            return Err(e);
        }
        self.dev.sync()?;
        let id = VolumeId(self.volumes.len());
        self.volumes.push(Some(volume));
        Ok(id)
    }

    /// The volumes unlocked along with `id`, directly below it.
    pub fn below(&self, id: VolumeId) -> Result<Vec<VolumeId>> {
        Ok(self.volume(id)?.below_ids.clone())
    }

    /// Every volume unlocked so far.
    pub fn volumes(&self) -> Vec<VolumeId> {
        self.volumes.iter().enumerate().filter(|(_, v)| v.is_some()).map(|(i, _)| VolumeId(i)).collect()
    }

    /// The volume's size in bytes.
    pub fn len(&self, id: VolumeId) -> Result<u64> {
        Ok(self.volume(id)?.len)
    }

    pub fn is_empty(&self, id: VolumeId) -> Result<bool> {
        Ok(self.len(id)? == 0)
    }

    /// Reads from `offset` into `buf`, stopping at the end of the volume.
    /// Returns how many bytes were read.
    pub fn read(&mut self, id: VolumeId, offset: u64, buf: &mut [u8]) -> Result<usize> {
        let v = self.take(id)?;
        let r = self.read_from(&v, offset, buf);
        self.volumes[id.0] = Some(v);
        r
    }

    /// Writes `data` at `offset`, growing the volume if needed. Nothing is
    /// kept until [`Store::flush`].
    pub fn write(&mut self, id: VolumeId, offset: u64, data: &[u8]) -> Result<()> {
        let mut v = self.take(id)?;
        let r = self.write_into(&mut v, offset, data);
        self.volumes[id.0] = Some(v);
        r
    }

    /// Cuts the volume to `len` bytes, or grows it with zeros.
    pub fn set_len(&mut self, id: VolumeId, len: u64) -> Result<()> {
        let mut v = self.take(id)?;
        let r = self.resize(&mut v, len);
        self.volumes[id.0] = Some(v);
        r
    }

    /// Saves every changed volume, then makes the cover writes.
    pub fn flush(&mut self) -> Result<()> {
        let dirty: Vec<usize> = self.volumes.iter().enumerate().filter(|(_, v)| v.as_ref().is_some_and(|v| v.dirty)).map(|(i, _)| i).collect();
        if dirty.is_empty() {
            return Ok(());
        }
        for i in dirty {
            let mut v = self.take(VolumeId(i))?;
            let r = self.save(&mut v);
            self.volumes[i] = Some(v);
            r?;
        }
        let real = std::mem::take(&mut self.writes);
        let cover = (real.saturating_mul(self.cover_per_write as u64)).max(self.cover_min as u64);
        self.cover(cover)?;
        self.dev.sync()?;
        Ok(())
    }

    /// Overwrites every block of the volume with random bytes and forgets
    /// it. The volumes below it stay unlocked; volumes above it stop
    /// listing it at their next save.
    pub fn destroy(&mut self, id: VolumeId) -> Result<()> {
        let v = self.take(id)?;
        let mut blocks: Vec<u32> = v.slots.to_vec();
        blocks.extend(&v.map_blocks);
        blocks.extend(v.map.iter().copied().filter(|&b| b != 0));
        blocks.extend(&v.retired);
        for b in blocks {
            self.scrub(b)?;
        }
        for other in self.volumes.iter_mut().flatten() {
            if let Some(i) = other.below.iter().position(|k| k[..] == v.master[..]) {
                other.below.remove(i);
                other.below_ids.retain(|b| *b != id);
                other.dirty = true;
            }
        }
        self.dev.sync()?;
        Ok(())
    }

    /// A file-like view of the volume, for `std::io` readers and writers.
    pub fn file(&mut self, id: VolumeId) -> VolumeFile<'_, D> {
        VolumeFile::new(self, id)
    }

    /// Forgets every key and hands the device back. Unsaved changes are lost.
    pub fn into_device(self) -> D {
        self.dev
    }

    fn find(&self, key: &[u8; 32]) -> Option<VolumeId> {
        self.volumes.iter().position(|v| v.as_ref().is_some_and(|v| v.master[..] == key[..])).map(VolumeId)
    }

    fn volume(&self, id: VolumeId) -> Result<&Volume> {
        self.volumes.get(id.0).and_then(|v| v.as_ref()).ok_or(Error::NoSuchVolume)
    }

    fn volume_mut(&mut self, id: VolumeId) -> Result<&mut Volume> {
        self.volumes.get_mut(id.0).and_then(|v| v.as_mut()).ok_or(Error::NoSuchVolume)
    }

    fn take(&mut self, id: VolumeId) -> Result<Volume> {
        self.volumes.get_mut(id.0).and_then(|v| v.take()).ok_or(Error::NoSuchVolume)
    }

    /// Where this key's superblock may be, in the order they're tried.
    fn candidates(&self, keys: &Keys) -> Vec<u32> {
        let mut out: Vec<u32> = Vec::new();
        for i in 0..SLOT_CANDIDATES {
            let h = prf(&keys.loc, b"slot", &i.to_le_bytes());
            let n = u64::from_le_bytes(h[..8].try_into().expect("8 bytes"));
            let slot = 1 + (n % (self.blocks as u64 - 1)) as u32;
            if !out.contains(&slot) {
                out.push(slot);
            }
        }
        out
    }

    fn read_from(&mut self, v: &Volume, offset: u64, buf: &mut [u8]) -> Result<usize> {
        if offset >= v.len {
            return Ok(0);
        }
        let n = buf.len().min((v.len - offset) as usize);
        let mut done = 0;
        while done < n {
            let at = offset + done as u64;
            let (lb, within) = ((at / PAYLOAD as u64) as usize, (at % PAYLOAD as u64) as usize);
            let take = (PAYLOAD - within).min(n - done);
            match v.map.get(lb).copied().unwrap_or(0) {
                0 => buf[done..done + take].fill(0),
                p => {
                    let payload = self.read_sealed(&v.keys, KIND_DATA, p)?.ok_or(Error::Damaged)?;
                    buf[done..done + take].copy_from_slice(&payload[within..within + take]);
                }
            }
            done += take;
        }
        Ok(n)
    }

    fn write_into(&mut self, v: &mut Volume, offset: u64, data: &[u8]) -> Result<()> {
        let end = offset.checked_add(data.len() as u64).ok_or(Error::Full)?;
        if end > self.blocks as u64 * PAYLOAD as u64 {
            return Err(Error::Full);
        }
        if end > v.len {
            v.map.resize(blocks_for(end), 0);
        }
        let mut done = 0;
        while done < data.len() {
            let at = offset + done as u64;
            let (lb, within) = ((at / PAYLOAD as u64) as usize, (at % PAYLOAD as u64) as usize);
            let take = (PAYLOAD - within).min(data.len() - done);
            let mut payload = Zeroizing::new([0u8; PAYLOAD]);
            let old = v.map[lb];
            if take < PAYLOAD && old != 0 {
                payload.copy_from_slice(&self.read_sealed(&v.keys, KIND_DATA, old)?.ok_or(Error::Damaged)?[..]);
            }
            payload[within..within + take].copy_from_slice(&data[done..done + take]);
            self.put_data(v, lb, &payload)?;
            done += take;
        }
        v.len = v.len.max(end);
        v.dirty = true;
        Ok(())
    }

    /// Writes logical block `lb`: in place if it was written since the last
    /// save, otherwise at a new random position.
    fn put_data(&mut self, v: &mut Volume, lb: usize, payload: &[u8; PAYLOAD]) -> Result<()> {
        let old = v.map[lb];
        let target = if old != 0 && v.fresh.contains(&old) {
            old
        } else {
            let fresh = self.allocate()?;
            v.fresh.insert(fresh);
            if old != 0 {
                v.retired.push(old);
            }
            fresh
        };
        self.write_sealed(&v.keys, KIND_DATA, target, payload)?;
        v.map[lb] = target;
        Ok(())
    }

    fn resize(&mut self, v: &mut Volume, len: u64) -> Result<()> {
        if len > self.blocks as u64 * PAYLOAD as u64 {
            return Err(Error::Full);
        }
        if len < v.len {
            for b in v.map.drain(blocks_for(len)..).filter(|&b| b != 0).collect::<Vec<_>>() {
                if v.fresh.remove(&b) {
                    self.scrub(b)?;
                } else {
                    v.retired.push(b);
                }
            }
            // Zero what's left of the last block, so growing again reads zeros.
            let within = (len % PAYLOAD as u64) as usize;
            if within != 0 {
                let lb = v.map.len() - 1;
                if v.map[lb] != 0 {
                    let mut payload = self.read_sealed(&v.keys, KIND_DATA, v.map[lb])?.ok_or(Error::Damaged)?;
                    payload[within..].fill(0);
                    self.put_data(v, lb, &payload)?;
                }
            }
        } else {
            v.map.resize(blocks_for(len), 0);
        }
        v.len = len;
        v.dirty = true;
        Ok(())
    }

    /// Writes the map and then the superblock, into the slot that isn't
    /// current; only then releases what the old state used.
    fn save(&mut self, v: &mut Volume) -> Result<()> {
        let chunks: Vec<&[u32]> = v.map.chunks(MAP_ENTRIES).collect();
        let mut new_map = Vec::with_capacity(chunks.len());
        for _ in 0..chunks.len() {
            match self.allocate() {
                Ok(b) => new_map.push(b),
                Err(e) => {
                    new_map.into_iter().for_each(|b| self.unmark(b));
                    return Err(e);
                }
            }
        }
        for (i, chunk) in chunks.iter().enumerate() {
            let mut payload = Zeroizing::new([0u8; PAYLOAD]);
            payload[..4].copy_from_slice(&new_map.get(i + 1).copied().unwrap_or(0).to_le_bytes());
            payload[4..8].copy_from_slice(&(chunk.len() as u32).to_le_bytes());
            for (j, b) in chunk.iter().enumerate() {
                payload[8 + j * 4..12 + j * 4].copy_from_slice(&b.to_le_bytes());
            }
            self.write_sealed(&v.keys, KIND_MAP, new_map[i], &payload)?;
        }

        let mut sup = Zeroizing::new([0u8; PAYLOAD]);
        let gen = v.gen + 1;
        sup[..8].copy_from_slice(SUPER_MAGIC);
        sup[8..16].copy_from_slice(&gen.to_le_bytes());
        sup[16..24].copy_from_slice(&v.len.to_le_bytes());
        sup[24..28].copy_from_slice(&new_map.first().copied().unwrap_or(0).to_le_bytes());
        sup[28..32].copy_from_slice(&(new_map.len() as u32).to_le_bytes());
        sup[32] = v.below.len() as u8;
        for (i, k) in v.below.iter().enumerate() {
            sup[SUPER_HEAD + i * 32..SUPER_HEAD + (i + 1) * 32].copy_from_slice(&k[..]);
        }
        let next = 1 - v.current;
        // Everything the new superblock points to must be on the disk first.
        self.dev.sync()?;
        self.write_sealed(&v.keys, KIND_SUPER, v.slots[next], &sup)?;
        self.dev.sync()?;

        let old_map = std::mem::replace(&mut v.map_blocks, new_map);
        for b in old_map.into_iter().chain(std::mem::take(&mut v.retired)) {
            self.scrub(b)?;
        }
        v.current = next;
        v.gen = gen;
        v.fresh.clear();
        v.dirty = false;
        Ok(())
    }

    fn load_map(&mut self, keys: &Keys, head: u32, count: usize, entries: usize) -> Result<(Vec<u32>, Vec<u32>)> {
        if count != entries.div_ceil(MAP_ENTRIES) {
            return Err(Error::Damaged);
        }
        let mut map = Vec::with_capacity(entries);
        let mut blocks = Vec::with_capacity(count);
        let mut at = head;
        for _ in 0..count {
            if at == 0 || at >= self.blocks || blocks.contains(&at) {
                return Err(Error::Damaged);
            }
            let payload = self.read_sealed(keys, KIND_MAP, at)?.ok_or(Error::Damaged)?;
            let n = u32_at(&payload[..], 4) as usize;
            if n > MAP_ENTRIES {
                return Err(Error::Damaged);
            }
            for j in 0..n {
                let b = u32_at(&payload[..], 8 + j * 4);
                if b >= self.blocks {
                    return Err(Error::Damaged);
                }
                map.push(b);
            }
            blocks.push(at);
            at = u32_at(&payload[..], 0);
        }
        if map.len() != entries || at != 0 {
            return Err(Error::Damaged);
        }
        Ok((map, blocks))
    }

    fn read_sealed(&mut self, keys: &Keys, kind: u8, index: u32) -> Result<Option<Zeroizing<[u8; PAYLOAD]>>> {
        let mut block = Zeroizing::new([0u8; BLOCK]);
        self.dev.read(index as u64, &mut block)?;
        let mut payload = Zeroizing::new([0u8; PAYLOAD]);
        payload.copy_from_slice(&block[NONCE..NONCE + PAYLOAD]);
        let nonce = XNonce::from_slice(&block[..NONCE]);
        let tag = Tag::from_slice(&block[NONCE + PAYLOAD..]);
        let cipher = XChaCha20Poly1305::new((&*keys.enc).into());
        match cipher.decrypt_in_place_detached(nonce, &aad(&self.salt, kind, index), &mut payload[..], tag) {
            Ok(()) => Ok(Some(payload)),
            Err(_) => Ok(None),
        }
    }

    fn write_sealed(&mut self, keys: &Keys, kind: u8, index: u32, payload: &[u8; PAYLOAD]) -> Result<()> {
        let mut block = Zeroizing::new([0u8; BLOCK]);
        random(&mut block[..NONCE])?;
        block[NONCE..NONCE + PAYLOAD].copy_from_slice(payload);
        let cipher = XChaCha20Poly1305::new((&*keys.enc).into());
        let nonce = *XNonce::from_slice(&block[..NONCE]);
        let tag = cipher
            .encrypt_in_place_detached(&nonce, &aad(&self.salt, kind, index), &mut block[NONCE..NONCE + PAYLOAD])
            .map_err(|_| Error::Damaged)?;
        block[NONCE + PAYLOAD..].copy_from_slice(&tag);
        self.dev.write(index as u64, &block)?;
        self.writes += 1;
        Ok(())
    }

    /// Overwrites a block with random bytes and makes it free.
    fn scrub(&mut self, index: u32) -> Result<()> {
        let mut block = Zeroizing::new([0u8; BLOCK]);
        self.noise.fill(&mut block[..])?;
        self.dev.write(index as u64, &block)?;
        self.unmark(index);
        Ok(())
    }

    /// Rewrites `count` random free blocks with new random bytes.
    fn cover(&mut self, count: u64) -> Result<()> {
        let free = self.blocks as u64 - self.used_count as u64;
        let mut block = Zeroizing::new([0u8; BLOCK]);
        for _ in 0..count.min(free) {
            let Some(b) = self.random_free() else { break };
            self.noise.fill(&mut block[..])?;
            self.dev.write(b as u64, &block)?;
        }
        Ok(())
    }

    fn random_free(&self) -> Option<u32> {
        let span = self.blocks as u64 - 1;
        for _ in 0..64 {
            let b = 1 + (random_u64().ok()? % span) as u32;
            if !self.is_used(b) {
                return Some(b);
            }
        }
        // Nearly full: look from a random place onwards.
        let start = random_u64().ok()? % span;
        (0..span).map(|k| 1 + ((start + k) % span) as u32).find(|&b| !self.is_used(b))
    }

    fn allocate(&mut self) -> Result<u32> {
        let b = self.random_free().ok_or(Error::Full)?;
        self.mark(b)?;
        Ok(b)
    }

    fn is_used(&self, b: u32) -> bool {
        self.used[b as usize / 64] & (1 << (b % 64)) != 0
    }

    /// Claims a block; a block that's claimed already means two volumes
    /// think they own it.
    fn mark(&mut self, b: u32) -> Result<()> {
        if b >= self.blocks || self.is_used(b) {
            return Err(Error::Damaged);
        }
        self.used[b as usize / 64] |= 1 << (b % 64);
        self.used_count += 1;
        Ok(())
    }

    fn unmark(&mut self, b: u32) {
        if self.is_used(b) {
            self.used[b as usize / 64] &= !(1 << (b % 64));
            self.used_count -= 1;
        }
    }
}

fn checked_size(blocks: u64) -> Result<u32> {
    if !(MIN_BLOCKS..=u32::MAX as u64).contains(&blocks) {
        return Err(Error::BadSize);
    }
    Ok(blocks as u32)
}

fn blocks_for(len: u64) -> usize {
    len.div_ceil(PAYLOAD as u64) as usize
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

/// Binds a block to this container, its position and what it's for, so
/// blocks can't be moved around or swapped between containers.
fn aad(salt: &[u8; SALT], kind: u8, index: u32) -> [u8; 12 + SALT + 4] {
    let mut out = [0u8; 12 + SALT + 4];
    out[..11].copy_from_slice(b"deniable v1");
    out[11] = kind;
    out[12..12 + SALT].copy_from_slice(salt);
    out[12 + SALT..].copy_from_slice(&index.to_le_bytes());
    out
}

fn prf(key: &[u8; 32], label: &[u8], input: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut mac = <Blake2bMac<U32> as Mac>::new_from_slice(key).expect("32-byte key");
    mac.update(label);
    mac.update(&[0]);
    mac.update(input);
    let mut out = Zeroizing::new([0u8; 32]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

fn derive(master: &[u8; 32]) -> Keys {
    Keys { enc: prf(master, b"deniable v1 encryption", &[]), loc: prf(master, b"deniable v1 location", &[]) }
}

fn random(buf: &mut [u8]) -> Result<()> {
    getrandom::getrandom(buf).map_err(|e| Error::Io(io::Error::other(e)))
}

fn random_u64() -> Result<u64> {
    let mut b = [0u8; 8];
    random(&mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Random bytes in bulk, for filling and scrubbing blocks: ChaCha20 under a
/// random key, renewed long before its counter could run out.
struct Noise {
    cipher: chacha20::ChaCha20,
    left: u64,
}

impl Noise {
    const PER_KEY: u64 = 1 << 36;

    fn new() -> Result<Self> {
        let mut key = Zeroizing::new([0u8; 32]);
        let mut nonce = [0u8; 12];
        random(&mut key[..])?;
        random(&mut nonce)?;
        Ok(Self { cipher: chacha20::ChaCha20::new((&*key).into(), (&nonce).into()), left: Self::PER_KEY })
    }

    fn fill(&mut self, buf: &mut [u8]) -> Result<()> {
        if self.left < buf.len() as u64 {
            *self = Self::new()?;
        }
        buf.zeroize();
        self.cipher.apply_keystream(buf);
        self.left -= buf.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
