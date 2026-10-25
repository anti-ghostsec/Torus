use std::io::{Read, Seek, SeekFrom, Write};

use super::*;

/// Cheap enough for tests; real use takes [`Kdf::DEFAULT`] or more.
const FAST: Kdf = Kdf { memory_kib: 64, passes: 1, lanes: 1 };

fn fresh(blocks: u64) -> Store<MemDevice> {
    Store::format(MemDevice::new(blocks), FAST).unwrap()
}

fn reopen(store: Store<MemDevice>) -> Store<MemDevice> {
    Store::open(store.into_device(), FAST).unwrap()
}

fn read_all(store: &mut Store<MemDevice>, id: VolumeId) -> Vec<u8> {
    let mut out = vec![0; store.len(id).unwrap() as usize];
    assert_eq!(store.read(id, 0, &mut out).unwrap(), out.len());
    out
}

fn pattern(len: usize, seed: u8) -> Vec<u8> {
    (0..len).map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed)).collect()
}

#[test]
fn a_volume_survives_closing_and_opening() {
    let mut store = fresh(256);
    let id = store.create(b"correct horse", &[]).unwrap();
    store.write(id, 0, b"hello, hidden world").unwrap();
    store.flush().unwrap();

    let mut store = reopen(store);
    let id = store.unlock(b"correct horse").unwrap();
    assert_eq!(read_all(&mut store, id), b"hello, hidden world");
}

#[test]
fn a_wrong_password_and_a_missing_volume_look_the_same() {
    let mut store = fresh(256);
    store.create(b"right", &[]).unwrap();
    store.flush().unwrap();
    let mut store = reopen(store);
    assert!(matches!(store.unlock(b"wrong"), Err(Error::NotFound)));
    let mut empty = fresh(256);
    assert!(matches!(empty.unlock(b"right"), Err(Error::NotFound)));
}

#[test]
fn the_top_password_opens_everything_and_the_lower_one_only_itself() {
    let mut store = fresh(512);
    let decoy = store.create(b"decoy", &[]).unwrap();
    let hidden = store.create(b"hidden", &[decoy]).unwrap();
    store.write(decoy, 0, b"shopping list").unwrap();
    store.write(hidden, 0, &pattern(20_000, 7)).unwrap();
    store.flush().unwrap();

    let mut store = reopen(store);
    let hidden = store.unlock(b"hidden").unwrap();
    let below = store.below(hidden).unwrap();
    assert_eq!(below.len(), 1);
    assert_eq!(read_all(&mut store, below[0]), b"shopping list");
    assert_eq!(read_all(&mut store, hidden), pattern(20_000, 7));

    // Under pressure: only the decoy is revealed, and nothing in it points up.
    let mut store = reopen(store);
    let decoy = store.unlock(b"decoy").unwrap();
    assert_eq!(store.volumes(), vec![decoy]);
    assert!(store.below(decoy).unwrap().is_empty());
    assert_eq!(read_all(&mut store, decoy), b"shopping list");
}

#[test]
fn working_with_everything_unlocked_never_harms_the_lower_volume() {
    let mut store = fresh(1024);
    let decoy = store.create(b"decoy", &[]).unwrap();
    store.write(decoy, 0, &pattern(50_000, 1)).unwrap();
    let hidden = store.create(b"hidden", &[decoy]).unwrap();
    store.flush().unwrap();
    for round in 0..20u8 {
        store.write(hidden, round as u64 * 1000, &pattern(30_000, round)).unwrap();
        store.flush().unwrap();
    }
    let mut store = reopen(store);
    let decoy = store.unlock(b"decoy").unwrap();
    assert_eq!(read_all(&mut store, decoy), pattern(50_000, 1));
}

#[test]
fn the_container_looks_random_before_and_after_use() {
    fn looks_random(bytes: &[u8]) {
        let mut counts = [0u64; 256];
        bytes.iter().for_each(|&b| counts[b as usize] += 1);
        let expected = bytes.len() as f64 / 256.0;
        let chi: f64 = counts.iter().map(|&c| (c as f64 - expected).powi(2) / expected).sum();
        // 255 degrees of freedom: anything this far out is not random.
        assert!(chi < 400.0, "chi-square {chi}");
        assert!(bytes.chunks(BLOCK).all(|b| b.iter().any(|&x| x != 0)), "an all-zero block");
    }
    let mut store = fresh(512);
    looks_random(store.dev.as_bytes());
    let id = store.create(b"pw", &[]).unwrap();
    // Very regular plaintext, which must not show through.
    store.write(id, 0, &vec![0u8; 200_000]).unwrap();
    store.write(id, 300_000, &vec![b'A'; 100_000]).unwrap();
    store.flush().unwrap();
    looks_random(store.dev.as_bytes());
    assert!(!store.dev.as_bytes().windows(64).any(|w| w.iter().all(|&b| b == b'A')));
}

#[test]
fn changes_that_were_never_saved_are_gone() {
    let mut store = fresh(256);
    let id = store.create(b"pw", &[]).unwrap();
    store.write(id, 0, b"kept").unwrap();
    store.flush().unwrap();
    store.write(id, 0, b"lost, never saved").unwrap();
    let mut store = reopen(store);
    let id = store.unlock(b"pw").unwrap();
    assert_eq!(read_all(&mut store, id), b"kept");
}

/// Writes go through until `torn_at` is written: that write leaves garbage
/// and fails, as a power cut in the middle of it would.
struct PowerCut {
    inner: MemDevice,
    torn_at: Option<u64>,
}

impl BlockDevice for PowerCut {
    fn blocks(&self) -> u64 {
        self.inner.blocks()
    }
    fn read(&mut self, index: u64, buf: &mut [u8; BLOCK]) -> io::Result<()> {
        self.inner.read(index, buf)
    }
    fn write(&mut self, index: u64, buf: &[u8; BLOCK]) -> io::Result<()> {
        if self.torn_at == Some(index) {
            let mut half = *buf;
            half[BLOCK / 2..].fill(0x5a);
            self.inner.write(index, &half)?;
            return Err(io::Error::other("power cut"));
        }
        self.inner.write(index, buf)
    }
    fn sync(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn a_power_cut_while_saving_leaves_the_previous_state() {
    let mut store = Store::format(PowerCut { inner: MemDevice::new(256), torn_at: None }, FAST).unwrap();
    let id = store.create(b"pw", &[]).unwrap();
    store.write(id, 0, &pattern(9000, 3)).unwrap();
    store.flush().unwrap();

    store.write(id, 0, &pattern(9000, 4)).unwrap();
    let v = store.volume(id).unwrap();
    store.dev.torn_at = Some(v.slots[1 - v.current] as u64);
    assert!(store.flush().is_err());

    let mut dev = store.into_device();
    dev.torn_at = None;
    let mut store = Store::open(dev, FAST).unwrap();
    let id = store.unlock(b"pw").unwrap();
    let mut out = vec![0; 9000];
    store.read(id, 0, &mut out).unwrap();
    assert_eq!(out, pattern(9000, 3));
}

#[test]
fn partial_writes_holes_and_resizing() {
    let mut store = fresh(256);
    let id = store.create(b"pw", &[]).unwrap();
    // A hole: the first blocks were never written and read as zeros.
    store.write(id, 3 * PAYLOAD as u64 + 10, b"far out").unwrap();
    let mut out = vec![1u8; 3 * PAYLOAD + 17];
    store.read(id, 0, &mut out).unwrap();
    assert!(out[..3 * PAYLOAD + 10].iter().all(|&b| b == 0));
    assert_eq!(&out[3 * PAYLOAD + 10..], b"far out");

    // A write across a block boundary, then one inside it.
    store.write(id, PAYLOAD as u64 - 3, b"abcdef").unwrap();
    store.write(id, PAYLOAD as u64 - 1, b"Z").unwrap();
    let mut out = [0u8; 6];
    store.read(id, PAYLOAD as u64 - 3, &mut out).unwrap();
    assert_eq!(&out, b"abZdef");
    store.flush().unwrap();

    // Shrinking forgets the tail, and growing again reads zeros there.
    store.set_len(id, PAYLOAD as u64).unwrap();
    store.set_len(id, PAYLOAD as u64 + 100).unwrap();
    let mut out = [9u8; 100];
    store.read(id, PAYLOAD as u64, &mut out).unwrap();
    assert!(out.iter().all(|&b| b == 0));
    store.set_len(id, PAYLOAD as u64 - 2).unwrap();
    store.set_len(id, PAYLOAD as u64).unwrap();
    let mut out = [9u8; 2];
    store.read(id, PAYLOAD as u64 - 2, &mut out).unwrap();
    assert_eq!(out, [0, 0]);
    store.flush().unwrap();

    let mut store = reopen(store);
    let id = store.unlock(b"pw").unwrap();
    assert_eq!(store.len(id).unwrap(), PAYLOAD as u64);
    let mut out = [9u8; 3];
    store.read(id, PAYLOAD as u64 - 3, &mut out).unwrap();
    assert_eq!(&out, b"a\0\0");
}

#[test]
fn a_volume_bigger_than_one_map_block() {
    let mut store = fresh(4096);
    let id = store.create(b"pw", &[]).unwrap();
    let data = pattern(MAP_ENTRIES * PAYLOAD * 2 + 12345, 9);
    store.write(id, 0, &data).unwrap();
    store.flush().unwrap();
    assert_eq!(store.volume(id).unwrap().map_blocks.len(), 3);
    let mut store = reopen(store);
    let id = store.unlock(b"pw").unwrap();
    assert_eq!(read_all(&mut store, id), data);
}

#[test]
fn rewriting_keeps_the_same_number_of_blocks_in_use() {
    let mut store = fresh(512);
    let id = store.create(b"pw", &[]).unwrap();
    store.write(id, 0, &pattern(40_000, 0)).unwrap();
    store.flush().unwrap();
    let in_use = store.used_count;
    for round in 0..10 {
        store.write(id, 0, &pattern(40_000, round)).unwrap();
        store.write(id, 0, &pattern(40_000, round + 1)).unwrap();
        store.flush().unwrap();
        assert_eq!(store.used_count, in_use);
    }
}

#[test]
fn a_replaced_block_can_no_longer_be_read_with_the_key() {
    let mut store = fresh(256);
    let id = store.create(b"pw", &[]).unwrap();
    store.write(id, 0, b"first version").unwrap();
    store.flush().unwrap();
    let old = store.volume(id).unwrap().map[0];
    store.write(id, 0, b"second version").unwrap();
    store.flush().unwrap();
    let v = store.take(id).unwrap();
    assert!(store.read_sealed(&v.keys, KIND_DATA, old).unwrap().is_none());
}

#[test]
fn destroying_a_volume() {
    let mut store = fresh(512);
    let decoy = store.create(b"decoy", &[]).unwrap();
    let hidden = store.create(b"hidden", &[decoy]).unwrap();
    store.write(hidden, 0, b"top").unwrap();
    store.write(decoy, 0, b"bottom").unwrap();
    store.flush().unwrap();
    store.destroy(decoy).unwrap();
    store.flush().unwrap();

    let mut store = reopen(store);
    assert!(matches!(store.unlock(b"decoy"), Err(Error::NotFound)));
    let hidden = store.unlock(b"hidden").unwrap();
    assert!(store.below(hidden).unwrap().is_empty());
    assert_eq!(read_all(&mut store, hidden), b"top");
}

#[test]
fn a_password_can_only_be_used_once() {
    let mut store = fresh(256);
    store.create(b"pw", &[]).unwrap();
    assert!(matches!(store.create(b"pw", &[]), Err(Error::Exists)));
    store.flush().unwrap();
    // Not unlocked, but still there: making it again would wipe it.
    let mut store = reopen(store);
    assert!(matches!(store.create(b"pw", &[]), Err(Error::Exists)));
}

#[test]
fn a_full_container_says_so() {
    let mut store = fresh(MIN_BLOCKS);
    let id = store.create(b"pw", &[]).unwrap();
    assert!(matches!(store.write(id, 0, &vec![1; PAYLOAD * MIN_BLOCKS as usize]), Err(Error::Full)));
    assert!(matches!(Store::format(MemDevice::new(MIN_BLOCKS - 1), FAST), Err(Error::BadSize)));
}

#[test]
fn a_volume_as_a_file() {
    let mut store = fresh(256);
    let id = store.create(b"pw", &[]).unwrap();
    {
        let mut f = store.file(id);
        f.write_all(b"0123456789").unwrap();
        f.seek(SeekFrom::Start(2)).unwrap();
        f.write_all(b"ab").unwrap();
        f.seek(SeekFrom::End(-3)).unwrap();
        let mut tail = String::new();
        f.read_to_string(&mut tail).unwrap();
        assert_eq!(tail, "789");
        f.flush().unwrap();
    }
    let mut store = reopen(store);
    let id = store.unlock(b"pw").unwrap();
    let mut all = String::new();
    store.file(id).read_to_string(&mut all).unwrap();
    assert_eq!(all, "01ab456789");
}

#[test]
fn a_container_in_a_file() {
    let path = std::env::temp_dir().join(format!("deniable-test-{}", std::process::id()));
    let _ = std::fs::remove_file(&path);
    let mut store = Store::format(FileDevice::create(&path, 128).unwrap(), FAST).unwrap();
    let id = store.create(b"pw", &[]).unwrap();
    store.write(id, 0, b"on disk").unwrap();
    store.flush().unwrap();
    drop(store);
    let mut store = Store::open(FileDevice::open(&path).unwrap(), FAST).unwrap();
    let id = store.unlock(b"pw").unwrap();
    let mut out = [0u8; 7];
    store.read(id, 0, &mut out).unwrap();
    assert_eq!(&out, b"on disk");
    std::fs::remove_file(&path).unwrap();
}

#[test]
fn a_volume_can_be_opened_with_a_key_instead_of_a_password() {
    let mut store = fresh(256);
    let key = [7u8; 32];
    let id = store.create_key(&key, &[]).unwrap();
    store.write(id, 0, b"keyed").unwrap();
    store.flush().unwrap();
    let mut store = reopen(store);
    let id = store.unlock_key(&key).unwrap();
    assert_eq!(read_all(&mut store, id), b"keyed");
}
