//! An onion service's identity, small enough to audit in one sitting.
//!
//! The editor keeps these keys in the vault but must not contain Tor itself,
//! so the two things it needs, making a key and showing its address, live
//! here with no networking code at all.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::hazmat::ExpandedSecretKey;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha3::{Digest, Sha3_256};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

#[cfg(target_pointer_width = "64")]
mod fast;

use zeroize::Zeroizing;

/// An expanded Ed25519 secret key, in the layout Tor uses: the scalar, then
/// the hash prefix. Whoever holds these bytes owns the onion address.
pub type Identity = Zeroizing<[u8; 64]>;

const VERSION: u8 = 3;

/// Makes a new identity from the operating system's secure randomness.
pub fn new_identity() -> Result<Identity, getrandom::Error> {
    let mut seed = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(seed.as_mut())?;
    let expanded = ExpandedSecretKey::from(&*seed);
    let mut identity = Zeroizing::new([0u8; 64]);
    identity[..32].copy_from_slice(&expanded.scalar.to_bytes());
    identity[32..].copy_from_slice(&expanded.hash_prefix);
    Ok(identity)
}

/// The `.onion` address an identity publishes at (rend-spec-v3, section 6).
pub fn address(identity: &Identity) -> String {
    // The stored scalar is already clamped and reduced; clamping it a second
    // time, as the usual key-loading routines do, would yield a different key.
    let mut scalar = Zeroizing::new([0u8; 32]);
    scalar.copy_from_slice(&identity[..32]);
    let public = EdwardsPoint::mul_base(&Scalar::from_bytes_mod_order(*scalar)).compress().to_bytes();
    let checksum = Sha3_256::new()
        .chain_update(b".onion checksum")
        .chain_update(public)
        .chain_update([VERSION])
        .finalize();
    let mut raw = [0u8; 35];
    raw[..32].copy_from_slice(&public);
    raw[32..34].copy_from_slice(&checksum[..2]);
    raw[34] = VERSION;
    format!("{}.onion", BASE32_NOPAD.encode(&raw).to_ascii_lowercase())
}

/// The letters an onion address is written in (RFC 4648 base32, lowercase).
const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
/// Longer than this would take far longer than anyone would wait.
pub const MAX_PREFIX: usize = 12;

/// Why a wanted beginning cannot be an onion address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BadPrefix {
    Empty,
    TooLong,
    /// The letter at this position cannot appear: onion addresses use a-z and 2-7.
    Letter(usize, char),
}

impl std::fmt::Display for BadPrefix {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            BadPrefix::Empty => f.write_str("type the letters the address should start with"),
            BadPrefix::TooLong => write!(f, "at most {MAX_PREFIX} letters: more would take years"),
            BadPrefix::Letter(_, c) => write!(f, "\"{c}\" cannot appear in an onion address: use a to z and 2 to 7 (no 0, 1, 8 or 9)"),
        }
    }
}

/// The bits an address beginning with some letters has in its public key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prefix {
    text: String,
    bytes: Vec<u8>,
    masks: Vec<u8>,
}

impl Prefix {
    pub fn new(wanted: &str) -> Result<Self, BadPrefix> {
        let text = wanted.trim().to_ascii_lowercase();
        if text.is_empty() {
            return Err(BadPrefix::Empty);
        }
        if text.len() > MAX_PREFIX {
            return Err(BadPrefix::TooLong);
        }
        let mut bits = Vec::with_capacity(text.len() * 5);
        for (at, c) in text.chars().enumerate() {
            let value = ALPHABET.iter().position(|&a| a as char == c).ok_or(BadPrefix::Letter(at, c))?;
            bits.extend((0..5).rev().map(|shift| (value >> shift) & 1 == 1));
        }
        let mut bytes = vec![0u8; bits.len().div_ceil(8)];
        let mut masks = vec![0u8; bytes.len()];
        for (at, bit) in bits.iter().enumerate() {
            let place = 7 - (at % 8);
            masks[at / 8] |= 1 << place;
            if *bit {
                bytes[at / 8] |= 1 << place;
            }
        }
        Ok(Self { text, bytes, masks })
    }

    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// How many keys must be tried, on average, to find one.
    pub fn expected_tries(&self) -> f64 {
        32f64.powi(self.text.len() as i32)
    }

    fn matches(&self, public: &[u8; 32]) -> bool {
        self.bytes.iter().zip(&self.masks).zip(public).all(|((want, mask), have)| have & mask == *want)
    }
}

/// Tries keys until one's address begins with `prefix`, or until `stop` is
/// set. Counts what it tries into `tried`. Run it on as many threads as the
/// device can spare; each one searches on its own.
///
/// Each thread starts from a fresh random key and steps through the keys
/// after it: adding the base point to a public key is far cheaper than
/// computing one from scratch, and the secret follows by adding one. The
/// result is as random as any other key: its start was.
pub fn mine(prefix: &Prefix, stop: &AtomicBool, tried: &AtomicU64) -> Option<Identity> {
    mine_any(std::slice::from_ref(prefix), stop, tried)
}

/// Like [`mine`], for an address beginning with any one of `prefixes`:
/// whichever turns up first. Each extra prefix adds its own chance per key
/// tried, so the wait is about that of one prefix divided by how many there
/// are, if they are the same length. A shorter one dominates.
pub fn mine_any(prefixes: &[Prefix], stop: &AtomicBool, tried: &AtomicU64) -> Option<Identity> {
    if prefixes.is_empty() {
        return None;
    }
    #[cfg(target_pointer_width = "64")]
    {
        mine_fast(prefixes, stop, tried)
    }
    #[cfg(not(target_pointer_width = "64"))]
    {
        mine_simple(prefixes, stop, tried)
    }
}

/// How many keys must be tried, on average, before one begins with any of
/// `prefixes`.
pub fn expected_tries_any(prefixes: &[Prefix]) -> f64 {
    1.0 / prefixes.iter().map(|p| 1.0 / p.expected_tries()).sum::<f64>()
}

/// How many keys one thread walks side by side.
#[cfg(target_pointer_width = "64")]
const WALKERS: usize = 256;

/// The search of [`mine`], with many keys per thread sharing one inversion
/// per step: see the `fast` module. About ten times the speed.
#[cfg(target_pointer_width = "64")]
fn mine_fast(prefixes: &[Prefix], stop: &AtomicBool, tried: &AtomicU64) -> Option<Identity> {
    let d = fast::curve_d();
    let base = fast::decompress(&curve25519_dalek::constants::ED25519_BASEPOINT_POINT.compress().to_bytes(), &d)?;
    let start = new_identity().ok()?;
    let mut first = Zeroizing::new([0u8; 32]);
    first.copy_from_slice(&start[..32]);
    let first = Zeroizing::new(Scalar::from_bytes_mod_order(*first));
    // Walkers start 2^40 keys apart, so they never cover the same keys.
    let spacing = Scalar::from(1u64 << 40);
    let mut secrets = Vec::with_capacity(WALKERS);
    let mut points = Vec::with_capacity(WALKERS);
    for walker in 0..WALKERS {
        let secret = Zeroizing::new(*first + spacing * Scalar::from(walker as u64));
        points.push(fast::decompress(&EdwardsPoint::mul_base(&secret).compress().to_bytes(), &d)?);
        secrets.push(secret);
    }
    let mut walk = fast::Walk::new(points, base, &d);
    let mut steps = 0u64;
    loop {
        for walker in 0..WALKERS {
            // At most 12 letters: only the start of y matters, never the sign of x.
            let y = walk.ys[walker].to_bytes();
            if prefixes.iter().any(|prefix| prefix.matches(&y)) {
                let secret = Zeroizing::new(*secrets[walker] + Scalar::from(steps));
                let mut identity = Zeroizing::new([0u8; 64]);
                identity[..32].copy_from_slice(&secret.to_bytes());
                identity[32..].copy_from_slice(&start[32..]);
                // Checked by the ordinary key code: only a real match is returned.
                let found = address(&identity);
                if prefixes.iter().any(|prefix| found.starts_with(prefix.as_str())) {
                    return Some(identity);
                }
            }
        }
        tried.fetch_add(WALKERS as u64, Ordering::Relaxed);
        walk.step();
        steps += 1;
        if steps % 16 == 0 && stop.load(Ordering::Relaxed) {
            return None;
        }
    }
}

/// The plain search: one key at a time.
#[cfg_attr(target_pointer_width = "64", allow(dead_code))]
fn mine_simple(prefixes: &[Prefix], stop: &AtomicBool, tried: &AtomicU64) -> Option<Identity> {
    const BATCH: u64 = 4096;
    let start = new_identity().ok()?;
    let mut scalar_bytes = Zeroizing::new([0u8; 32]);
    scalar_bytes.copy_from_slice(&start[..32]);
    let base = Zeroizing::new(Scalar::from_bytes_mod_order(*scalar_bytes));
    let mut point = EdwardsPoint::mul_base(&base);
    let step = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let mut offset = 0u64;
    loop {
        for _ in 0..BATCH {
            let public = point.compress().to_bytes();
            if prefixes.iter().any(|prefix| prefix.matches(&public)) {
                tried.fetch_add(offset % BATCH, Ordering::Relaxed);
                let secret = Zeroizing::new(*base + Scalar::from(offset));
                let mut identity = Zeroizing::new([0u8; 64]);
                identity[..32].copy_from_slice(&secret.to_bytes());
                identity[32..].copy_from_slice(&start[32..]);
                return Some(identity);
            }
            point += step;
            offset += 1;
        }
        tried.fetch_add(BATCH, Ordering::Relaxed);
        if stop.load(Ordering::Relaxed) {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn addresses_are_stable_distinct_and_well_formed() {
        let a = new_identity().unwrap();
        let b = new_identity().unwrap();
        assert_eq!(address(&a), address(&a));
        assert_ne!(address(&a), address(&b));
        let name = address(&a);
        assert_eq!(name.len(), 62);
        assert!(name.ends_with("d.onion"), "v3 addresses always end in d: {name}");
    }

    #[test]
    fn a_mined_address_starts_with_what_was_asked_for() {
        let prefix = Prefix::new("ab").unwrap();
        let (stop, tried) = (AtomicBool::new(false), AtomicU64::new(0));
        let identity = mine(&prefix, &stop, &tried).unwrap();
        assert!(address(&identity).starts_with("ab"), "{}", address(&identity));
        // And it is a working key, not only a matching address.
        assert_eq!(address(&identity).len(), 62);
    }

    /// The fast walk lands on exactly the points the curve library computes.
    #[cfg(target_pointer_width = "64")]
    #[test]
    fn the_fast_walk_agrees_with_the_curve_library() {
        let d = fast::curve_d();
        let base_point = curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
        let base = fast::decompress(&base_point.compress().to_bytes(), &d).unwrap();
        let starts: Vec<EdwardsPoint> =
            (1..=5u64).map(|n| EdwardsPoint::mul_base(&Scalar::from(n * 1_000_003 + 7))).collect();
        let affine = starts.iter().map(|p| fast::decompress(&p.compress().to_bytes(), &d).unwrap()).collect();
        let mut walk = fast::Walk::new(affine, base, &d);
        let mut expected = starts.clone();
        for _ in 0..20 {
            for (at, point) in expected.iter().enumerate() {
                assert_eq!(fast::compress(&walk.xs[at], &walk.ys[at]), point.compress().to_bytes());
            }
            walk.step();
            for point in &mut expected {
                *point += base_point;
            }
        }
        // And the slow search finds real matches too.
        let prefix = Prefix::new("a").unwrap();
        let (stop, tried) = (AtomicBool::new(false), AtomicU64::new(0));
        assert!(address(&mine_simple(std::slice::from_ref(&prefix), &stop, &tried).unwrap()).starts_with('a'));
    }

    #[test]
    fn any_of_several_prefixes_is_found() {
        let wanted: Vec<Prefix> = ["zz", "ab", "q7"].iter().map(|w| Prefix::new(w).unwrap()).collect();
        let (stop, tried) = (AtomicBool::new(false), AtomicU64::new(0));
        let found = address(&mine_any(&wanted, &stop, &tried).unwrap());
        assert!(wanted.iter().any(|p| found.starts_with(p.as_str())), "{found}");
        // Three prefixes of two letters: a third of the wait for one.
        assert!((expected_tries_any(&wanted) - 1024.0 / 3.0).abs() < 1e-6);
        assert!(mine_any(&[], &stop, &tried).is_none());
    }

    #[test]
    fn only_possible_prefixes_are_accepted() {
        assert!(Prefix::new("torus").is_ok());
        assert_eq!(Prefix::new(" Torus ").unwrap().as_str(), "torus");
        assert_eq!(Prefix::new("ab1"), Err(BadPrefix::Letter(2, '1')));
        assert_eq!(Prefix::new(""), Err(BadPrefix::Empty));
        assert_eq!(Prefix::new("abcdefghijklm"), Err(BadPrefix::TooLong));
        assert_eq!(Prefix::new("abc").unwrap().expected_tries(), 32768.0);
    }

    #[test]
    #[ignore = "a benchmark: how many keys one thread tries per second"]
    fn speed() {
        let prefix = Prefix::new("zzzzzzzzzz").unwrap();
        let (stop, tried) = (AtomicBool::new(false), AtomicU64::new(0));
        std::thread::scope(|scope| {
            scope.spawn(|| mine(&prefix, &stop, &tried));
            std::thread::sleep(std::time::Duration::from_secs(5));
            stop.store(true, Ordering::Relaxed);
        });
        println!("{} keys per second on one thread", tried.load(Ordering::Relaxed) / 5);
    }
}
