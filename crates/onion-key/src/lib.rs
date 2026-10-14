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
}
