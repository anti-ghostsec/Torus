//! Sealing: encrypting to a public key so that only the holder of the
//! matching secret can read the result.
//!
//! A site's host holds only the public key, so what visitors send to a
//! sealed collection cannot be read back by the host, by anyone who seizes
//! it, or by anyone who breaks into it. The secret stays in the vault.
//!
//! Two key agreements are combined, and both must be broken to read a
//! message: ML-KEM-768 (FIPS 203), which is designed to withstand quantum
//! computers, and X25519, which has withstood two decades of classical
//! attack. Someone recording sealed data today cannot read it with a
//! quantum computer tomorrow.
//!
//! Sealed message: `version | ephemeral X25519 public key | ML-KEM
//! ciphertext | nonce | XChaCha20-Poly1305 ciphertext`.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use ml_kem::kem::{Decapsulate, Encapsulate, FromSeed, KeyExport, TryKeyInit};
use ml_kem::MlKem768;
use sha3::{Digest, Sha3_256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

type KemPublic = ml_kem::kem::EncapsulationKey<MlKem768>;

const VERSION: u8 = 1;
const X_LEN: usize = 32;
const KEM_SEED_LEN: usize = 64;
const KEM_PUBLIC_LEN: usize = 1184;
const KEM_CIPHERTEXT_LEN: usize = 1088;
const NONCE_LEN: usize = 24;
/// The secret: an ML-KEM seed, then an X25519 secret.
pub const SECRET_LEN: usize = KEM_SEED_LEN + X_LEN;
/// The public key: an X25519 public key, then an ML-KEM encapsulation key.
pub const PUBLIC_LEN: usize = X_LEN + KEM_PUBLIC_LEN;

/// Lowercase hexadecimal, the form keys and sealed messages travel in.
pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Reads lowercase or uppercase hexadecimal, and nothing else: no signs,
/// spaces or prefixes, so each value has exactly one spelling.
pub fn from_hex(text: &str) -> Option<Vec<u8>> {
    let digit = |b: u8| (b as char).to_digit(16).map(|d| d as u8);
    let bytes = text.as_bytes();
    if bytes.len() % 2 != 0 {
        return None;
    }
    bytes.chunks_exact(2).map(|pair| Some(digit(pair[0])? << 4 | digit(pair[1])?)).collect()
}

fn random<const N: usize>() -> Option<Zeroizing<[u8; N]>> {
    let mut bytes = Zeroizing::new([0u8; N]);
    getrandom::getrandom(bytes.as_mut()).ok()?;
    Some(bytes)
}

fn x_secret(secret: &[u8]) -> Option<StaticSecret> {
    let bytes: [u8; X_LEN] = secret.get(KEM_SEED_LEN..SECRET_LEN)?.try_into().ok()?;
    Some(StaticSecret::from(bytes))
}

/// Makes a new secret from the operating system's secure randomness.
pub fn new_secret() -> Option<Zeroizing<Vec<u8>>> {
    Some(Zeroizing::new(random::<SECRET_LEN>()?.to_vec()))
}

/// The public key that goes with a secret. `None` if the secret is damaged.
pub fn public_key(secret: &[u8]) -> Option<Vec<u8>> {
    if secret.len() != SECRET_LEN {
        return None;
    }
    let seed = secret[..KEM_SEED_LEN].try_into().ok()?;
    let (_, kem_public) = MlKem768::from_seed(&seed);
    let mut public = PublicKey::from(&x_secret(secret)?).as_bytes().to_vec();
    public.extend_from_slice(&kem_public.to_bytes());
    Some(public)
}

/// The message key: both shared secrets, bound to everything that was sent
/// and to the key it was sent to.
fn message_key(quantum_safe: &[u8], classical: &[u8], header: &[u8], public: &[u8]) -> Zeroizing<[u8; 32]> {
    let digest = Sha3_256::new()
        .chain_update(b"torus-seal-v1")
        .chain_update(quantum_safe)
        .chain_update(classical)
        .chain_update(header)
        .chain_update(public)
        .finalize();
    Zeroizing::new(digest.into())
}

/// Encrypts `message` so that only the holder of the secret behind `public`
/// can read it. `None` if `public` is not a public key.
pub fn seal(public: &[u8], message: &[u8]) -> Option<Vec<u8>> {
    if public.len() != PUBLIC_LEN {
        return None;
    }
    let (x_public, kem_public) = public.split_at(X_LEN);
    let kem_public = KemPublic::new_from_slice(kem_public).ok()?;
    let (kem_ciphertext, quantum_safe) = kem_public.encapsulate();

    let ephemeral = StaticSecret::from(*random::<X_LEN>()?);
    let x_public: [u8; X_LEN] = x_public.try_into().ok()?;
    let classical = ephemeral.diffie_hellman(&PublicKey::from(x_public));
    // A public key crafted to force a known shared secret adds nothing; refuse it.
    if !classical.was_contributory() {
        return None;
    }

    let mut sealed = vec![VERSION];
    sealed.extend_from_slice(PublicKey::from(&ephemeral).as_bytes());
    sealed.extend_from_slice(&kem_ciphertext);
    let key = message_key(&quantum_safe, classical.as_bytes(), &sealed, public);
    let nonce = random::<NONCE_LEN>()?;
    let body = XChaCha20Poly1305::new(key.as_ref().into()).encrypt(XNonce::from_slice(nonce.as_ref()), message).ok()?;
    sealed.extend_from_slice(nonce.as_ref());
    sealed.extend_from_slice(&body);
    Some(sealed)
}

/// Decrypts what [`seal`] produced. `None` if it was not sealed to this
/// secret or has been altered.
pub fn open(secret: &[u8], sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let header_len = 1 + X_LEN + KEM_CIPHERTEXT_LEN;
    if secret.len() != SECRET_LEN || sealed.len() < header_len + NONCE_LEN || sealed[0] != VERSION {
        return None;
    }
    let public = public_key(secret)?;
    let (header, rest) = sealed.split_at(header_len);
    let (nonce, body) = rest.split_at(NONCE_LEN);

    let seed = secret[..KEM_SEED_LEN].try_into().ok()?;
    let (kem_secret, _) = MlKem768::from_seed(&seed);
    let quantum_safe = kem_secret.decapsulate_slice(&header[1 + X_LEN..]).ok()?;
    let ephemeral: [u8; X_LEN] = header[1..1 + X_LEN].try_into().ok()?;
    let classical = x_secret(secret)?.diffie_hellman(&PublicKey::from(ephemeral));

    let key = message_key(&quantum_safe, classical.as_bytes(), header, &public);
    XChaCha20Poly1305::new(key.as_ref().into()).decrypt(XNonce::from_slice(nonce), body).ok().map(Zeroizing::new)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_secret_opens_what_was_sealed_to_its_public_key() {
        let secret = new_secret().unwrap();
        let public = public_key(&secret).unwrap();
        assert_eq!((secret.len(), public.len()), (SECRET_LEN, PUBLIC_LEN));
        assert_eq!(public, public_key(&secret).unwrap(), "the public key follows from the secret");

        let sealed = seal(&public, b"meet at the usual place").unwrap();
        assert!(!sealed.windows(5).any(|w| w == b"usual"));
        assert_eq!(open(&secret, &sealed).unwrap().as_slice(), b"meet at the usual place");
        // Sealing the same words twice never gives the same bytes.
        assert_ne!(sealed, seal(&public, b"meet at the usual place").unwrap());
        assert_eq!(open(&secret, &seal(&public, b"").unwrap()).unwrap().as_slice(), b"");

        let other = new_secret().unwrap();
        assert!(open(&other, &sealed).is_none(), "another secret opened it");
    }

    #[test]
    fn anything_altered_or_malformed_is_refused() {
        let secret = new_secret().unwrap();
        let public = public_key(&secret).unwrap();
        let sealed = seal(&public, b"message").unwrap();

        // One flipped bit anywhere: version, either key exchange, nonce or body.
        for at in [0, 1, 20, 40, 600, 1 + 32 + 1088, 1 + 32 + 1088 + 24, sealed.len() - 1] {
            let mut altered = sealed.clone();
            altered[at] ^= 1;
            assert!(open(&secret, &altered).is_none(), "accepted a change at byte {at}");
        }
        assert!(open(&secret, &sealed[..sealed.len() - 1]).is_none());
        assert!(open(&secret, &sealed[..100]).is_none());
        assert!(open(&secret, &[]).is_none());
        assert!(open(&secret[..40], &sealed).is_none());

        assert!(seal(&public[..100], b"x").is_none());
        assert!(seal(&[], b"x").is_none());
        // A public key whose classical half is the all-zero point is refused.
        let mut weak = public.clone();
        weak[..32].fill(0);
        assert!(seal(&weak, b"x").is_none());
        assert!(public_key(&secret[..10]).is_none());
    }

    #[test]
    fn hex_has_one_spelling() {
        assert_eq!(from_hex("00ffA0").unwrap(), [0, 255, 160]);
        for bad in ["+f", "-1", " f", "0x", "f", "zz", "é0"] {
            assert!(from_hex(bad).is_none(), "{bad:?}");
        }
        assert_eq!(from_hex(&to_hex(&[1, 2, 254])).unwrap(), [1, 2, 254]);
    }
}
