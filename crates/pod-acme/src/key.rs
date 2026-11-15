//! The P-256 keys of ACME: the account's and each certificate's. A key is
//! drawn from the system's entropy (`pod-core`), kept as PKCS #8, and signs
//! with `p256` (pure Rust, deterministic ECDSA of RFC 6979), as the server
//! of `pod-tls` signs with its P-256 key: the pure provider of `pod-tls`
//! loads no private key.

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use pod_core::entropy::{Entropy, OsEntropy};
use zeroize::Zeroizing;

/// The PKCS #8 of a P-256 key with its public point, before the scalar
/// (RFC 5915 inside RFC 5208), as ring and OpenSSL write it.
const PKCS8_HEAD: [u8; 36] = [
    0x30, 0x81, 0x87, 0x02, 0x01, 0x00, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x04, 0x6d, 0x30, 0x6b, 0x02, 0x01, 0x01, 0x04, 0x20,
];
/// Between the scalar and the uncompressed point.
const PKCS8_POINT: [u8; 5] = [0xa1, 0x44, 0x03, 0x42, 0x00];
/// The bytes of an uncompressed P-256 point: 0x04, then x and y.
pub const POINT: usize = 65;
/// Draws of a scalar before the source is taken as broken: a draw of 32
/// bytes is no valid scalar about once in 2^32 draws.
const DRAWS: usize = 8;

/// A P-256 key: its PKCS #8, its signing half, and its public point.
pub struct Key {
    pkcs8: Zeroizing<Vec<u8>>,
    secret: SigningKey,
    /// The uncompressed point, as a SubjectPublicKeyInfo holds it.
    public: Vec<u8>,
}

impl Key {
    /// A new key, from the system's source of randomness.
    pub fn generate() -> Result<Key, String> {
        let mut scalar = Zeroizing::new([0u8; 32]);
        for _ in 0..DRAWS {
            OsEntropy.fill(&mut scalar[..]).map_err(|e| format!("no P-256 key could be made: {e}"))?;
            let Ok(secret) = SigningKey::from_slice(&scalar[..]) else { continue };
            let point = secret.verifying_key().to_sec1_point(false);
            let mut der = Zeroizing::new(Vec::with_capacity(PKCS8_HEAD.len() + 32 + PKCS8_POINT.len() + POINT));
            der.extend_from_slice(&PKCS8_HEAD);
            der.extend_from_slice(&scalar[..]);
            der.extend_from_slice(&PKCS8_POINT);
            der.extend_from_slice(point.as_bytes());
            return Key::from_pkcs8(&der);
        }
        Err("no P-256 key could be made: the system's random bytes gave no valid scalar".into())
    }

    /// The key of `der`, a P-256 key in PKCS #8, read as the server of
    /// `pod-tls` reads a key.
    pub fn from_pkcs8(der: &[u8]) -> Result<Key, String> {
        let pem = Zeroizing::new(crate::certs::pem("PRIVATE KEY", der));
        let secret =
            pod_tls::server::signing_key(pem.as_bytes()).map_err(|why| format!("not a P-256 key in PKCS #8: {why}"))?;
        let public = secret.verifying_key().to_sec1_point(false).as_bytes().to_vec();
        Ok(Key { pkcs8: Zeroizing::new(der.to_vec()), secret, public })
    }

    /// The key as PKCS #8.
    pub fn pkcs8(&self) -> &[u8] {
        &self.pkcs8
    }

    /// The uncompressed public point: 0x04, then x and y of 32 bytes each.
    pub fn public(&self) -> &[u8] {
        &self.public
    }

    /// The key as PEM (`PRIVATE KEY`), as the files of a server's key hold
    /// one.
    pub fn pem(&self) -> Zeroizing<String> {
        Zeroizing::new(crate::certs::pem("PRIVATE KEY", &self.pkcs8))
    }

    /// ECDSA with SHA-256 over `message`, in DER, as X.509 and PKCS #10
    /// carry it.
    pub fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let signature: Signature = self.secret.sign(message);
        signature.to_der().as_bytes().to_vec()
    }

    /// ECDSA with SHA-256 over `message`, r and s of 32 bytes each, as JWS
    /// carries it (RFC 7518, section 3.4).
    pub fn sign_fixed(&self, message: &[u8]) -> [u8; 64] {
        let signature: Signature = self.secret.sign(message);
        let mut fixed = [0u8; 64];
        fixed.copy_from_slice(&signature.to_bytes()[..]);
        fixed
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The private half never goes into a line.
        f.debug_struct("Key").field("public", &self.public).finish_non_exhaustive()
    }
}

impl rcgen::PublicKeyData for Key {
    fn der_bytes(&self) -> &[u8] {
        &self.public
    }

    fn algorithm(&self) -> &'static rcgen::SignatureAlgorithm {
        &rcgen::PKCS_ECDSA_P256_SHA256
    }
}

impl rcgen::SigningKey for Key {
    /// ECDSA with SHA-256, in DER, as X.509 and PKCS #10 carry it.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        Ok(self.sign_der(message))
    }
}

#[cfg(test)]
mod tests {
    use p256::ecdsa::signature::Verifier as _;

    use super::*;

    #[test]
    fn a_key_is_drawn_written_as_pkcs8_and_signs_in_both_forms() {
        let key = Key::generate().unwrap();
        let again = Key::from_pkcs8(key.pkcs8()).expect("its PKCS #8 loads again");
        assert_eq!(again.public(), key.public());
        let verifying = p256::ecdsa::VerifyingKey::from_sec1_bytes(key.public()).expect("a P-256 point");
        let signature = Signature::from_der(&key.sign_der(b"message")).expect("DER");
        assert!(verifying.verify(b"message", &signature).is_ok());
        let signature = Signature::from_slice(&key.sign_fixed(b"message")).expect("r and s");
        assert!(verifying.verify(b"message", &signature).is_ok());
        assert!(verifying.verify(b"another", &signature).is_err());
        assert_ne!(Key::generate().unwrap().public(), key.public(), "each key is drawn anew");
        assert!(!format!("{key:?}").contains("secret"));
    }

    /// A key that ring wrote (`EcdsaKeyPair::generate_pkcs8`, the form of
    /// the keys that podssh kept) is read, and its point is the one that
    /// ring gives.
    #[test]
    fn a_key_that_ring_wrote_is_read_with_its_point() {
        use ring::signature::KeyPair as _;
        let rng = ring::rand::SystemRandom::new();
        let alg = &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING;
        let document = ring::signature::EcdsaKeyPair::generate_pkcs8(alg, &rng).unwrap();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(alg, document.as_ref(), &rng).unwrap();
        let key = Key::from_pkcs8(document.as_ref()).expect("ring's PKCS #8");
        assert_eq!(key.public(), pair.public_key().as_ref());
        // And ring reads a key of this crate.
        let ours = Key::generate().unwrap();
        assert!(ring::signature::EcdsaKeyPair::from_pkcs8(alg, ours.pkcs8(), &rng).is_ok());
    }

    #[test]
    fn no_key_and_a_key_of_another_curve_are_refused() {
        assert!(Key::from_pkcs8(b"no key").is_err());
        // An Ed25519 key of RFC 8410, section 10.3.
        let ed25519 = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, 0xd4, 0xee,
            0x72, 0xdb, 0xf9, 0x13, 0x58, 0x4a, 0xd5, 0xb6, 0xd8, 0xf1, 0xf7, 0x69, 0xf8, 0xad, 0x3a, 0xfe, 0x7c, 0x28,
            0xcb, 0xf1, 0xd4, 0xfb, 0xe0, 0x97, 0xa8, 0x8f, 0x44, 0x75, 0x58, 0x42,
        ];
        assert!(Key::from_pkcs8(&ed25519).is_err());
    }
}
