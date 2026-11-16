//! The TLS of the stand-ins: two certificate authorities of the lab, made
//! for each run, the leaf of each name, and the configurations of a server
//! and of a client on the pure-Rust provider of `pod-tls` (no C). rcgen
//! writes the DER with no crypto of its own: each signature is a P-256 key
//! of `p256` from the random bytes of the kernel.

use std::sync::Arc;

use p256::ecdsa::signature::Signer as _;
use p256::ecdsa::{Signature, SigningKey};
use rustls_pki_types::{CertificateDer, ServerName};

use super::Ca;

/// A P-256 key, with its public point as a SubjectPublicKeyInfo holds it.
pub struct Key {
    secret: SigningKey,
    public: Vec<u8>,
}

impl Key {
    /// A new key from `getrandom(2)`.
    pub fn generate() -> Result<Key, String> {
        for _ in 0..8 {
            let mut scalar = [0u8; 32];
            pod_hostprobe::sys::getrandom(&mut scalar).map_err(|e| format!("getrandom: {}", e.name()))?;
            let made = SigningKey::from_slice(&scalar);
            scalar.fill(0);
            // A draw of 32 bytes is no valid scalar about once in 2^32.
            let Ok(secret) = made else { continue };
            let public = secret.verifying_key().to_sec1_point(false).as_bytes().to_vec();
            return Ok(Key { secret, public });
        }
        Err("the random bytes gave no P-256 key".to_string())
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
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rcgen::Error> {
        let signature: Signature = self.secret.sign(message);
        Ok(signature.to_der().as_bytes().to_vec())
    }
}

/// A random serial number: with no crypto feature, rcgen draws none.
fn serial() -> Result<rcgen::SerialNumber, String> {
    let mut bytes = [0u8; 16];
    pod_hostprobe::sys::getrandom(&mut bytes).map_err(|e| format!("getrandom: {}", e.name()))?;
    bytes[0] &= 0x7f;
    Ok(rcgen::SerialNumber::from_slice(&bytes))
}

/// One certificate authority of the lab: its key, its parameters and its
/// certificate.
pub struct Authority {
    key: Key,
    params: rcgen::CertificateParams,
    pub der: CertificateDer<'static>,
}

impl Authority {
    fn new(name: &str) -> Result<Authority, String> {
        let key = Key::generate()?;
        let mut params = rcgen::CertificateParams::default();
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, name);
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.key_usages = vec![rcgen::KeyUsagePurpose::KeyCertSign, rcgen::KeyUsagePurpose::DigitalSignature];
        params.serial_number = Some(serial()?);
        let cert = params.self_signed(&key).map_err(|e| format!("the certificate of {name}: {e}"))?;
        Ok(Authority { key, params, der: cert.der().clone() })
    }

    /// The certificate as PEM.
    pub fn pem(&self) -> String {
        pem("CERTIFICATE", &self.der)
    }
}

/// The two authorities of a lab and the key of each leaf.
pub struct Cas {
    pub proxy: Authority,
    pub server: Authority,
    leaf: Key,
}

impl Cas {
    pub fn new() -> Result<Cas, String> {
        Ok(Cas {
            proxy: Authority::new("pod-lab proxy CA")?,
            server: Authority::new("pod-lab server CA")?,
            leaf: Key::generate()?,
        })
    }

    pub fn of(&self, ca: Ca) -> &Authority {
        match ca {
            Ca::Proxy => &self.proxy,
            Ca::Server => &self.server,
        }
    }

    /// A leaf for `name` (a DNS name or an IP address) that `ca` signs.
    fn leaf(&self, name: &str, ca: Ca) -> Result<CertificateDer<'static>, String> {
        let mut params = rcgen::CertificateParams::new(vec![name.to_string()]).map_err(|e| format!("{name}: {e}"))?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params.distinguished_name.push(rcgen::DnType::CommonName, name);
        params.serial_number = Some(serial()?);
        let by = self.of(ca);
        let issuer = rcgen::Issuer::from_params(&by.params, &by.key);
        let cert = params.signed_by(&self.leaf, &issuer).map_err(|e| format!("the leaf of {name}: {e}"))?;
        Ok(cert.der().clone())
    }

    /// The configuration of a TLS server that shows the leaf of `name`,
    /// signed by `ca`.
    pub fn server(&self, name: &str, ca: Ca) -> Result<Arc<rustls::ServerConfig>, String> {
        let chain = vec![self.leaf(name, ca)?];
        let pair = pod_tls::server::certified_key(chain, self.leaf.secret.clone()).map_err(|e| e.to_string())?;
        pod_tls::server::server_config_for(provider(), pod_tls::server::Served::new(Some(pair)), &[])
            .map_err(|e| e.to_string())
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(pod_tls::crypto::provider())
}

/// `der` as a PEM block of `label`.
pub fn pem(label: &str, der: &[u8]) -> String {
    use base64::Engine as _;
    let text = base64::engine::general_purpose::STANDARD.encode(der);
    let mut out = format!("-----BEGIN {label}-----\n");
    for line in text.as_bytes().chunks(64) {
        out.push_str(&String::from_utf8_lossy(line));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// A TLS client that trusts `roots` alone, with no name in its ClientHello
/// where `sni` is false.
pub fn client(roots: &[CertificateDer<'static>], sni: bool) -> Result<Arc<rustls::ClientConfig>, String> {
    let mut store = rustls::RootCertStore::empty();
    for r in roots {
        store.add(r.clone()).map_err(|e| format!("a root of the lab: {e}"))?;
    }
    let mut config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .map_err(|e| e.to_string())?
        .with_root_certificates(store)
        .with_no_client_auth();
    config.enable_sni = sni;
    Ok(Arc::new(config))
}

/// The name of a server for a client: a DNS name or an IP address.
pub fn server_name(name: &str) -> Result<ServerName<'static>, String> {
    ServerName::try_from(name.to_string()).map_err(|e| format!("{name}: {e}"))
}
