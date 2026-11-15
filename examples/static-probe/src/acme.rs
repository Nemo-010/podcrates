//! pod-acme: a key, the CSR of a name and the certificate of a challenge,
//! read back as a leaf, so that the keys of p256, rcgen and x509-parser
//! link in.

pub fn acme() -> String {
    let made = pod_acme::certs::Key::generate().and_then(|key| {
        let csr = pod_acme::certs::csr("probe.example", &key)?;
        let (cert, _) = pod_acme::certs::challenge("probe.example", "token.thumbprint", 1_793_620_800)?;
        let der = pod_acme::certs::pem_block(&cert, "CERTIFICATE").ok_or("no certificate")?;
        let leaf = pod_acme::certs::leaf(&der)?;
        Ok(format!("a CSR of {} bytes, a challenge {}", csr.len(), pod_acme::about(&leaf)))
    });
    format!("pod-acme: {}", made.unwrap_or_else(|e| e))
}
