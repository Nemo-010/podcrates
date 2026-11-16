//! The bytes of a TLS handshake that a row reads with no TLS library: a
//! ClientHello of TLS 1.2 (no `supported_versions`, so the server sends
//! its certificates in clear), the records of the server up to its
//! `Certificate`, the issuer and the subject of a certificate (DER), and
//! the certificates of a PEM file. The row checks no signature: it reads
//! which certificate of the file names the issuer of the chain.

use std::io::{ErrorKind, Read};

/// How a handshake ended before the certificates of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum End {
    /// A TCP reset.
    Reset,
    /// The server closed with no record.
    Closed,
    /// No byte in the time limit.
    Silent,
    /// An alert of TLS: its description.
    Alert(u8),
    /// Bytes that are not records of TLS.
    Garbled,
}

impl End {
    pub fn word(self) -> String {
        match self {
            End::Reset => "reset".to_string(),
            End::Closed => "closed".to_string(),
            End::Silent => "silent".to_string(),
            End::Alert(n) => format!("alert-{n}"),
            End::Garbled => "garbled".to_string(),
        }
    }

    /// The end of a read error.
    pub fn of(e: &std::io::Error) -> End {
        match e.kind() {
            ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => End::Reset,
            ErrorKind::WouldBlock | ErrorKind::TimedOut => End::Silent,
            ErrorKind::UnexpectedEof => End::Closed,
            _ => End::Garbled,
        }
    }
}

/// The suites of the ClientHello: ECDHE with AES-GCM and ChaCha20, then
/// the forms of an older server.
const SUITES: [u16; 14] = [
    0xc02b, 0xc02c, 0xc02f, 0xc030, 0xcca9, 0xcca8, 0xc009, 0xc013, 0xc00a, 0xc014, 0x009c, 0x009d, 0x002f, 0x0035,
];
/// x25519, secp256r1, secp384r1.
const GROUPS: [u16; 3] = [0x001d, 0x0017, 0x0018];
/// ECDSA with SHA-256 to SHA-512, RSA-PSS, RSA PKCS #1.
const SIGNATURES: [u16; 9] = [0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806, 0x0401, 0x0501, 0x0601];

fn u16s(v: &[u16]) -> Vec<u8> {
    let mut out = ((v.len() * 2) as u16).to_be_bytes().to_vec();
    v.iter().for_each(|x| out.extend_from_slice(&x.to_be_bytes()));
    out
}

fn extension(out: &mut Vec<u8>, kind: u16, data: &[u8]) {
    out.extend_from_slice(&kind.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// One record of a ClientHello of TLS 1.2, with `name` in its
/// `server_name` where there is one.
pub fn client_hello(name: Option<&str>, random: [u8; 32]) -> Vec<u8> {
    let mut ext = Vec::new();
    if let Some(n) = name {
        let mut entry = vec![0u8];
        entry.extend_from_slice(&(n.len() as u16).to_be_bytes());
        entry.extend_from_slice(n.as_bytes());
        let mut list = (entry.len() as u16).to_be_bytes().to_vec();
        list.extend_from_slice(&entry);
        extension(&mut ext, 0x0000, &list);
    }
    extension(&mut ext, 0x000a, &u16s(&GROUPS));
    extension(&mut ext, 0x000b, &[1, 0]);
    extension(&mut ext, 0x000d, &u16s(&SIGNATURES));
    extension(&mut ext, 0x0017, &[]);
    extension(&mut ext, 0xff01, &[0]);
    let mut body = vec![3, 3];
    body.extend_from_slice(&random);
    body.push(0);
    body.extend_from_slice(&u16s(&SUITES));
    body.extend_from_slice(&[1, 0]);
    body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
    body.extend_from_slice(&ext);
    let mut hs = vec![1];
    hs.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    hs.extend_from_slice(&body);
    let mut record = vec![0x16, 3, 1];
    record.extend_from_slice(&(hs.len() as u16).to_be_bytes());
    record.extend_from_slice(&hs);
    record
}

/// The longest handshake that a row reads.
const HANDSHAKE_MAX: usize = 256 * 1024;

fn read_exact(s: &mut impl Read, buf: &mut [u8]) -> Result<(), End> {
    let mut at = 0;
    while at < buf.len() {
        match s.read(&mut buf[at..]) {
            Ok(0) => return Err(End::Closed),
            Ok(n) => at += n,
            Err(e) if e.kind() == ErrorKind::Interrupted => {}
            Err(e) => return Err(End::of(&e)),
        }
    }
    Ok(())
}

fn u24(b: &[u8]) -> usize {
    usize::from(b[0]) << 16 | usize::from(b[1]) << 8 | usize::from(b[2])
}

/// The certificates of a `Certificate` message body.
fn certificates(body: &[u8]) -> Option<Vec<Vec<u8>>> {
    let total = u24(body.get(..3)?);
    let mut rest = body.get(3..3 + total)?;
    let mut out = Vec::new();
    while !rest.is_empty() {
        let n = u24(rest.get(..3)?);
        out.push(rest.get(3..3 + n)?.to_vec());
        rest = &rest[3 + n..];
    }
    Some(out)
}

/// Read the records of the server up to its `Certificate`: the chain, the
/// leaf first. A `ServerHelloDone` with no `Certificate` gives none.
pub fn server_certificates(s: &mut impl Read) -> Result<Vec<Vec<u8>>, End> {
    let mut hs: Vec<u8> = Vec::new();
    loop {
        let mut head = [0u8; 5];
        read_exact(s, &mut head)?;
        let len = usize::from(u16::from_be_bytes([head[3], head[4]]));
        if head[1] != 3 || len > 1 << 15 {
            return Err(End::Garbled);
        }
        let mut payload = vec![0u8; len];
        read_exact(s, &mut payload)?;
        match head[0] {
            0x15 => return Err(End::Alert(payload.get(1).copied().unwrap_or(0))),
            0x16 => hs.extend_from_slice(&payload),
            _ => return Err(End::Garbled),
        }
        if hs.len() > HANDSHAKE_MAX {
            return Err(End::Garbled);
        }
        // Each whole message of the handshake, in order.
        let mut at = 0;
        while hs.len() >= at + 4 {
            let n = u24(&hs[at + 1..at + 4]);
            let Some(body) = hs.get(at + 4..at + 4 + n) else { break };
            match hs[at] {
                11 => return certificates(body).ok_or(End::Garbled),
                14 => return Ok(Vec::new()),
                _ => at += 4 + n,
            }
        }
    }
}

/// One DER item: its tag, the whole item, its content, and the bytes after
/// it.
fn tlv(b: &[u8]) -> Option<(u8, &[u8], &[u8], &[u8])> {
    let tag = *b.first()?;
    let first = *b.get(1)?;
    let (len, head) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let n = usize::from(first & 0x7f);
        if n == 0 || n > 4 {
            return None;
        }
        let len = b.get(2..2 + n)?.iter().fold(0usize, |a, &x| a << 8 | usize::from(x));
        (len, 2 + n)
    };
    let end = head.checked_add(len)?;
    Some((tag, b.get(..end)?, b.get(head..end)?, b.get(end..)?))
}

/// The issuer and the subject of a certificate, each the whole DER of its
/// `Name`.
pub fn issuer_subject(cert: &[u8]) -> Option<(&[u8], &[u8])> {
    let (_, _, cert, _) = tlv(cert)?;
    let (_, _, tbs, _) = tlv(cert)?;
    let (tag, _, _, mut rest) = tlv(tbs)?;
    if tag == 0xa0 {
        rest = tlv(rest)?.3; // the version came first: this is the serial
    }
    let (_, _, _, rest) = tlv(rest)?; // the algorithm of the signature
    let (_, issuer, _, rest) = tlv(rest)?;
    let (_, _, _, rest) = tlv(rest)?; // the validity
    let (_, subject, _, _) = tlv(rest)?;
    Some((issuer, subject))
}

/// The certificate of `file` (1 for the first) that issued a certificate
/// of `chain`, or that is one, from the leaf up.
pub fn issuer_in(chain: &[Vec<u8>], file: &[Vec<u8>]) -> Option<usize> {
    for c in chain {
        let Some((issuer, _)) = issuer_subject(c) else { continue };
        for (i, f) in file.iter().enumerate() {
            if f == c || issuer_subject(f).is_some_and(|(_, subject)| subject == issuer) {
                return Some(i + 1);
            }
        }
    }
    None
}

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/// Base64 with padding, as `Proxy-Authorization: Basic` takes it.
pub fn base64(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let n = chunk.iter().enumerate().fold(0u32, |a, (i, &b)| a | u32::from(b) << (16 - 8 * i));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ALPHABET[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The bytes of a base64 text; another character than of the alphabet, a
/// space or `=` gives `None`.
fn unbase64(text: &[u8]) -> Option<Vec<u8>> {
    let (mut out, mut acc, mut bits) = (Vec::new(), 0u32, 0);
    for &c in text {
        let v = match c {
            b'=' | b'\n' | b'\r' | b' ' | b'\t' => continue,
            _ => ALPHABET.iter().position(|&a| a == c)? as u32,
        };
        acc = acc << 6 | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    Some(out)
}

/// The DER of each `CERTIFICATE` block of a PEM text.
pub fn pem_certificates(text: &[u8]) -> Vec<Vec<u8>> {
    let text = String::from_utf8_lossy(text);
    let mut out = Vec::new();
    let mut rest = text.as_ref();
    while let Some(start) = rest.find("-----BEGIN CERTIFICATE-----") {
        let body = &rest[start + 27..];
        let Some(end) = body.find("-----END CERTIFICATE-----") else { break };
        if let Some(der) = unbase64(body[..end].as_bytes()) {
            out.push(der);
        }
        rest = &body[end..];
    }
    out
}
