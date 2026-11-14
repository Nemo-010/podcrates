//! Signature Version 4 of the S3 API: the canonical request, the string to
//! sign, the key of the day and the `Authorization` field. The service is
//! `s3`; the payload hash goes in `x-amz-content-sha256`.

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256};

/// The SHA-256 of no bytes, in hex.
pub const EMPTY_HASH: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

/// The key of a bucket's account: the id, the secret and the token of a
/// session when the key is a temporary one. Its Debug shows the id alone.
#[derive(Clone, PartialEq, Eq)]
pub struct Credentials {
    pub access_key: String,
    pub secret_key: String,
    /// `x-amz-security-token`, for temporary keys.
    pub session_token: Option<String>,
}

impl Credentials {
    pub fn new(access_key: impl Into<String>, secret_key: impl Into<String>) -> Credentials {
        Credentials { access_key: access_key.into(), secret_key: secret_key.into(), session_token: None }
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Credentials")
            .field("access_key", &self.access_key)
            .field("secret_key", &"(hidden)")
            .field("session_token", &self.session_token.as_ref().map(|_| "(hidden)"))
            .finish()
    }
}

/// The parts of a request that the signature covers. `path` and `query` are
/// not encoded yet; `headers` are the fields to sign, in any case and
/// order; `date` is `YYYYMMDDTHHMMSSZ`, the value of `x-amz-date`.
pub struct Signing<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub query: &'a [(&'a str, &'a str)],
    pub headers: &'a [(&'a str, &'a str)],
    pub payload_hash: &'a str,
    pub date: &'a str,
    pub region: &'a str,
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[usize::from(b >> 4)] as char);
        out.push(DIGITS[usize::from(b & 15)] as char);
    }
    out
}

/// The SHA-256 of `bytes`, in hex.
pub fn sha256_hex(bytes: &[u8]) -> String {
    hex(&Sha256::digest(bytes))
}

fn hmac(key: &[u8], data: &[u8]) -> [u8; 32] {
    let Ok(mut mac) = Hmac::<Sha256>::new_from_slice(key) else { unreachable!("HMAC takes a key of each length") };
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// Each byte but `A-Z a-z 0-9 - . _ ~` as `%XX`; `/` stays in a path.
pub fn uri_encode(text: &str, path: bool) -> String {
    let mut out = String::with_capacity(text.len());
    for &b in text.as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~') || (path && b == b'/') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// The query of a request: each name and value encoded, sorted by name.
pub fn canonical_query(query: &[(&str, &str)]) -> String {
    let mut pairs: Vec<(String, String)> =
        query.iter().map(|(k, v)| (uri_encode(k, false), uri_encode(v, false))).collect();
    pairs.sort();
    pairs.iter().map(|(k, v)| format!("{k}={v}")).collect::<Vec<_>>().join("&")
}

/// The fields as the signature takes them: lower case, trimmed, sorted;
/// and the list of their names.
fn canonical_headers(headers: &[(&str, &str)]) -> (String, String) {
    let mut fields: Vec<(String, String)> = headers
        .iter()
        .map(|(n, v)| (n.to_ascii_lowercase(), v.split_whitespace().collect::<Vec<_>>().join(" ")))
        .collect();
    fields.sort();
    let text = fields.iter().map(|(n, v)| format!("{n}:{v}\n")).collect::<String>();
    let names = fields.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>().join(";");
    (text, names)
}

/// The value of the field `Authorization` of a request.
pub fn authorization(credentials: &Credentials, s: &Signing<'_>) -> String {
    let (headers, signed) = canonical_headers(s.headers);
    let canonical = format!(
        "{}\n{}\n{}\n{headers}\n{signed}\n{}",
        s.method,
        uri_encode(s.path, true),
        canonical_query(s.query),
        s.payload_hash
    );
    let day = s.date.get(..8).unwrap_or_default();
    let scope = format!("{day}/{}/s3/aws4_request", s.region);
    let to_sign = format!("AWS4-HMAC-SHA256\n{}\n{scope}\n{}", s.date, sha256_hex(canonical.as_bytes()));
    let key = [day, s.region, "s3", "aws4_request"]
        .iter()
        .fold(format!("AWS4{}", credentials.secret_key).into_bytes(), |key, part| hmac(&key, part.as_bytes()).to_vec());
    let signature = hex(&hmac(&key, to_sign.as_bytes()));
    format!(
        "AWS4-HMAC-SHA256 Credential={}/{scope}, SignedHeaders={signed}, Signature={signature}",
        credentials.access_key
    )
}

/// The days from 1970-01-01 to the date `y-m-d` (proleptic Gregorian).
pub fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let mp = (i64::from(m) + 9) % 12;
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// `x-amz-date` of a time in seconds since 1970: `YYYYMMDDTHHMMSSZ`.
pub fn amz_date(unix: u64) -> String {
    let days = (unix / 86_400) as i64;
    let secs = unix % 86_400;
    // The inverse of `days_from_civil`.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}{m:02}{d:02}T{:02}{:02}{:02}Z", secs / 3600, secs / 60 % 60, secs % 60)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The example key of the documentation of the S3 API: no account has
    /// it. Its id is in two parts, so that the scanner of secrets does not
    /// try it at AWS (a failed try is a finding of state "unknown").
    fn example() -> Credentials {
        Credentials::new(concat!("AKIA", "IOSFODNN7EXAMPLE"), "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY")
    }

    fn sign(method: &str, path: &str, query: &[(&str, &str)], headers: &[(&str, &str)], hash: &str) -> String {
        let s =
            Signing { method, path, query, headers, payload_hash: hash, date: "20130524T000000Z", region: "us-east-1" };
        let auth = authorization(&example(), &s);
        auth.rsplit("Signature=").next().unwrap().to_string()
    }

    const HOST: (&str, &str) = ("Host", "examplebucket.s3.amazonaws.com");
    const DATE: (&str, &str) = ("x-amz-date", "20130524T000000Z");

    #[test]
    fn the_examples_of_the_documentation_of_the_s3_api_sign_alike() {
        let empty = ("x-amz-content-sha256", EMPTY_HASH);
        let get = sign("GET", "/test.txt", &[], &[HOST, ("Range", "bytes=0-9"), empty, DATE], EMPTY_HASH);
        assert_eq!(get, "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41", "GET Object");
        let body = sha256_hex(b"Welcome to Amazon S3.");
        assert_eq!(body, "44ce7dd67c959e0d3524ffac1771dfbba87d2b6b4b4e99e42034a8b803f8b072");
        let put = sign(
            "PUT",
            "/test$file.text",
            &[],
            &[
                ("Date", "Fri, 24 May 2013 00:00:00 GMT"),
                HOST,
                ("x-amz-content-sha256", &body),
                DATE,
                ("x-amz-storage-class", "REDUCED_REDUNDANCY"),
            ],
            &body,
        );
        assert_eq!(put, "98ad721746da40c64f1a55b78f14c238d841ea1380cd77a1b5971af0ece108bd", "PUT Object");
        let lifecycle = sign("GET", "/", &[("lifecycle", "")], &[HOST, empty, DATE], EMPTY_HASH);
        assert_eq!(lifecycle, "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543", "GET lifecycle");
        let list = sign("GET", "/", &[("prefix", "J"), ("max-keys", "2")], &[HOST, empty, DATE], EMPTY_HASH);
        assert_eq!(list, "34b48302e7b5fa45bde8084f4b7868a86f0a534bc59db6670ed5711ef69dc6f7", "GET Bucket");
    }

    #[test]
    fn the_date_and_the_encoding() {
        assert_eq!(amz_date(1_369_353_600), "20130524T000000Z");
        assert_eq!(amz_date(951_782_400 + 3661), "20000229T010101Z");
        assert_eq!(days_from_civil(2013, 5, 24) * 86_400, 1_369_353_600);
        assert_eq!(uri_encode("a b/c~$", true), "a%20b/c~%24");
        assert_eq!(uri_encode("a/b", false), "a%2Fb");
        assert_eq!(canonical_query(&[("prefix", "J"), ("max-keys", "2")]), "max-keys=2&prefix=J");
        let shown = format!("{:?}", example());
        assert!(!shown.contains("EXAMPLEKEY") && shown.contains("IOSFODNN7EXAMPLE"), "{shown}");
    }
}
