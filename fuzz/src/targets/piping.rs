//! The fuzz targets of `pod-piping` (feature `fuzzing`).

use pod_piping::fuzzing::{answer, hello, hello_of, server};
use pod_piping::http1::Framing;

use crate::text;

/// A hello at a node's door (`fuzzing::hello`), or a server's URL as a user
/// names one (`fuzzing::server`): a hello that is read is the one that the
/// key writes for its mode and link; a server that is read prints as a URL
/// that reads back to the same server.
pub fn piping_hello(data: &[u8]) {
    if let Ok((mode, link)) = hello(data) {
        assert_eq!(hello(hello_of(mode, &link).as_bytes()), Ok((mode, link)));
    }
    let Some(url) = text(data) else { return };
    if let Ok(read) = server(url) {
        let shown = read.to_string();
        assert_eq!(server(&shown).as_ref(), Ok(&read), "{shown}");
        assert!(read.prefix.is_empty() || (read.prefix.starts_with('/') && !read.prefix.ends_with('/')), "{shown}");
    }
}

/// An answer of HTTP/1.1 to a client of the carrier
/// (`fuzzing::answer`): a body is never longer than its cap, nor longer
/// than its length.
pub fn piping_answer(data: &[u8]) {
    for cap in [0, 16, 4096] {
        if let Ok((head, body)) = answer(data, cap) {
            assert!(body.len() <= cap, "{} bytes past the cap of {cap}", body.len());
            if let Framing::Length(length) = head.framing {
                assert_eq!(body.len() as u64, length, "a body of a length is whole");
            }
        }
    }
}
