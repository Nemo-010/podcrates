//! The readers of the wire that the fuzz targets of `fuzz/` call (feature
//! `fuzzing`): a hello at the door, an answer of HTTP/1.1 with its body, and
//! a server's URL. No consumer turns it on.

use std::future::Future;
use std::pin::pin;
use std::task::{Context, Poll, Waker};

use crate::http1::{self, Answer, Reader};
use crate::paths::{LinkId, Mode, Secret};
use crate::server::Server;

/// The key of the fuzz targets: a hello of another key fails its tag.
const KEY: [u8; 32] = [7; 32];

/// What the node reads of `data` at its door.
pub fn hello(data: &[u8]) -> Result<(Mode, LinkId), String> {
    Secret::from_bytes(KEY).read_hello(data)
}

/// A hello of the fuzz targets' key, which [`hello`] takes.
pub fn hello_of(mode: Mode, link: &LinkId) -> String {
    Secret::from_bytes(KEY).hello(mode, link)
}

/// The head of the answer in `data`, and its body read whole within `cap`
/// bytes, as a client of the carrier reads them; the reader of a body never
/// waits, as `data` is all there is.
pub fn answer(data: &[u8], cap: usize) -> Result<(Answer, Vec<u8>), String> {
    now(async {
        let mut io = data;
        let mut buf = Vec::new();
        let answer = http1::read_head(&mut io, &mut buf).await?;
        let body = Reader::new(io, buf, answer.framing).all(cap).await?;
        Ok((answer, body))
    })
}

/// The server of a URL, as a user names one.
pub fn server(text: &str) -> Result<Server, String> {
    Server::parse(text)
}

/// The value of `work`, whose reads of a slice are each ready at once.
fn now<T>(work: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    let mut work = pin!(work);
    match work.as_mut().poll(&mut Context::from_waker(Waker::noop())) {
        Poll::Ready(done) => done,
        Poll::Pending => Err("a read of a slice waited".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_hello_an_answer_and_a_url_are_read_with_no_runtime() {
        let link = LinkId([3; 16]);
        assert_eq!(hello(hello_of(Mode::Numbered, &link).as_bytes()), Ok((Mode::Numbered, link)));
        let (head, body) =
            answer(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n3\r\nabc\r\n0\r\n\r\n", 16).unwrap();
        assert_eq!((head.status, body.as_slice()), (200, b"abc".as_slice()));
        assert!(answer(b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\nabc", 16).is_err(), "a body cut short");
        assert!(answer(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\nabc", 2).is_err(), "a body past its cap");
        assert_eq!(server("https://ppng.io").map(|s| s.to_string()), Ok("https://ppng.io".to_string()));
    }
}
