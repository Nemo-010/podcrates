//! The wire of the split on each half: the hello of the dialer, then
//! frames of a type (1 byte) and a length (4 bytes, big endian).

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The first bytes of a half: `PODSPLIT`, the version, the half, the
/// session.
pub const MAGIC: &[u8; 8] = b"PODSPLIT";
pub const VERSION: u8 = 1;
pub const HELLO: usize = 8 + 1 + 1 + 16;

/// The most bytes of the body of one frame of data.
pub const FRAME: usize = 64 << 10;

/// The head of a frame: its type and the length of its body.
pub const HEAD: usize = 5;

/// The types of a frame.
pub mod kind {
    /// Bytes of the link: on the main direction of a half.
    pub const DATA: u8 = 1;
    /// A sign of life, with no body: on each direction that is idle.
    pub const BEAT: u8 = 2;
    /// The end of the bytes of the link of the sender.
    pub const END: u8 = 3;
    /// The listener joined the two halves: the first frame down.
    pub const JOINED: u8 = 4;
    /// The sender lost a half (the body: 1 up, 2 down), on the other half.
    pub const LOST: u8 = 5;
}

/// The byte of a half in a hello and in `LOST`: 1 up, 2 down.
pub fn half_byte(up: bool) -> u8 {
    if up { 1 } else { 2 }
}

fn bad(text: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, text.into())
}

/// The hello of a half: up or down, and the session.
pub fn hello(up: bool, session: &[u8; 16]) -> [u8; HELLO] {
    let mut out = [0u8; HELLO];
    out[..8].copy_from_slice(MAGIC);
    out[8] = VERSION;
    out[9] = half_byte(up);
    out[10..].copy_from_slice(session);
    out
}

/// Read a hello: the half (true for up) and the session.
pub async fn read_hello<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<(bool, [u8; 16])> {
    let mut got = [0u8; HELLO];
    r.read_exact(&mut got).await?;
    if &got[..8] != MAGIC || got[8] != VERSION || !matches!(got[9], 1 | 2) {
        return Err(bad("no hello of a split of version 1"));
    }
    let mut session = [0u8; 16];
    session.copy_from_slice(&got[10..]);
    Ok((got[9] == 1, session))
}

/// Write one frame and flush it.
pub async fn write<W: AsyncWrite + Unpin>(w: &mut W, kind: u8, body: &[u8]) -> io::Result<()> {
    let mut out = Vec::with_capacity(HEAD + body.len());
    out.push(kind);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes());
    out.extend_from_slice(body);
    w.write_all(&out).await?;
    w.flush().await
}

/// Read one frame: none at an end of the carrier before its first byte.
/// A frame of data is 1 byte to [`FRAME`]; each other frame has no body.
pub async fn read<R: AsyncRead + Unpin>(r: &mut R) -> io::Result<Option<(u8, Vec<u8>)>> {
    let mut head = [0u8; HEAD];
    let first = r.read(&mut head[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    r.read_exact(&mut head[1..]).await?;
    let len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]) as usize;
    let fits = match head[0] {
        kind::DATA => (1..=FRAME).contains(&len),
        kind::BEAT | kind::END | kind::JOINED => len == 0,
        kind::LOST => len == 1,
        other => return Err(bad(format!("a frame of the unknown type {other}"))),
    };
    if !fits {
        return Err(bad(format!("a frame of type {} with a body of {len} bytes", head[0])));
    }
    let mut body = vec![0u8; len];
    r.read_exact(&mut body).await?;
    Ok(Some((head[0], body)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_hello_and_the_frames_read_back_and_a_bad_frame_is_refused() {
        let session = [7u8; 16];
        let (mut a, mut b) = tokio::io::duplex(1 << 20);
        a.write_all(&hello(false, &session)).await.unwrap();
        write(&mut a, kind::DATA, b"bytes").await.unwrap();
        write(&mut a, kind::BEAT, &[]).await.unwrap();
        assert_eq!(read_hello(&mut b).await.unwrap(), (false, session));
        assert_eq!(read(&mut b).await.unwrap(), Some((kind::DATA, b"bytes".to_vec())));
        assert_eq!(read(&mut b).await.unwrap(), Some((kind::BEAT, Vec::new())));
        for bad in [vec![9, 0, 0, 0, 0], vec![kind::BEAT, 0, 0, 0, 1, 0], vec![kind::DATA, 0, 0, 0, 0]] {
            let (mut a, mut b) = tokio::io::duplex(64);
            a.write_all(&bad).await.unwrap();
            assert_eq!(read(&mut b).await.unwrap_err().kind(), io::ErrorKind::InvalidData, "{bad:?}");
        }
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(b"PODSPLIT\x02\x01").await.unwrap();
        a.write_all(&[0; 16]).await.unwrap();
        assert!(read_hello(&mut b).await.is_err(), "another version");
        drop(a);
        assert_eq!(read(&mut b).await.unwrap(), None, "the end of the carrier");
    }
}
