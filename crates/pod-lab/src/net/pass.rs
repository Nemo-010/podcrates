//! The messages between the stand-in proxy and the way out: one datagram
//! of text on a socket pair of `AF_UNIX` and `SOCK_SEQPACKET`, with at most
//! one descriptor beside it (`SCM_RIGHTS`). A socket pair is no address of
//! a network namespace: the stand-in inside the lab and the process of the
//! way out outside it share it.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::time::Duration;

use linux_raw_sys::cmsg_macros::{CMSG_DATA, CMSG_FIRSTHDR, CMSG_LEN, CMSG_SPACE};
use linux_raw_sys::general::{__NR_recvmsg, __NR_sendmsg, __NR_socketpair};
use linux_raw_sys::general::iovec;
use linux_raw_sys::net::{MSG_CMSG_CLOEXEC, MSG_NOSIGNAL, SCM_RIGHTS, SOCK_SEQPACKET, SOL_SOCKET, cmsghdr, msghdr};
use pod_hostprobe::sys::{self as k, Errno};

/// The longest message: a host name, a port and a reason.
pub const MESSAGE_MAX: usize = 1024;

/// The control buffer of one descriptor, aligned for `cmsghdr`.
#[repr(C, align(8))]
struct Control([u8; 32]);

/// A new socket pair, close-on-exec.
pub fn pair() -> Result<(OwnedFd, OwnedFd), Errno> {
    let mut fds = [0i32; 2];
    // SAFETY: the kernel writes two descriptors into the live array.
    unsafe {
        k::sys(
            __NR_socketpair as i64,
            [k::AF_UNIX, u64::from(SOCK_SEQPACKET) | k::SOCK_CLOEXEC, 0, fds.as_mut_ptr() as u64, 0, 0],
        )
    }?;
    // SAFETY: the two descriptors are new, and nothing else owns them.
    Ok(unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) })
}

fn header(iov: &mut iovec, control: &mut Control, with_fd: bool) -> msghdr {
    msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        // The two structs of `iovec` of linux-raw-sys are one layout.
        msg_iov: (iov as *mut iovec).cast(),
        msg_iovlen: 1,
        msg_control: if with_fd { control.0.as_mut_ptr().cast() } else { std::ptr::null_mut() },
        // SAFETY: a computation on a constant.
        msg_controllen: if with_fd { (unsafe { CMSG_SPACE(4) }) as _ } else { 0 },
        msg_flags: 0,
    }
}

/// Send `text`, and `fd` beside it where there is one.
pub fn send(sock: &OwnedFd, text: &str, fd: Option<&OwnedFd>) -> Result<(), Errno> {
    let mut iov = iovec { iov_base: text.as_ptr() as *mut _, iov_len: text.len() as _ };
    let mut control = Control([0; 32]);
    let msg = header(&mut iov, &mut control, fd.is_some());
    if let Some(fd) = fd {
        // SAFETY: `msg` points to `control`, which holds one header and
        // the room of one descriptor.
        unsafe {
            let c: *mut cmsghdr = CMSG_FIRSTHDR(&msg);
            (*c).cmsg_len = CMSG_LEN(4) as _;
            (*c).cmsg_level = SOL_SOCKET as _;
            (*c).cmsg_type = SCM_RIGHTS as _;
            CMSG_DATA(c).cast::<i32>().write_unaligned(fd.as_raw_fd());
        }
    }
    loop {
        // SAFETY: `msg` and each buffer that it points to are live.
        let r = unsafe {
            k::sys(__NR_sendmsg as i64, [sock.as_raw_fd() as u64, &msg as *const msghdr as u64, MSG_NOSIGNAL as u64, 0, 0, 0])
        };
        match r {
            Err(e) if e == k::EINTR => continue,
            r => return r.map(|_| ()),
        }
    }
}

/// Receive one message: its text, and the descriptor beside it. An empty
/// text is the end: each peer has closed.
pub fn recv(sock: &OwnedFd) -> Result<(String, Option<OwnedFd>), Errno> {
    let mut buf = [0u8; MESSAGE_MAX];
    let mut iov = iovec { iov_base: buf.as_mut_ptr().cast(), iov_len: buf.len() as _ };
    let mut control = Control([0; 32]);
    let mut msg = header(&mut iov, &mut control, true);
    let n = loop {
        // SAFETY: `msg` and each buffer that it points to are live.
        let r = unsafe {
            k::sys(
                __NR_recvmsg as i64,
                [sock.as_raw_fd() as u64, &mut msg as *mut msghdr as u64, MSG_CMSG_CLOEXEC as u64, 0, 0, 0],
            )
        };
        match r {
            Err(e) if e == k::EINTR => continue,
            r => break r? as usize,
        }
    };
    let mut fd = None;
    // SAFETY: the kernel set `msg_controllen` to the bytes that it wrote
    // into `control`; one header of `SCM_RIGHTS` holds one descriptor.
    unsafe {
        let c: *mut cmsghdr = CMSG_FIRSTHDR(&msg);
        if !c.is_null()
            && (*c).cmsg_level == SOL_SOCKET as i32
            && (*c).cmsg_type == SCM_RIGHTS as i32
            && (*c).cmsg_len as usize >= CMSG_LEN(4) as usize
        {
            fd = Some(OwnedFd::from_raw_fd(CMSG_DATA(c).cast::<i32>().read_unaligned()));
        }
    }
    Ok((String::from_utf8_lossy(&buf[..n.min(buf.len())]).into_owned(), fd))
}

/// The time limit of each receive on `sock`.
pub fn recv_limit(sock: OwnedFd, limit: Duration) -> std::io::Result<OwnedFd> {
    let d = std::os::unix::net::UnixDatagram::from(sock);
    d.set_read_timeout(Some(limit))?;
    Ok(d.into())
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    /// A text and a descriptor cross the pair; the descriptor is the same
    /// open file.
    #[test]
    fn a_message_carries_its_text_and_a_descriptor() {
        let (a, b) = super::pair().unwrap();
        let (mut r, w) = std::io::pipe().unwrap();
        super::send(&a, "listed.test\t443", Some(&std::os::fd::OwnedFd::from(w))).unwrap();
        let (text, fd) = super::recv(&b).unwrap();
        assert_eq!(text, "listed.test\t443");
        let mut w = std::fs::File::from(fd.expect("a descriptor"));
        w.write_all(b"through").unwrap();
        drop(w);
        let mut got = String::new();
        r.read_to_string(&mut got).unwrap();
        assert_eq!(got, "through");
        super::send(&a, "no descriptor", None).unwrap();
        let (text, fd) = super::recv(&b).unwrap();
        assert_eq!((text.as_str(), fd.is_none()), ("no descriptor", true));
        drop(a);
        assert_eq!(super::recv(&b).unwrap().0, "", "the end of each peer");
    }
}
