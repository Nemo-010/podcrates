//! The fuzz targets of `pod-opentunnel` (feature `fuzzing`).

use pod_opentunnel::fuzzing::{cert, frame, message, name, service, tunnel};

use crate::text;

/// A message of the bridge (`fuzzing::message`) or a data frame
/// (`fuzzing::frame`): a frame is its connection's id and the rest of the
/// bytes; a message that is read is read the same a second time.
pub fn opentunnel_message(data: &[u8]) {
    if let Some((conn, payload)) = frame(data) {
        assert_eq!(&data[..4], &conn.to_be_bytes());
        assert_eq!(payload, &data[4..]);
    }
    let Some(text) = text(data) else { return };
    if let Ok(read) = message(text) {
        assert_eq!(message(text), Ok(read));
    }
}

/// An answer of the API (`fuzzing::tunnel`, `fuzzing::cert`), a service's
/// URL (`fuzzing::service`) or a node's name (`fuzzing::name`): a tunnel's
/// name is its id under a domain; a service and a name that are read print
/// as text that reads back to the same.
pub fn opentunnel_answer(data: &[u8]) {
    let Some(text) = text(data) else { return };
    if let Ok(read) = tunnel(text) {
        assert!(read.hostname.starts_with(&format!("{}.", read.id)), "{read:?}");
    }
    let _ = cert(text);
    if let Ok(read) = service(text) {
        assert_eq!(service(&read.to_string()).as_ref(), Ok(&read), "{read}");
    }
    if let Ok(read) = name(text) {
        assert_eq!(name(&read.to_string()).as_ref(), Ok(&read), "{read}");
    }
}
