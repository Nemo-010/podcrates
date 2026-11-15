//! What a Close of IAP's relay means. Its codes extend RFC 6455's,
//! as IAP Desktop names them (`SshRelayCloseCode` in
//! `Google.Solutions.Iap/Protocol/SshRelayConstants.cs`) and gcloud reads
//! them (`iap_tunnel_websocket.py`, `iap_tunnel_websocket_helper.py`).

use pod_core::{Class, Stage};

/// What the session does after a Close of the server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fate {
    /// The far end of the stream closed: the session's own end (1000, and
    /// 4009 and 4010, the backend's write and read that failed).
    End,
    /// The token is too old (4004): a new link with a new token takes the
    /// session up, as gcloud takes it up.
    Reauthenticate,
    /// The link went, not the session: a new link may take it up, as IAP
    /// Desktop tries again on a code that it does not know.
    Resume,
    /// The session cannot go on.
    Fail(Why),
}

/// Why a Close ends the session for good.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Why {
    /// IAP refused the account (4033).
    NotAuthorized,
    /// IAP could not connect to the port of the VM (4003).
    Backend,
    /// IAP found no such VM (4047, 4051).
    Lookup,
    /// The server forgot the session, or another link holds it (4001, 4002,
    /// 4074): no reconnect can take it up.
    Lost,
    /// A fault of the protocol: an acknowledgement, an opcode, a tag or data
    /// that the server refused (4005 to 4008, 4013).
    Protocol,
}

pub const NORMAL: u16 = 1000;
pub const SID_UNKNOWN: u16 = 4001;
pub const SID_IN_USE: u16 = 4002;
pub const FAILED_TO_CONNECT_TO_BACKEND: u16 = 4003;
pub const REAUTHENTICATION_REQUIRED: u16 = 4004;
pub const DESTINATION_WRITE_FAILED: u16 = 4009;
pub const DESTINATION_READ_FAILED: u16 = 4010;
pub const INVALID_DATA: u16 = 4013;
pub const NOT_AUTHORIZED: u16 = 4033;
pub const LOOKUP_FAILED: u16 = 4047;
pub const LOOKUP_FAILED_RECONNECT: u16 = 4051;
pub const FAILED_TO_REWIND: u16 = 4074;

/// The fate of a session after a Close with `code`; a Close with no code,
/// and a code that no table names, is a lost link.
pub fn fate(code: Option<u16>) -> Fate {
    match code {
        Some(NORMAL | DESTINATION_WRITE_FAILED | DESTINATION_READ_FAILED) => Fate::End,
        Some(REAUTHENTICATION_REQUIRED) => Fate::Reauthenticate,
        Some(NOT_AUTHORIZED) => Fate::Fail(Why::NotAuthorized),
        Some(FAILED_TO_CONNECT_TO_BACKEND) => Fate::Fail(Why::Backend),
        Some(LOOKUP_FAILED | LOOKUP_FAILED_RECONNECT) => Fate::Fail(Why::Lookup),
        Some(SID_UNKNOWN | SID_IN_USE | FAILED_TO_REWIND) => Fate::Fail(Why::Lost),
        Some(4005..=4008 | INVALID_DATA) => Fate::Fail(Why::Protocol),
        _ => Fate::Resume,
    }
}

/// The stage and the class of a Close with `code` that ends a session or
/// opens none: a refusal of the account or of its token is IAP's, at the
/// upgrade's stage; a port of the VM that IAP cannot reach, or no such VM,
/// is the origin's; a session that the server forgot is the session's.
pub fn stage_and_class(code: Option<u16>) -> (Stage, Class) {
    match fate(code) {
        Fate::Fail(Why::NotAuthorized) | Fate::Reauthenticate => (Stage::WebSocket, Class::Refused),
        Fate::Fail(Why::Backend) | Fate::End => (Stage::Origin, Class::Unavailable),
        Fate::Fail(Why::Lookup) => (Stage::Origin, Class::NotFound),
        Fate::Fail(Why::Lost) => (Stage::Session, Class::Unavailable),
        Fate::Fail(Why::Protocol) => (Stage::WebSocket, Class::Protocol),
        Fate::Resume => (Stage::WebSocket, Class::Unavailable),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iap_close_codes_have_their_fates() {
        for code in [1000, 4009, 4010] {
            assert_eq!(fate(Some(code)), Fate::End, "{code}");
        }
        assert_eq!(fate(Some(4004)), Fate::Reauthenticate);
        assert_eq!(fate(Some(4033)), Fate::Fail(Why::NotAuthorized));
        assert_eq!(fate(Some(4003)), Fate::Fail(Why::Backend));
        assert_eq!(fate(Some(4047)), Fate::Fail(Why::Lookup));
        assert_eq!(fate(Some(4051)), Fate::Fail(Why::Lookup));
        for code in [4001, 4002, 4074] {
            assert_eq!(fate(Some(code)), Fate::Fail(Why::Lost), "{code}");
        }
        for code in [4005, 4006, 4007, 4008, 4013] {
            assert_eq!(fate(Some(code)), Fate::Fail(Why::Protocol), "{code}");
        }
        for code in [None, Some(1001), Some(1006), Some(1011), Some(4000), Some(4999)] {
            assert_eq!(fate(code), Fate::Resume, "{code:?}");
        }
    }

    #[test]
    fn iap_close_codes_have_their_stages_and_classes() {
        assert_eq!(stage_and_class(Some(4033)), (Stage::WebSocket, Class::Refused));
        assert_eq!(stage_and_class(Some(4004)), (Stage::WebSocket, Class::Refused));
        assert_eq!(stage_and_class(Some(4003)), (Stage::Origin, Class::Unavailable));
        assert_eq!(stage_and_class(Some(4047)), (Stage::Origin, Class::NotFound));
        assert_eq!(stage_and_class(Some(4074)), (Stage::Session, Class::Unavailable));
        assert_eq!(stage_and_class(Some(4013)), (Stage::WebSocket, Class::Protocol));
        assert_eq!(stage_and_class(None), (Stage::WebSocket, Class::Unavailable));
    }
}
