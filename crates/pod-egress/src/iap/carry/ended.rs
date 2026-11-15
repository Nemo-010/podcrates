//! Why no session opened, and how a session ended: each with its words, its
//! stage and its class, so that a caller maps it to its own code.

use std::fmt;
use std::time::Duration;

use pod_core::{Class, Failure, Stage};

use super::super::close;
use super::link::words;

/// Why no session opened.
#[derive(Debug)]
pub enum NotOpen<E> {
    /// The link did not open: the dial's own reason.
    Dial(E),
    /// The server closed the link before the session: its code and reason.
    Closed { code: Option<u16>, reason: String },
    /// No message of IAP within the wait.
    Silent(Duration),
    /// A message out of the protocol, or a link that broke.
    Fault(String),
}

impl<E> NotOpen<E> {
    /// The stage and the class of the failure; `None` for a dial that
    /// failed, which has its own.
    pub fn stage_and_class(&self) -> Option<(Stage, Class)> {
        match self {
            NotOpen::Dial(_) => None,
            NotOpen::Closed { code, .. } => Some(close::stage_and_class(*code)),
            NotOpen::Silent(_) => Some((Stage::WebSocket, Class::Timeout)),
            NotOpen::Fault(_) => Some((Stage::WebSocket, Class::Protocol)),
        }
    }
}

impl<E: fmt::Display> fmt::Display for NotOpen<E> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            NotOpen::Dial(e) => write!(f, "{e}"),
            NotOpen::Closed { code, reason } => {
                write!(f, "IAP closed the link before the session: {}", words(*code, reason))
            }
            NotOpen::Silent(wait) => {
                write!(f, "IAP sent no connect success within {} s of the upgrade", wait.as_secs())
            }
            NotOpen::Fault(why) => f.write_str(why),
        }
    }
}

/// A dial's failure is its own; each other has the stage and the class of
/// what came.
impl<E: fmt::Display + Into<Failure>> From<NotOpen<E>> for Failure {
    fn from(e: NotOpen<E>) -> Failure {
        match e {
            NotOpen::Dial(e) => e.into(),
            other => {
                let (stage, class) = other.stage_and_class().unwrap_or((Stage::WebSocket, Class::Protocol));
                Failure::new(stage, class, other.to_string())
            }
        }
    }
}

/// How a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Ended {
    /// The stream's own end: the caller's, or the far end's.
    Normal,
    /// A Close of the server that ends the session: its code and reason.
    Closed { code: Option<u16>, reason: String },
    /// A lost link that no new one took up: why.
    Lost(String),
    /// A fault of the protocol: why.
    Fault(String),
}

impl Ended {
    /// The stage and the class of an end that is a failure; `None` for the
    /// stream's own end.
    pub fn stage_and_class(&self) -> Option<(Stage, Class)> {
        match self {
            Ended::Normal => None,
            Ended::Closed { code, .. } => Some(close::stage_and_class(*code)),
            Ended::Lost(_) => Some((Stage::Session, Class::Unavailable)),
            Ended::Fault(_) => Some((Stage::WebSocket, Class::Protocol)),
        }
    }

    /// The end as a failure; `None` for the stream's own end.
    pub fn failure(&self) -> Option<Failure> {
        self.stage_and_class().map(|(stage, class)| Failure::new(stage, class, self.to_string()))
    }
}

impl fmt::Display for Ended {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Ended::Normal => f.write_str("the session ended"),
            Ended::Closed { code, reason } => write!(f, "IAP ended the session: {}", words(*code, reason)),
            Ended::Lost(why) => write!(f, "the link to IAP was lost, and {why}"),
            Ended::Fault(why) => f.write_str(why),
        }
    }
}
