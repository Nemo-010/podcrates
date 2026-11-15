//! Why the transit road gave no link. No variant holds the token or a key.

use std::fmt;

use pod_core::{Class, Failure, Stage};

use crate::meet::Missed;

/// Why a dial, a meeting or a carry of the transit road gave nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The relay took no connection: the dial, TLS or the upgrade failed.
    /// The words name the relay as shown; the stage and the class are the
    /// dial's.
    Dial { why: String, stage: Stage, class: Class },
    /// No node met this client within its wait, in the words of the client.
    Alone(String),
    /// The meeting at the relay at `shown` failed.
    Missed { shown: String, missed: Missed },
    /// The handshake of the resumable layer on the first link failed.
    Session(String),
}

impl Failed {
    /// The stage and the class of the failure, for a caller that maps them
    /// to an exit code.
    pub fn stage_and_class(&self) -> (Stage, Class) {
        match self {
            Failed::Dial { stage, class, .. } => (*stage, *class),
            Failed::Alone(_) => (Stage::Rendezvous, Class::Timeout),
            Failed::Missed { missed, .. } => match missed {
                Missed::Alone(_) => (Stage::Rendezvous, Class::Timeout),
                Missed::Dropped(_) => (Stage::Rendezvous, Class::TempFail),
                Missed::Refused(_) => (Stage::Rendezvous, Class::Protocol),
                Missed::SamePart => (Stage::Rendezvous, Class::TempFail),
                Missed::NotProven(_) => (Stage::Rendezvous, Class::Refused),
                Missed::Broken(_) => (Stage::Rendezvous, Class::Unavailable),
            },
            Failed::Session(_) => (Stage::Session, Class::Protocol),
        }
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failed::Dial { why, .. } | Failed::Alone(why) | Failed::Session(why) => f.write_str(why),
            Failed::Missed { shown, missed } => write!(f, "the transit relay {shown}: {missed}"),
        }
    }
}

impl std::error::Error for Failed {}

impl From<Failed> for Failure {
    fn from(failed: Failed) -> Failure {
        let (stage, class) = failed.stage_and_class();
        Failure::caused(stage, class, failed.to_string(), failed)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn each_failure_has_a_stage_and_a_class_and_becomes_a_failure() {
        let missed = |missed| Failed::Missed { shown: "wss://relay.example".into(), missed };
        let all = [
            (Failed::Dial { why: "x".into(), stage: Stage::Tls, class: Class::Refused }, Stage::Tls, Class::Refused),
            (Failed::Alone("x".into()), Stage::Rendezvous, Class::Timeout),
            (missed(Missed::Alone(Duration::from_secs(1))), Stage::Rendezvous, Class::Timeout),
            (missed(Missed::Dropped("x".into())), Stage::Rendezvous, Class::TempFail),
            (missed(Missed::Refused("x".into())), Stage::Rendezvous, Class::Protocol),
            (missed(Missed::SamePart), Stage::Rendezvous, Class::TempFail),
            (missed(Missed::NotProven("x".into())), Stage::Rendezvous, Class::Refused),
            (missed(Missed::Broken("x".into())), Stage::Rendezvous, Class::Unavailable),
            (Failed::Session("x".into()), Stage::Session, Class::Protocol),
        ];
        for (failed, stage, class) in all {
            assert_eq!(failed.stage_and_class(), (stage, class), "{failed:?}");
            let text = failed.to_string();
            let failure = Failure::from(failed);
            assert_eq!((failure.stage, failure.class, failure.text()), (stage, class, text.as_str()));
        }
        let words = missed(Missed::NotProven("its proof is not of this pair's secret".into())).to_string();
        assert_eq!(
            words,
            "the transit relay wss://relay.example: the peer did not prove the pair: its proof is not of this pair's secret"
        );
    }
}
