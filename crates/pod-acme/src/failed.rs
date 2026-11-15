//! Why ACME gave no certificate. No variant holds a key.

use std::fmt;

use pod_core::{Class, Failure, Stage};

/// Why a client or an order of ACME gave nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failed {
    /// The directory's URL is no `https://` URL: the caller's setting.
    Directory(String),
    /// The state could not be kept or read: no private directory, a key or
    /// a chain that does not load.
    Store(String),
    /// The CA refused, or did not answer, or answered what is not ACME.
    Ca(String),
    /// The order did not end within its limit.
    Late(String),
}

impl Failed {
    /// The stage and the class of the failure, for a caller that maps them
    /// to an exit code.
    pub fn stage_and_class(&self) -> (Stage, Class) {
        match self {
            Failed::Directory(_) => (Stage::Origin, Class::Usage),
            Failed::Store(_) => (Stage::Host, Class::Unavailable),
            Failed::Ca(_) => (Stage::Origin, Class::Unavailable),
            Failed::Late(_) => (Stage::Origin, Class::Timeout),
        }
    }

    /// The same failure, its words between `before` and `after`.
    pub fn within(self, before: impl fmt::Display, after: impl fmt::Display) -> Failed {
        let words = |why: String| format!("{before}{why}{after}");
        match self {
            Failed::Directory(why) => Failed::Directory(words(why)),
            Failed::Store(why) => Failed::Store(words(why)),
            Failed::Ca(why) => Failed::Ca(words(why)),
            Failed::Late(why) => Failed::Late(words(why)),
        }
    }
}

impl fmt::Display for Failed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failed::Directory(why) | Failed::Store(why) | Failed::Ca(why) | Failed::Late(why) => f.write_str(why),
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
    use super::*;

    #[test]
    fn each_failure_has_a_stage_and_a_class_and_keeps_its_words() {
        let all = [
            (Failed::Directory("x".into()), Stage::Origin, Class::Usage),
            (Failed::Store("x".into()), Stage::Host, Class::Unavailable),
            (Failed::Ca("x".into()), Stage::Origin, Class::Unavailable),
            (Failed::Late("x".into()), Stage::Origin, Class::Timeout),
        ];
        for (failed, stage, class) in all {
            let failure = Failure::from(failed.clone().within("ACME at ca.test: ", "; no certificate"));
            assert_eq!((failure.stage, failure.class), (stage, class), "{failed:?}");
            assert_eq!(failure.text(), "ACME at ca.test: x; no certificate");
        }
    }
}
