//! The stage and the class of a failure in an `anyhow` chain (section 1,
//! rule 9). The stage names the part of the path that broke (podnet's
//! `Hop`); the class gives the exit code of the consumer (podnet's
//! `Fault`). Both survive a later `context`.

use std::fmt;

use pod_core::{Class, Stage};

/// An error with the stage where it happened.
#[derive(Debug)]
pub struct AtStage {
    pub stage: Stage,
    inner: anyhow::Error,
}

impl fmt::Display for AtStage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl AtStage {
    pub fn inner(&self) -> &anyhow::Error {
        &self.inner
    }
}

impl std::error::Error for AtStage {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

/// Tag `err` with `stage`. A stage that is in the chain stays: the inner
/// stage is the more exact one.
pub fn at(stage: Stage, err: anyhow::Error) -> anyhow::Error {
    if stage_of(&err).is_some() {
        return err;
    }
    anyhow::Error::new(AtStage { stage, inner: err })
}

/// The innermost stage of `err`. A refusal of the edge is the stage
/// `EdgeRegister`.
pub fn stage_of(err: &anyhow::Error) -> Option<Stage> {
    let tagged = err.chain().filter_map(|e| e.downcast_ref::<AtStage>()).last().map(|e| e.stage);
    tagged.or_else(|| err.chain().any(|e| e.downcast_ref::<Refused>().is_some()).then_some(Stage::EdgeRegister))
}

/// The refusal of a registration by the edge.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Refused {
    pub cause: String,
    pub should_retry: bool,
    pub retry_after: std::time::Duration,
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "the edge refused the registration: {} (retry: {}, after {} s; podnet speaks {})",
            self.cause,
            if self.should_retry { "yes" } else { "no" },
            self.retry_after.as_secs(),
            crate::cloudflare::speaks()
        )
    }
}

impl std::error::Error for Refused {}

/// Tag a result with a stage.
pub trait StageExt<T> {
    fn stage(self, stage: Stage) -> anyhow::Result<T>;
}

impl<T, E: Into<anyhow::Error>> StageExt<T> for Result<T, E> {
    fn stage(self, stage: Stage) -> anyhow::Result<T> {
        self.map_err(|e| at(stage, e.into()))
    }
}

/// The text of an I/O error of a TLS handshake: an alert of the peer is
/// named; a reset or an end of the stream is said as such.
pub fn tls_text(err: &std::io::Error) -> String {
    if let Some(inner) = err.get_ref()
        && let Some(rustls::Error::AlertReceived(alert)) = inner.downcast_ref::<rustls::Error>()
    {
        return format!("TLS alert from the peer: {alert:?}");
    }
    match err.kind() {
        std::io::ErrorKind::ConnectionReset => {
            format!("the connection was reset during the TLS handshake ({err})")
        }
        std::io::ErrorKind::UnexpectedEof => "the connection was closed during the TLS handshake".to_string(),
        _ => err.to_string(),
    }
}

/// The stage of an I/O error of a TLS handshake: an error of rustls is
/// TLS; a reset or a refusal is the network.
pub fn tls_stage(err: &std::io::Error) -> Stage {
    use std::io::ErrorKind::*;
    if err.get_ref().is_some_and(|inner| inner.downcast_ref::<rustls::Error>().is_some()) {
        return Stage::Tls;
    }
    match err.kind() {
        ConnectionReset | ConnectionAborted | BrokenPipe | UnexpectedEof | TimedOut | ConnectionRefused => {
            Stage::Network
        }
        _ => Stage::Tls,
    }
}

/// An error with its class.
#[derive(Debug)]
pub struct Classed {
    pub class: Class,
    inner: anyhow::Error,
}

impl fmt::Display for Classed {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.inner)
    }
}

impl std::error::Error for Classed {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.inner.source()
    }
}

/// Give `err` the class `class`.
pub fn fault(class: Class, err: anyhow::Error) -> anyhow::Error {
    anyhow::Error::new(Classed { class, inner: err })
}

/// The class of `err`, if a part of its chain has one.
pub fn class_of(err: &anyhow::Error) -> Option<Class> {
    err.chain().find_map(|e| e.downcast_ref::<Classed>()).map(|c| c.class)
}

#[cfg(test)]
mod tests {
    use super::*;
    use anyhow::Context;

    #[test]
    fn a_reset_in_the_tls_handshake_is_the_network() {
        use std::io::{Error, ErrorKind};
        let reset = Error::from(ErrorKind::ConnectionReset);
        assert_eq!(tls_stage(&reset), Stage::Network);
        assert!(tls_text(&reset).contains("reset during the TLS handshake"));
        assert_eq!(tls_stage(&Error::from(ErrorKind::UnexpectedEof)), Stage::Network);
        let cert = Error::new(
            ErrorKind::InvalidData,
            rustls::Error::InvalidCertificate(rustls::CertificateError::UnknownIssuer),
        );
        assert_eq!(tls_stage(&cert), Stage::Tls);
    }

    #[test]
    fn the_innermost_stage_is_kept_through_context() {
        let err = Err::<(), _>(anyhow::anyhow!("403 not on the egress allowlist"))
            .stage(Stage::Proxy)
            .context("POST https://api.trycloudflare.com/tunnel")
            .map_err(|e| at(Stage::EdgeRegister, e))
            .unwrap_err();
        assert_eq!(stage_of(&err), Some(Stage::Proxy));
        assert_eq!(format!("{err:#}"), "POST https://api.trycloudflare.com/tunnel: 403 not on the egress allowlist");
        assert_eq!(stage_of(&anyhow::anyhow!("plain")), None);
    }

    #[test]
    fn a_class_survives_context() {
        let err = fault(Class::Config, anyhow::anyhow!("bad edge list"));
        let err = Err::<(), _>(err).context("starting the tunnel").unwrap_err();
        assert_eq!(class_of(&err), Some(Class::Config));
        assert_eq!(format!("{err:#}"), "starting the tunnel: bad edge list");
        assert_eq!(class_of(&anyhow::anyhow!("plain")), None);
    }
}
