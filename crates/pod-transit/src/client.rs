//! The client of the transit road: a connection to the transit relay for
//! each link, under the pair's token and this run's side, which meets the
//! node that waits there. A meeting with another client of the pair, or a
//! side that the relay dropped as a spare, is tried again within the wait.
//! The meeting proves the pair only: the node's identity is the end-to-end
//! channel's to check, above the layer.

use std::sync::Arc;
use std::time::Duration;

use pod_core::entropy::{NoRandom, OsEntropy};
use pod_session::client::{self, Outcome};
use pod_session::resume::{self, Next, Note};
use pod_session::{Ask, Ended, Hearing, Settings};
use rand::RngExt;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::config::Config;
use crate::failed::Failed;
use crate::far::dial;
use crate::link::Link;
use crate::meet::{Missed, Part, meet};
use crate::token::{Keys, Side};

/// How long a link waits for the node: one that waits at the relay answers
/// at once, and one that just met another client opens its next wait in a
/// second.
pub const MEET_LIMIT: Duration = Duration::from_secs(15);

/// The links of one client to the node of one pair.
pub struct Dialer {
    config: Config,
    keys: Keys,
    side: Side,
    wait: Duration,
}

impl Dialer {
    /// The dialer of the pair whose words are `keys`, at the relay of
    /// `config`, with a side of this run's.
    pub fn new(config: Config, keys: Keys) -> Result<Dialer, NoRandom> {
        let side = Side::random(&mut OsEntropy)?;
        Ok(Dialer { config, keys, side, wait: MEET_LIMIT })
    }

    /// The same, with `side` in place of a random one: a test's two ends of
    /// one side, which the relay never pairs.
    pub fn with_side(self, side: Side) -> Dialer {
        Dialer { side, ..self }
    }

    /// The same, waiting `wait` for the node in place of [`MEET_LIMIT`].
    pub fn with_wait(self, wait: Duration) -> Dialer {
        Dialer { wait, ..self }
    }

    /// The relay.
    pub fn url(&self) -> &pod_ws::url::WsUrl {
        &self.config.url
    }

    /// The settings of the dialer's connections.
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// A new link to the node, which met this client and proved the pair;
    /// else why there is none.
    pub async fn link(&self) -> Result<Link, Failed> {
        let (shown, until) = (self.config.url.shown(), Instant::now() + self.wait);
        let mut others: u32 = 0;
        loop {
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() {
                return Err(self.alone(others));
            }
            let session = dial(&self.config).await?;
            match meet(&session, &self.keys, &self.side, Part::Client, Some(left), &mut OsEntropy).await {
                Ok(first) => return Ok(Link::start(session, first)),
                Err(Missed::Alone(_)) => return Err(self.alone(others)),
                // Two clients of the pair met while the node's wait was
                // taken: each tries again, and the node's next wait comes.
                Err(Missed::SamePart) => {
                    others = others.saturating_add(1);
                    let line = format!("another client of the pair met this one at the transit relay {shown}");
                    self.config.info("transit.client", line);
                }
                // A spare side that the relay dropped, once another one met.
                Err(Missed::Dropped(why)) => {
                    self.config.info("transit.client", format!("the transit relay {shown}: {why}; trying again"))
                }
                Err(missed) => return Err(Failed::Missed { shown, missed }),
            }
            let _ = session.send_close(1000, "").await;
            drop(session);
            // Apart, so that two clients that parted do not meet again.
            let jitter = rand::rng().random_range(100..600);
            tokio::time::sleep(Duration::from_millis(jitter)).await;
        }
    }

    fn alone(&self, others: u32) -> Failed {
        let mut why = format!(
            "no node met this client at the transit relay {} within {} s",
            self.config.url.shown(),
            self.wait.as_secs()
        );
        if others > 0 {
            why.push_str(&format!(" (another client of the pair met it {others} times)"));
        }
        Failed::Alone(why)
    }
}

/// Carry `app` to the node of `dialer`: the first link and the layer's
/// handshake on it, then a new link after each lost one, until the session
/// ends. `note` hears each step of the session across links.
pub async fn carry<A, N>(dialer: &Dialer, app: A, settings: Settings, note: N) -> Result<Outcome, Failed>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    carry_heard(dialer, app, settings, note, Arc::default()).await
}

/// [`carry`], with the session's `hearing`, which a notice of the far end's
/// silence reads.
pub async fn carry_heard<A, N>(
    dialer: &Dialer,
    app: A,
    settings: Settings,
    note: N,
    hearing: Arc<Hearing>,
) -> Result<Outcome, Failed>
where
    A: AsyncRead + AsyncWrite + Unpin + Send,
    N: FnMut(Note),
{
    let first = dialer.link().await?;
    let client = client::start(first, Ask::New, settings, &mut OsEntropy).await;
    let client = client.map_err(|e| Failed::Session(e.to_string()))?;
    let client = client.with_hearing(hearing);
    let connect = |_: &Ended| async move {
        match dialer.link().await {
            Ok(link) => Next::Link(link),
            Err(why) => Next::Retry(why.to_string()),
        }
    };
    // On the heap: the layer's future is larger than a small thread's stack
    // in a debug build.
    Ok(Box::pin(resume::run(client, app, connect, note, &mut OsEntropy)).await)
}
