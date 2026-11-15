//! The node of the transit road: one connection at a time that waits at
//! the transit relay for an operator of the pair, under the pair's token
//! and the node's side for the run; at each meeting the next one opens at
//! once, and the link is served by the resumable layer's far end with the
//! node's keeper, which the pair's road may share, so that a session
//! resumes on either. A new session reaches its target only after its
//! handshake, and the end-to-end channel above it. A connection that fails
//! is made again with the jittered backoff of `pod-core`; a peer that
//! did not prove the pair costs a wait too, so that a stranger who knows
//! the token cannot keep the node busy.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use pod_core::entropy::OsEntropy;
use pod_session::budget::Tell;
use pod_session::keep::Keeper;
use pod_session::record::Role;
use pod_session::{Settings, far};
use pod_ws::RelaySession;
use pod_ws::url::{self, Stream};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::time::Instant;

use crate::config::Config;
use crate::failed::Failed;
use crate::link::Link;
use crate::meet::{Missed, Part, meet};
use crate::token::{Keys, Side};

/// How often the sessions whose links are lost are checked for their
/// deadline.
const SWEEP_EVERY: Duration = Duration::from_secs(10);
/// A wait that the relay ended after this long, with no meeting, is the
/// relay's own bound on a wait: the next one starts at once.
const LONG_WAIT: Duration = Duration::from_secs(60);

/// The pair's words now, read before each wait: a node goes on with a later
/// pair at an expiry, and its token is that pair's.
pub type KeysNow = Arc<dyn Fn() -> Keys + Send + Sync>;

/// A node of the transit road.
pub struct Node {
    /// The relay, the way out, the trust and the sink of the node's lines.
    pub config: Config,
    pub keys: KeysNow,
    /// The node's side for the run, so that its waits never meet each other.
    pub side: Side,
}

/// A connection to the relay of `config`, before its meeting.
pub async fn dial(config: &Config) -> Result<RelaySession<Stream>, Failed> {
    let (url, timeout) = (&config.url, config.connect_timeout);
    url::dial(url, &config.way, &config.trust, timeout, config.idle).await.map_err(|e| {
        let (stage, class) = e.stage_and_class();
        Failed::Dial { why: url::failure(url, &e), stage, class }
    })
}

/// Serve the sessions of each link of `node`, for ever, with a keeper of its
/// own, whose budget lines go to `tell`; a new session's target comes from
/// `open`, and the replay buffers of all sessions stay within `budget`
/// bytes.
pub async fn serve<A, O, F>(node: Node, settings: Settings, budget: usize, open: O, tell: Tell)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    let keeper = Arc::new(Keeper::new(settings.resume_deadline).with_tell(tell));
    serve_kept(node, settings, budget, open, keeper).await
}

/// [`serve`] with `keeper`, which another road's far end may share, so that
/// a session resumes on either road. It returns never: the caller ends it.
pub async fn serve_kept<A, O, F>(node: Node, settings: Settings, budget: usize, open: O, keeper: Arc<Keeper<A>>)
where
    A: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    O: Fn() -> F + Clone + Send + Sync + 'static,
    F: Future<Output = Result<A, String>> + Send + 'static,
{
    // The sweep ends with the keeper, when the node and its sessions end.
    {
        let keeper = Arc::downgrade(&keeper);
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(SWEEP_EVERY).await;
                let Some(keeper) = keeper.upgrade() else { return };
                keeper.expire().await;
            }
        });
    }
    let (config, shown) = (&node.config, node.config.url.shown());
    let (mut retry, mut waiting): (u32, bool) = (0, false);
    loop {
        let keys = (node.keys)();
        let session = match dial(config).await {
            Ok(session) => session,
            Err(why) => {
                config.warn("transit.dial", format!("no connection to the transit relay: {why}"));
                waiting = false;
                retry = retry.saturating_add(1);
                pause(&node, retry).await;
                continue;
            }
        };
        if !waiting {
            config.info("transit.wait", format!("waiting at the transit relay {shown} for the pair's operators"));
            waiting = true;
        }
        let started = Instant::now();
        match meet(&session, &keys, &node.side, Part::Node, None, &mut OsEntropy).await {
            Ok(first) => {
                retry = 0;
                let link = Link::start(session, first);
                let (keeper, open) = (keeper.clone(), open.clone());
                tokio::spawn(async move {
                    far::serve(link, Role::NODE, settings, &keeper, budget, open).await;
                });
            }
            // The relay's own bound on a wait, or a spare that it dropped:
            // the next wait, at once.
            Err(Missed::Dropped(_)) if started.elapsed() >= LONG_WAIT => retry = 0,
            // Two waits of this node never meet; a node of the same pair
            // elsewhere is the user's to stop, as on the pair's road.
            Err(missed) => {
                config.warn("transit.meeting", format!("a meeting at the transit relay failed: {missed}"));
                waiting = false;
                retry = retry.saturating_add(1);
                pause(&node, retry).await;
            }
        }
    }
}

/// The jittered backoff of the `retry`th failure in a row, said.
async fn pause(node: &Node, retry: u32) {
    let wait = pod_core::backoff::backoff(retry);
    node.config.info("transit.pause", format!("waiting at the transit relay again in {} ms", wait.as_millis()));
    tokio::time::sleep(wait).await;
}
