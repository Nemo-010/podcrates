//! The far end's line at each resume (PodUtils/podssh#283): the number of the
//! resume, the offset that each end gave in the handshake, the bytes that
//! this side sends again, and what held the session before: no link, the
//! first link or the link of an older resume, which the resume stopped. A
//! resume that does not take its session says why: an older resume gives
//! way to the newer one. The line goes to the sink of the keeper's
//! [`super::Tell`], with the kind [`RESUME`], at the level `Info`.

use pod_core::Event;

use super::Tell;
use crate::secret::SessionId;

/// The kind of the event of each resume at the far end.
pub const RESUME: &str = "session.resume";

/// Why a resume did not take its session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum NotTaken {
    /// The session ended, on its old link, while this one shook hands; the
    /// words of its `CLOSE`, empty but for one that a handover ended.
    Ended(String),
    /// A newer resume came, with this number: the client left this link.
    Newer(u64),
    /// The old link did not stop in time.
    Stuck,
}

impl std::fmt::Display for NotTaken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            NotTaken::Ended(_) => "the session ended on its old link",
            NotTaken::Newer(_) => "a newer link resumed the session",
            NotTaken::Stuck => "the old link of the session did not stop",
        })
    }
}

/// Where a resume found the session, and what it sends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Taken {
    /// The number of the resume, in the order of the handshakes.
    pub number: u64,
    /// The caller's name of the link that carries it: empty, or as `relay
    /// session ID`.
    pub by: String,
    /// The client's received offset, from its `PROOF`: this side sends
    /// from there.
    pub client: u64,
    /// This side's received offset in its `ACCEPT`: the client sends from
    /// there.
    pub accepted: u64,
    /// This side's received offset when the resume took the session: more
    /// than `accepted` when the old link read on after the `ACCEPT`.
    pub received: u64,
    /// The bytes received and not yet written to the target.
    pub held: usize,
    /// The bytes that this side sends again.
    pub again: u64,
    /// The link that the resume stopped: `Some(0)` for the first link,
    /// `Some(n)` for the link of resume `n`, `None` when no link held the
    /// session.
    pub stopped: Option<u64>,
    /// The room of the replay buffer once the resume took the session, and
    /// the window of the link: what the reader of the target may send.
    pub room: (usize, Option<usize>),
}

impl std::fmt::Display for Taken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let Taken { number, by, client, accepted, received, held, again, stopped, room } = self;
        write!(
            f,
            "resume {number}{}: the client has {client} bytes of this side, and this side sends {again} bytes again; \
             this side has {received} bytes of the client ({accepted} in its ACCEPT), {held} of them not yet \
             written to the target; ",
            on(by)
        )?;
        match stopped {
            None => f.write_str("no link carried the session"),
            Some(0) => f.write_str("it stopped the first link"),
            Some(older) => write!(f, "it stopped the link of resume {older}"),
        }?;
        match room {
            (room, Some(window)) => write!(f, "; room {room} in the replay buffer, a window of {window} bytes"),
            (room, None) => write!(f, "; room {room} in the replay buffer, no window"),
        }
    }
}

/// Say that resume `taken` carries session `id` on.
pub(super) fn took(tell: &Tell, id: &SessionId, taken: &Taken) {
    tell.events.event(Event::info(RESUME, format!("session {}: {taken}", id.short())));
}

/// Say that resume `number`, on the link named `by`, of session `id` did
/// not take it, and why.
pub(super) fn not_taken(tell: &Tell, id: &SessionId, (number, by): (u64, &str), why: &str) {
    let line = format!("session {}: resume {number}{} did not take it: {why}", id.short(), on(by));
    tell.events.event(Event::info(RESUME, line));
}

/// The words of the link's name, after the number of its resume.
fn on(by: &str) -> String {
    if by.is_empty() { String::new() } else { format!(" on {}", pod_core::text::one_line(by)) }
}

/// The words of `not`, with the newer resume's number when one came.
pub(super) fn why_not(not: &NotTaken) -> String {
    match not {
        NotTaken::Newer(newer) => format!("{not} (resume {newer}); this resume gave way"),
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn taken(stopped: Option<u64>) -> Taken {
        Taken {
            number: 3,
            by: String::new(),
            client: 4096,
            accepted: 8192,
            received: 9000,
            held: 12,
            again: 65536,
            stopped,
            room: (1 << 20, Some(786_432)),
        }
    }

    #[test]
    fn a_line_gives_the_number_the_offsets_the_bytes_sent_again_and_what_held_the_session() {
        let line = taken(None).to_string();
        assert_eq!(
            line,
            "resume 3: the client has 4096 bytes of this side, and this side sends 65536 bytes again; this side \
             has 9000 bytes of the client (8192 in its ACCEPT), 12 of them not yet written to the target; no link \
             carried the session; room 1048576 in the replay buffer, a window of 786432 bytes"
        );
        assert!(taken(Some(0)).to_string().contains("; it stopped the first link; room"));
        let named = Taken { by: "relay session 0a1b".into(), ..taken(None) };
        assert!(named.to_string().starts_with("resume 3 on relay session 0a1b: the client has 4096 bytes"), "{named}");
        assert!(taken(Some(2)).to_string().contains("; it stopped the link of resume 2; room"));
        let open = Taken { room: (5, None), ..taken(None) };
        assert!(open.to_string().ends_with("; room 5 in the replay buffer, no window"), "{open}");
        assert_eq!(why_not(&NotTaken::Newer(5)), "a newer link resumed the session (resume 5); this resume gave way");
        assert_eq!(why_not(&NotTaken::Stuck), "the old link of the session did not stop");
    }
}
