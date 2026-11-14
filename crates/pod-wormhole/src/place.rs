//! Where the two ends of a code meet: a mailbox of magic-wormhole, the tag
//! of the code at a Nostr relay ([`crate::nostr`]), or the topic of the
//! code at an MQTT broker ([`crate::mqtt`]). The wormhole says the same
//! messages at each; a relay and a broker hold no nameplate and have no
//! mood.

use std::time::Duration;

use crate::Failed;
use crate::mailbox::{Mailbox, Message, Mood};
use crate::mqtt::Broker;
use crate::nostr::Relay;

/// A meeting point of one code.
pub enum Place {
    Mailbox(Mailbox),
    Relay(Relay),
    Broker(Broker),
}

impl From<Mailbox> for Place {
    fn from(mailbox: Mailbox) -> Place {
        Place::Mailbox(mailbox)
    }
}

impl From<Relay> for Place {
    fn from(relay: Relay) -> Place {
        Place::Relay(relay)
    }
}

impl From<Broker> for Place {
    fn from(broker: Broker) -> Place {
        Place::Broker(broker)
    }
}

impl Place {
    /// The URL, as lines show it.
    pub fn shown(&self) -> &str {
        match self {
            Place::Mailbox(m) => &m.shown,
            Place::Relay(r) => &r.shown,
            Place::Broker(b) => &b.shown,
        }
    }

    /// The word of the kind, for a line: `mailbox`, `Nostr relay` or
    /// `broker`.
    pub fn noun(&self) -> &'static str {
        match self {
            Place::Mailbox(_) => "mailbox",
            Place::Relay(_) => "Nostr relay",
            Place::Broker(_) => "broker",
        }
    }

    /// The AppID of the ends: SPAKE2's identity.
    pub fn appid(&self) -> &str {
        match self {
            Place::Mailbox(m) => m.appid(),
            Place::Relay(r) => r.appid(),
            Place::Broker(b) => b.appid(),
        }
    }

    /// Open the mailbox `id`; a relay and a broker subscribed to the code's
    /// tag or topic at their connection.
    pub async fn open(&mut self, id: &str) -> Result<(), Failed> {
        match self {
            Place::Mailbox(m) => m.open(id).await,
            Place::Relay(_) | Place::Broker(_) => Ok(()),
        }
    }

    /// Add a message of `phase` for the other end.
    pub async fn add(&mut self, phase: &str, body: &[u8]) -> Result<(), Failed> {
        match self {
            Place::Mailbox(m) => m.add(phase, body).await,
            Place::Relay(r) => r.add(phase, body).await,
            Place::Broker(b) => b.add(phase, body).await,
        }
    }

    /// The next message, within `wait`. A mailbox gives this end's own
    /// messages too; a relay and a broker do not.
    pub async fn message(&mut self, wait: Duration) -> Result<Option<Message>, Failed> {
        match self {
            Place::Mailbox(m) => m.message(wait).await,
            Place::Relay(r) => r.message(wait).await,
            Place::Broker(b) => b.message(wait).await,
        }
    }

    /// Release `nameplate` at a mailbox.
    pub async fn release(&mut self, nameplate: &str) -> Result<(), Failed> {
        match self {
            Place::Mailbox(m) => m.release(nameplate).await,
            Place::Relay(_) | Place::Broker(_) => Ok(()),
        }
    }

    /// Close the mailbox `id` with `mood`, end the subscription at the
    /// relay, or disconnect from the broker.
    pub async fn close(&mut self, id: &str, mood: Mood) -> Result<(), Failed> {
        match self {
            Place::Mailbox(m) => m.close(id, mood).await,
            Place::Relay(r) => {
                r.close().await;
                Ok(())
            }
            Place::Broker(b) => {
                b.disconnect().await;
                Ok(())
            }
        }
    }

    /// End the connection with a Close.
    pub async fn end(&self) {
        match self {
            Place::Mailbox(m) => m.end().await,
            Place::Relay(r) => r.end().await,
            Place::Broker(b) => b.end().await,
        }
    }
}
