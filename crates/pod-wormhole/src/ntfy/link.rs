//! The topic of one code at one ntfy server: this end reads the topic of
//! its direction and writes the other end's, on one connection
//! ([`super::conn`]).
//!
//! Before the code is shown or typed, the connection proves the server: on
//! HTTP/2 the stream of the topic gives its `open` line; on HTTP/1.1 a poll
//! gives `200` and lines of ntfy. A server that refuses is passed over with
//! its words.
//!
//! A server keeps each message for hours (12 h on ntfy.sh), and a read
//! from `since` gives the kept ones: the taker sends at once, and nothing
//! is sent again. Each read takes the messages since this end's start less
//! [`SINCE_SLACK`], then since the id of the last message read; a message
//! that comes twice is dropped by its id. The giver holds its messages
//! until the taker is heard, so that each end reads only what came after
//! its own start.

use std::collections::{HashSet, VecDeque};
use std::sync::Arc;
use std::time::Duration;

use pod_core::{Event, Events};
use tokio::time::Instant;

use super::conn::{self, Answer, Body, Conn};
use super::wire::{self, Lines, Said};
use super::{Pace, Point, SINCE_SLACK, Servers};
use crate::Failed;
use crate::config::Config;
use crate::message::{self, Message};
use crate::mqtt::Role;
use crate::nostr::unix_now;

/// The most messages kept while a step waits for its answer, as a mailbox.
pub const KEPT_MOST: usize = crate::mailbox::KEPT_MOST;
/// The most ids of messages that one topic gives: a code says a few dozen
/// messages, so a server that gives more is no honest one.
pub const SEEN_MOST: usize = 1024;

/// A connection to one server, reading the topic of one code.
pub struct Topic {
    conn: Conn,
    point: Point,
    config: Config,
    /// The URL, as lines show it.
    pub shown: String,
    side: String,
    /// The topic that this end reads, and the one that the other end reads.
    inbox: String,
    outbox: String,
    role: Role,
    pace: Pace,
    /// The stream of the inbox, on HTTP/2.
    stream: Option<Body>,
    lines: Lines,
    /// The lines of the stream that came and that were not read.
    pending: VecDeque<Vec<u8>>,
    /// The messages that came and that no step has read.
    kept: VecDeque<Message>,
    /// The giver's messages before the taker was heard.
    unanswered: Vec<String>,
    heard: bool,
    /// The ids of the messages read.
    seen: HashSet<String>,
    /// The id of the last message read; before it, this end's start less
    /// the slack.
    last: Option<String>,
    start: u64,
    next_poll: Instant,
    events: Arc<dyn Events>,
}

impl Topic {
    /// Dial the server at `point` and read the topic that `role` reads of
    /// `tag` as `side`; the first read proves the server.
    pub async fn connect(point: &Point, servers: &Servers, side: &str, tag: &str, role: Role) -> Result<Topic, Failed> {
        let conn = conn::dial(point, &servers.config, servers.h2).await?;
        let (inbox, outbox) = role.topics(tag);
        let mut topic = Topic {
            conn,
            point: point.clone(),
            config: servers.config.clone(),
            shown: point.shown(),
            side: side.to_string(),
            inbox,
            outbox,
            role,
            pace: servers.pace,
            stream: None,
            lines: Lines::default(),
            pending: VecDeque::new(),
            kept: VecDeque::new(),
            unanswered: Vec::new(),
            heard: false,
            seen: HashSet::new(),
            last: None,
            start: unix_now().saturating_sub(SINCE_SLACK.as_secs()),
            next_poll: Instant::now(),
            events: servers.config.events.clone(),
        };
        let proved = if topic.conn.is_h2() {
            topic.subscribe().await
        } else {
            // A server that limits this end before a word is no meeting point.
            match topic.poll_once().await {
                Ok(true) => Ok(()),
                Ok(false) => Err(Failed::Refused(format!("the ntfy server {} limits this end", topic.shown))),
                Err(failed) => Err(failed),
            }
        };
        match proved {
            Ok(()) => Ok(topic),
            Err(failed) => {
                topic.end().await;
                Err(failed)
            }
        }
    }

    /// The AppID of the ends.
    pub fn appid(&self) -> &str {
        &self.config.appid
    }

    /// The topic that this end reads.
    pub fn inbox(&self) -> &str {
        &self.inbox
    }

    /// Whether the connection is of HTTP/2: the stream and the POSTs share
    /// it; else the polls and the POSTs take turns.
    pub fn is_h2(&self) -> bool {
        self.conn.is_h2()
    }

    /// Send a message of `phase` to the other end; before the taker was
    /// heard, the giver holds it.
    pub async fn add(&mut self, phase: &str, body: &[u8]) -> Result<(), Failed> {
        let content = wire::content(&self.side, phase, body).map_err(|len| {
            Failed::Broken(format!(
                "a message of {len} bytes is over the {} that an ntfy server carries",
                super::MESSAGE_MOST
            ))
        })?;
        if !self.heard && self.role == Role::Giver {
            self.unanswered.push(content);
            return Ok(());
        }
        self.publish(&content).await
    }

    /// The next message of the other end, the kept ones first; `None` when
    /// none comes within `wait`.
    pub async fn message(&mut self, wait: Duration) -> Result<Option<Message>, Failed> {
        let deadline = Instant::now() + wait;
        loop {
            if let Some(kept) = self.kept.pop_front() {
                return Ok(Some(kept));
            }
            if self.conn.is_h2() {
                if !self.read_stream(deadline).await? {
                    return Ok(None);
                }
                continue;
            }
            if Instant::now() >= self.next_poll {
                self.poll_once().await?;
                if !self.kept.is_empty() {
                    continue;
                }
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            tokio::time::sleep_until(deadline.min(self.next_poll)).await;
        }
    }

    /// End the stream of the topic; the server keeps the messages.
    pub async fn close(&mut self) {
        self.stream = None;
    }

    /// End the connection.
    pub async fn end(&mut self) {
        self.stream = None;
        self.conn.end().await;
    }

    /// The `since` of the next read.
    fn since(&self) -> String {
        self.last.clone().unwrap_or_else(|| self.start.to_string())
    }

    /// One poll of the inbox: its messages kept; `false` when the server
    /// limited this end (`429`).
    async fn poll_once(&mut self) -> Result<bool, Failed> {
        let target = self.point.target(&format!("{}/json?poll=1&since={}", self.inbox, self.since()));
        let answer = self.request("GET", &target, b"").await?;
        let quiet = self.role == Role::Giver && !self.heard;
        self.next_poll = Instant::now() + if quiet { self.pace.waiting } else { self.pace.poll };
        let Some(answer) = answer else {
            self.next_poll = Instant::now() + self.pace.retry;
            return Ok(false);
        };
        let mut lines = Lines::default();
        let mut all = lines.feed(&answer.body).map_err(|why| self.broken(&why))?;
        all.extend(lines.rest());
        for line in all {
            self.heed(&line).await?;
        }
        Ok(true)
    }

    /// The stream of the inbox from `since`, its `open` line read within
    /// the answer limit.
    async fn subscribe(&mut self) -> Result<(), Failed> {
        let target = self.point.target(&format!("{}/json?since={}", self.inbox, self.since()));
        let (status, body) = self.conn.stream(&self.point, &self.config, &target).await?;
        if !(200..300).contains(&status) {
            let mut answer = Answer { status, body: Vec::new() };
            let mut body = body;
            while let Some(Ok(part)) = body.part().await {
                answer.body.extend_from_slice(&part);
                if answer.body.len() > conn::BODY_MOST {
                    break;
                }
            }
            return Err(self.refused(&answer));
        }
        self.stream = Some(body);
        (self.lines, self.pending) = (Lines::default(), VecDeque::new());
        let deadline = Instant::now() + self.config.answer_limit;
        loop {
            let read = tokio::time::timeout_at(deadline, self.next_line()).await;
            let Ok(line) = read else {
                let limit = self.config.answer_limit;
                return Err(self.broken(&format!("its stream gave no open line within {limit:?}")));
            };
            let line = line?.ok_or_else(|| self.broken("its stream ended before its open line"))?;
            if wire::said(&line) == Some(Said::Open) {
                return Ok(());
            }
            self.heed(&line).await?;
        }
    }

    /// Read the stream until a message is kept (`true`) or `deadline`
    /// (`false`); a stream that ended is opened again from the last id.
    async fn read_stream(&mut self, deadline: Instant) -> Result<bool, Failed> {
        while self.kept.is_empty() {
            let line = tokio::select! {
                biased;
                line = self.next_line() => line?,
                () = tokio::time::sleep_until(deadline) => return Ok(false),
            };
            match line {
                Some(line) => self.heed(&line).await?,
                None => self.subscribe().await?,
            }
        }
        Ok(true)
    }

    /// The next line of the stream; `None` at its end.
    async fn next_line(&mut self) -> Result<Option<Vec<u8>>, Failed> {
        loop {
            if let Some(line) = self.pending.pop_front() {
                return Ok(Some(line));
            }
            let Some(stream) = self.stream.as_mut() else { return Ok(None) };
            let Some(part) = stream.part().await else {
                self.stream = None;
                return Ok(self.lines.rest());
            };
            let part = part.map_err(|why| self.broken(&why))?;
            let lines = self.lines.feed(&part).map_err(|why| self.broken(&why))?;
            self.pending.extend(lines);
        }
    }

    /// What one line means: a message of the other end is kept; the
    /// first one ends the giver's hold.
    async fn heed(&mut self, line: &[u8]) -> Result<(), Failed> {
        let Some(said) = wire::said(line) else {
            return Err(self.broken("it sent a line that is no JSON of ntfy"));
        };
        let Said::Message { id, topic, text, .. } = said else { return Ok(()) };
        if topic != self.inbox || self.seen.contains(&id) {
            return Ok(());
        }
        if self.seen.len() >= SEEN_MOST {
            return Err(self.broken(&format!("it gave more than {SEEN_MOST} messages of one code")));
        }
        self.seen.insert(id.clone());
        self.last = Some(id);
        let read = message::object(text.as_bytes()).as_ref().and_then(message::message_of);
        let Some(message) = read.filter(|m| m.side != self.side) else { return Ok(()) };
        if !self.heard {
            self.heard = true;
            for content in std::mem::take(&mut self.unanswered) {
                self.publish(&content).await?;
            }
        }
        if self.kept.len() >= KEPT_MOST {
            return Err(self.broken(&format!("it sent more than {KEPT_MOST} messages at once")));
        }
        self.kept.push_back(message);
        Ok(())
    }

    /// One POST of `content` to the outbox.
    async fn publish(&mut self, content: &str) -> Result<(), Failed> {
        let target = self.point.target(&self.outbox.clone());
        let deadline = Instant::now() + self.config.answer_limit;
        loop {
            if self.request("POST", &target, content.as_bytes()).await?.is_some() {
                return Ok(());
            }
            if Instant::now() + self.pace.retry > deadline {
                let limit = self.config.answer_limit;
                return Err(Failed::Refused(format!("the ntfy server {} limited each POST for {limit:?}", self.shown)));
            }
            tokio::time::sleep(self.pace.retry).await;
        }
    }

    /// One request and its answer; `None` for an answer `429`, which the
    /// caller waits out, with an event; a refusal fails with its words.
    async fn request(&mut self, method: &str, target: &str, body: &[u8]) -> Result<Option<Answer>, Failed> {
        let answer = self.conn.request(&self.point, &self.config, method, target, body).await?;
        if answer.status == 429 {
            let line = format!("the ntfy server {} limits this end: {}", self.shown, answer.refusal());
            self.events.event(Event::info("wormhole.ntfy", line));
            return Ok(None);
        }
        if !answer.is_success() {
            return Err(self.refused(&answer));
        }
        Ok(Some(answer))
    }

    fn refused(&self, answer: &Answer) -> Failed {
        Failed::Refused(format!("the ntfy server {} refused: {}", self.shown, answer.refusal()))
    }

    fn broken(&self, why: &str) -> Failed {
        Failed::Broken(format!("the ntfy server {}: {why}", self.shown))
    }
}
