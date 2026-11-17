//! The class of a flow (T-819, TR-4 of the ingest study): `Realtime`,
//! `Bulk` or `Default`, so that a carrier can take settings for each class.
//! The precedence: a rule of the caller's policy, then the DSCP of the
//! packet, then what the table saw of the flow, then `Default`. Both
//! directions of a flow have one key, so a reply takes the class of its
//! request. The table holds at most [`MOST_FLOWS`] flows, and a flow that is
//! idle for [`IDLE`] goes.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

/// The class of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Class {
    Realtime,
    Bulk,
    Default,
}

/// The most flows that the table holds.
pub const MOST_FLOWS: usize = 4096;
/// A flow with no packet for this long goes from the table.
pub const IDLE: Duration = Duration::from_secs(30);
/// The packets of a flow before its heuristic gives a class.
pub const WARM: u32 = 8;

/// The class of a DSCP: EF (46), CS5 (40), CS6 (48) and CS7 (56) are
/// `Realtime`; CS1 (8) and AF11 to AF13 (10, 12, 14) are `Bulk`.
pub fn of_dscp(dscp: u8) -> Option<Class> {
    match dscp {
        46 | 40 | 48 | 56 => Some(Class::Realtime),
        8 | 10 | 12 | 14 => Some(Class::Bulk),
        _ => None,
    }
}

/// One end of a flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct End {
    pub ip: IpAddr,
    pub port: u16,
}

/// The key of a flow: the protocol and its two ends in one order, so both
/// directions have the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Key {
    pub protocol: u8,
    pub low: End,
    pub high: End,
}

impl Key {
    /// The key of a packet from `source` to `destination`.
    pub fn of(protocol: u8, source: End, destination: End) -> Key {
        // The address and the port as one end: two flows of one host on two
        // ports are two keys.
        let (low, high) = if source <= destination { (source, destination) } else { (destination, source) };
        Key { protocol, low, high }
    }
}

/// A rule of the caller: a class for each flow to or from `port`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Rule {
    pub port: u16,
    pub class: Class,
}

/// What the table saw of a flow.
#[derive(Debug, Clone, Copy)]
struct Seen {
    packets: u32,
    large: u32,
    small: u32,
    first: Instant,
    last: Instant,
}

/// The classes of the flows that a stack carries.
#[derive(Debug, Default)]
pub struct Classes {
    rules: Vec<Rule>,
    flows: HashMap<Key, Seen>,
}

impl Classes {
    pub fn with_rules(rules: Vec<Rule>) -> Classes {
        Classes { rules, flows: HashMap::new() }
    }

    /// The class of a packet of `len` bytes with `dscp`, of the flow `key`,
    /// at `now`; the packet goes into what the table saw.
    pub fn class(&mut self, key: Key, dscp: u8, len: usize, now: Instant) -> Class {
        if let Some(rule) = self.rules.iter().find(|r| r.port == key.low.port || r.port == key.high.port) {
            return rule.class;
        }
        let seen = self.see(key, len, now);
        if let Some(class) = of_dscp(dscp) {
            return class;
        }
        seen.map_or(Class::Default, heuristic)
    }

    /// The flows in the table.
    pub fn len(&self) -> usize {
        self.flows.len()
    }

    pub fn is_empty(&self) -> bool {
        self.flows.is_empty()
    }

    fn see(&mut self, key: Key, len: usize, now: Instant) -> Option<Seen> {
        if !self.flows.contains_key(&key) && self.flows.len() >= MOST_FLOWS {
            self.flows.retain(|_, s| now.saturating_duration_since(s.last) < IDLE);
            if self.flows.len() >= MOST_FLOWS {
                // A full table of live flows: this flow gets no history, and
                // no flow of the table goes for it.
                return None;
            }
        }
        let seen = self.flows.entry(key).or_insert(Seen { packets: 0, large: 0, small: 0, first: now, last: now });
        if now.saturating_duration_since(seen.last) >= IDLE {
            *seen = Seen { packets: 0, large: 0, small: 0, first: now, last: now };
        }
        seen.packets += 1;
        seen.large += u32::from(len > 1000);
        seen.small += u32::from(len < 256);
        seen.last = now;
        Some(*seen)
    }
}

/// The class from what the table saw, after [`WARM`] packets: mostly large
/// packets are `Bulk`; mostly small ones at 20 or more each second are
/// `Realtime`.
fn heuristic(seen: Seen) -> Class {
    if seen.packets < WARM {
        return Class::Default;
    }
    if seen.large * 2 > seen.packets {
        return Class::Bulk;
    }
    let secs = seen.last.saturating_duration_since(seen.first).as_secs_f64().max(0.001);
    if seen.small * 2 > seen.packets && f64::from(seen.packets) / secs >= 20.0 {
        return Class::Realtime;
    }
    Class::Default
}

#[cfg(test)]
#[path = "class_tests.rs"]
mod tests;
