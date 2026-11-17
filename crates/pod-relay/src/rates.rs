//! The delivered rate of each host (T-814; the dig study's report 04): the
//! bytes and the time of each finished session that a caller counts
//! ([`crate::stream::of_measured`]), by host and egress, in a file of the
//! cache beside the rank. The rank still orders the hosts by the share of
//! failed probes and the time to open; this file gives the order by
//! measured rate beside it ([`order`]), which [`crate::rank_list::placed_now`]
//! writes as a debug line where it differs, for a release before any change
//! of the order. A session costs no new connection.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::cache;

/// The name of the file in the cache.
pub const FILE: &str = "relay-rates.json";
/// The version of the shape of the file.
pub const SCHEMA: u32 = 1;
/// The sessions of each host that the file keeps, the last ones.
pub const KEPT: usize = 16;
/// A session that carried fewer bytes says nothing of a rate: it is not
/// kept.
pub const MIN_BYTES: u64 = 1 << 20;
/// How long a session counts: a day, as a rank holds.
pub const HOLDS_MS: i64 = 24 * 3600 * 1000;

/// One finished session of a host.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rate {
    pub at_ms: i64,
    pub egress: String,
    /// The bytes both ways.
    pub bytes: u64,
    pub secs: f64,
}

/// The file: the sessions of each host, by its name.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Rates {
    pub schema: u32,
    pub hosts: BTreeMap<String, Vec<Rate>>,
}

impl Rates {
    /// A session of `host` through `egress`, unless it carried too few
    /// bytes or took no time; the last [`KEPT`] of the host stay.
    pub fn add(&mut self, host: &str, egress: &str, bytes: u64, secs: f64, now_ms: i64) {
        if bytes < MIN_BYTES || secs <= 0.0 {
            return;
        }
        let each = self.hosts.entry(host.to_string()).or_default();
        each.push(Rate { at_ms: now_ms, egress: egress.to_string(), bytes, secs });
        let over = each.len().saturating_sub(KEPT);
        each.drain(..over);
    }

    /// The median rate of `host` through `egress` within a day, in MiB
    /// each second; none with no such session.
    pub fn mib_s(&self, host: &str, egress: &str, now_ms: i64) -> Option<f64> {
        let mut rates: Vec<f64> = self
            .hosts
            .get(host)?
            .iter()
            .filter(|r| r.egress == egress && r.at_ms <= now_ms && now_ms - r.at_ms < HOLDS_MS)
            .map(|r| r.bytes as f64 / r.secs / (1 << 20) as f64)
            .collect();
        if rates.is_empty() {
            return None;
        }
        rates.sort_by(f64::total_cmp);
        Some(rates[rates.len() / 2])
    }
}

/// `names` by their measured rate through `egress`, the fastest first;
/// those with none keep their order, after the others.
pub fn order(names: &[String], rates: &Rates, egress: &str, now_ms: i64) -> Vec<(String, Option<f64>)> {
    let mut known: Vec<(String, Option<f64>)> = Vec::new();
    let mut unknown = Vec::new();
    for name in names {
        match rates.mib_s(name, egress, now_ms) {
            Some(rate) => known.push((name.clone(), Some(rate))),
            None => unknown.push((name.clone(), None)),
        }
    }
    known.sort_by(|a, b| b.1.unwrap_or(0.0).total_cmp(&a.1.unwrap_or(0.0)));
    known.extend(unknown);
    known
}

/// The rates in the cache.
pub fn load(cache: &cache::Cache) -> Rates {
    load_from(&cache.read_dirs())
}

/// [`load`] over explicit directories.
pub fn load_from(dirs: &[PathBuf]) -> Rates {
    cache::load_file_from(dirs, FILE).and_then(|text| serde_json::from_str(&text).ok()).unwrap_or_default()
}

/// Keep `rates` in the cache, a private file.
pub fn save(cache: &cache::Cache, rates: &Rates) -> Result<PathBuf, String> {
    let rates = Rates { schema: SCHEMA, ..rates.clone() };
    let body = serde_json::to_vec_pretty(&rates).map_err(|e| e.to_string())?;
    cache::store_file_in_first(cache.dirs(), FILE, &body)
}

/// A gap between two transfers longer than this is idle time, which a
/// rate leaves out: an SSH session can wait for hours, then copy.
pub const IDLE_GAP_NS: u64 = 1_000_000_000;

/// A counter of one session's bytes, both ways, and of its busy time: the
/// sum of the gaps under [`IDLE_GAP_NS`] between two transfers.
#[derive(Debug)]
pub struct Counted {
    bytes: AtomicU64,
    busy_ns: AtomicU64,
    last_ns: AtomicU64,
    started: Instant,
}

impl Default for Counted {
    fn default() -> Self {
        Counted {
            bytes: AtomicU64::new(0),
            busy_ns: AtomicU64::new(0),
            last_ns: AtomicU64::new(0),
            started: Instant::now(),
        }
    }
}

impl Counted {
    /// The bytes so far, and the busy seconds.
    pub fn taken(&self) -> (u64, f64) {
        (self.bytes.load(Ordering::Relaxed), self.busy_ns.load(Ordering::Relaxed) as f64 / 1e9)
    }

    fn add(&self, bytes: u64) {
        self.add_at(bytes, self.started.elapsed().as_nanos() as u64);
    }

    /// `bytes` at `now_ns` since the start.
    fn add_at(&self, bytes: u64, now_ns: u64) {
        self.bytes.fetch_add(bytes, Ordering::Relaxed);
        let before = self.last_ns.swap(now_ns, Ordering::Relaxed);
        let gap = now_ns.saturating_sub(before);
        if gap < IDLE_GAP_NS {
            self.busy_ns.fetch_add(gap, Ordering::Relaxed);
        }
    }
}

impl pod_ws::Tally for Counted {
    fn add_in(&self, bytes: u64) {
        self.add(bytes);
    }

    fn add_out(&self, bytes: u64) {
        self.add(bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIB: u64 = 1 << 20;

    #[test]
    fn a_session_with_too_few_bytes_is_not_kept_and_the_last_ones_stay() {
        let mut rates = Rates::default();
        rates.add("a.test", "direct", MIB - 1, 1.0, 10);
        rates.add("a.test", "direct", 8 * MIB, 0.0, 10);
        assert!(rates.hosts.is_empty());
        for i in 0..(KEPT as i64 + 4) {
            rates.add("a.test", "direct", 8 * MIB, 1.0, i);
        }
        assert_eq!(rates.hosts["a.test"].len(), KEPT);
        assert_eq!(rates.hosts["a.test"][0].at_ms, 4);
    }

    #[test]
    fn the_rate_is_the_median_of_the_day_and_of_the_egress() {
        let mut rates = Rates::default();
        for (mib, at) in [(10, 1), (20, 2), (30, 3)] {
            rates.add("a.test", "direct", mib * MIB, 1.0, at);
        }
        rates.add("a.test", "proxy-1", 100 * MIB, 1.0, 3);
        assert_eq!(rates.mib_s("a.test", "direct", 10), Some(20.0));
        assert_eq!(rates.mib_s("a.test", "proxy-1", 10), Some(100.0));
        assert_eq!(rates.mib_s("a.test", "direct", 3 + HOLDS_MS), None, "a day later");
        assert_eq!(rates.mib_s("b.test", "direct", 10), None);
    }

    #[test]
    fn the_order_by_rate_puts_the_fastest_first_and_the_unknown_last() {
        let mut rates = Rates::default();
        rates.add("slow.test", "direct", 2 * MIB, 1.0, 1);
        rates.add("fast.test", "direct", 40 * MIB, 1.0, 1);
        let names = ["first.test", "slow.test", "fast.test", "none.test"].map(String::from);
        let order: Vec<String> = order(&names, &rates, "direct", 5).into_iter().map(|(n, _)| n).collect();
        assert_eq!(order, ["fast.test", "slow.test", "first.test", "none.test"]);
    }

    /// The busy time leaves out each gap of a second or more.
    #[test]
    fn a_counter_leaves_idle_time_out() {
        let c = Counted::default();
        c.add_at(MIB, 100_000_000);
        c.add_at(MIB, 300_000_000);
        c.add_at(MIB, 3_600_000_000_000);
        c.add_at(MIB, 3_600_500_000_000);
        let (bytes, secs) = c.taken();
        assert_eq!(bytes, 4 * MIB);
        assert!((secs - 0.8).abs() < 1e-9, "{secs}");
    }

    #[test]
    fn the_file_keeps_its_rates() {
        let dir = std::env::temp_dir().join(format!("pod-relay-rates-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cache = cache::Cache::in_dirs(vec![dir.clone()]);
        let mut rates = Rates::default();
        rates.add("a.test", "direct", 8 * MIB, 2.0, 1);
        save(&cache, &rates).unwrap();
        let back = load(&cache);
        assert_eq!((back.schema, back.hosts.len()), (SCHEMA, 1));
        assert_eq!(back.mib_s("a.test", "direct", 2), Some(4.0));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
