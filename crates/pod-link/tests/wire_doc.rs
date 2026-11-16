//! `WIRE.md` against the code: each table row against the constant, the
//! decoder or `Settings::check` that it names, and each rule id against
//! its definition. A failure names the table and the row.

use std::collections::BTreeSet;
use std::time::Duration;

use pod_link::frame::{Decoder, Frame, FrameError, HEADER, PREFACE, kind};
use pod_link::{
    CONTROL_LIMIT, GoAwayCode, INITIAL_WINDOW, MAX_CREDIT, MAX_RECORD, MAX_STREAMS, MAX_WINDOW, MIN_FRAME, MIN_QUEUE,
    MIN_WINDOW, ResetCode, Settings,
};

const WIRE: &str = include_str!("../WIRE.md");
const README: &str = include_str!("../README.md");

/// The rows of the first table after the heading `head`, with no
/// backticks, with the header row and the rule row removed.
fn table(head: &str) -> Vec<Vec<String>> {
    let at = WIRE.find(&format!("\n{head}\n")).unwrap_or_else(|| panic!("WIRE.md has no heading {head:?}"));
    let rows: Vec<Vec<String>> = WIRE[at..]
        .lines()
        .skip_while(|l| !l.starts_with('|'))
        .take_while(|l| l.starts_with('|'))
        .map(|l| l.trim_matches('|').split('|').map(|c| c.trim().replace('`', "")).collect())
        .collect();
    assert!(rows.len() > 2, "the table {head:?} has no rows");
    rows[2..].to_vec()
}

/// A size or a count: `4096`, `16 KiB`, `1 MiB`.
fn size(cell: &str) -> Option<u64> {
    let mut words = cell.split_whitespace();
    let n: u64 = words.next()?.parse().ok()?;
    match words.next() {
        None => Some(n),
        Some("KiB") => Some(n << 10),
        Some("MiB") => Some(n << 20),
        Some(_) => None,
    }
}

/// A duration: `10 s`.
fn secs(cell: &str) -> Option<Duration> {
    cell.strip_suffix(" s")?.parse().ok().map(Duration::from_secs)
}

/// The header of a frame and a body of `len` bytes of 1.
fn bytes(t: u8, id: u32, len: usize) -> Vec<u8> {
    let mut b = vec![t];
    b.extend_from_slice(&id.to_be_bytes());
    b.extend_from_slice(&(len as u32).to_be_bytes()[1..]);
    b.resize(HEADER + len, 1);
    b
}

fn decode(t: u8, id: u32, len: usize) -> Result<Option<Frame>, FrameError> {
    let mut d = Decoder::new();
    d.push(&bytes(t, id, len));
    d.next()
}

fn check_all(name: &str, faults: Vec<String>) {
    assert!(faults.is_empty(), "WIRE.md, {name}:\n{}", faults.join("\n"));
}

#[test]
fn frame_types() {
    let known = [
        ("OPEN", kind::OPEN),
        ("DATA", kind::DATA),
        ("WINDOW", kind::WINDOW),
        ("CLOSE", kind::CLOSE),
        ("RESET", kind::RESET),
        ("PING", kind::PING),
        ("PONG", kind::PONG),
        ("GOAWAY", kind::GOAWAY),
    ];
    let mut faults = Vec::new();
    let mut seen = BTreeSet::new();
    for row in table("### Frame types") {
        let [t, name, id, len, _] = &row[..] else { panic!("the row {row:?} does not have 5 cells") };
        let Some(&(_, k)) = known.iter().find(|(n, _)| n == name) else {
            faults.push(format!("row {name}: no frame type of this name"));
            continue;
        };
        seen.insert(name.clone());
        if t.parse::<u8>().ok() != Some(k) {
            faults.push(format!("row {name}: the type {t}, the crate has {k}"));
        }
        let (stream_ok, link_ok) = match id.as_str() {
            "a stream" => (true, false),
            "0" => (false, true),
            "a stream or 0" => (true, true),
            other => {
                faults.push(format!("row {name}: the id {other:?} is not a known form"));
                continue;
            }
        };
        let good = |r: &Result<Option<Frame>, FrameError>| matches!(r, Ok(Some(_)));
        // A valid length for the id checks; a body of 1 bytes is a credit
        // that is not 0.
        let fine = match len.split_once(" to ") {
            Some((lo, hi)) => [size(lo), size(hi)].map(|n| n.map(|n| n as usize)),
            None => [size(len).map(|n| n as usize); 2],
        };
        let [Some(lo), Some(hi)] = fine else {
            faults.push(format!("row {name}: the body bytes {len:?} are not a size"));
            continue;
        };
        for (id, ok) in [(7, stream_ok), (0, link_ok)] {
            if good(&decode(k, id, lo)) != ok {
                faults.push(format!("row {name}: the id {id} gives {:?}", decode(k, id, lo)));
            }
        }
        let id = if stream_ok { 7 } else { 0 };
        for n in [lo, hi] {
            if !good(&decode(k, id, n)) {
                faults.push(format!("row {name}: a body of {n} bytes gives {:?}", decode(k, id, n)));
            }
        }
        for n in [lo.checked_sub(1), Some(hi + 1)].into_iter().flatten() {
            if good(&decode(k, id, n)) {
                faults.push(format!("row {name}: a body of {n} bytes decodes"));
            }
        }
    }
    let want: BTreeSet<String> = known.iter().map(|(n, _)| n.to_string()).collect();
    if seen != want {
        faults.push(format!("the rows {seen:?}, the crate has {want:?}"));
    }
    check_all("Frame types", faults);
}

#[test]
fn codes() {
    let known = [
        ("RESET", "CANCEL", ResetCode::CANCEL.0),
        ("RESET", "REFUSED", ResetCode::REFUSED.0),
        ("RESET", "PROTOCOL", ResetCode::PROTOCOL.0),
        ("GOAWAY", "NORMAL", GoAwayCode::NORMAL.0),
        ("GOAWAY", "PROTOCOL", GoAwayCode::PROTOCOL.0),
    ];
    let mut faults = Vec::new();
    let mut seen = BTreeSet::new();
    for row in table("### Codes") {
        let [frame, code, name, _] = &row[..] else { panic!("the row {row:?} does not have 4 cells") };
        seen.insert((frame.clone(), name.clone()));
        match known.iter().find(|(f, n, _)| f == frame && n == name) {
            Some(&(_, _, v)) if code.parse::<u32>().ok() == Some(v) => {}
            Some(&(_, _, v)) => faults.push(format!("row {frame} {name}: the code {code}, the crate has {v}")),
            None => faults.push(format!("row {frame} {name}: no code of this name")),
        }
    }
    let want: BTreeSet<_> = known.iter().map(|(f, n, _)| (f.to_string(), n.to_string())).collect();
    if seen != want {
        faults.push(format!("the rows {seen:?}, the crate has {want:?}"));
    }
    check_all("Codes", faults);
}

#[test]
fn limits() {
    let known: [(&str, u64); 10] = [
        ("HEADER", HEADER as u64),
        ("MAX_RECORD", MAX_RECORD as u64),
        ("INITIAL_WINDOW", u64::from(INITIAL_WINDOW)),
        ("MIN_WINDOW", u64::from(MIN_WINDOW)),
        ("MAX_WINDOW", u64::from(MAX_WINDOW)),
        ("MAX_CREDIT", MAX_CREDIT),
        ("MAX_STREAMS", MAX_STREAMS as u64),
        ("MIN_FRAME", MIN_FRAME as u64),
        ("CONTROL_LIMIT", CONTROL_LIMIT as u64),
        ("MIN_QUEUE", MIN_QUEUE as u64),
    ];
    let mut faults = Vec::new();
    let mut seen = BTreeSet::new();
    for row in table("### Limits") {
        let [name, value, _] = &row[..] else { panic!("the row {row:?} does not have 3 cells") };
        seen.insert(name.clone());
        if name == "PREFACE" {
            let hex: Vec<u8> = value.split(' ').filter_map(|b| u8::from_str_radix(b, 16).ok()).collect();
            if hex != PREFACE {
                faults.push(format!("row PREFACE: {value}, the crate has {PREFACE:02x?}"));
            }
            continue;
        }
        match known.iter().find(|(n, _)| n == name) {
            Some(&(_, v)) if size(value) == Some(v) => {}
            Some(&(_, v)) => faults.push(format!("row {name}: {value}, the crate has {v}")),
            None => faults.push(format!("row {name}: no constant of this name")),
        }
    }
    let want: BTreeSet<String> = known.iter().map(|(n, _)| n.to_string()).chain(["PREFACE".to_string()]).collect();
    if seen != want {
        faults.push(format!("the rows {seen:?}, the crate has {want:?}"));
    }
    if Settings::default().queue_limit() != (4 * Settings::default().frame_size).max(MIN_QUEUE) {
        faults.push("W-31: queue_limit is not the larger of 4 frames and MIN_QUEUE".into());
    }
    check_all("Limits", faults);
}

#[test]
fn settings() {
    let base = Settings::default();
    let mut faults = Vec::new();
    let mut seen = BTreeSet::new();
    for row in table("### Settings") {
        let [field, default, low, high, _] = &row[..] else { panic!("the row {row:?} does not have 5 cells") };
        seen.insert(field.clone());
        // Each field with a value: the default, and `check` at each limit
        // and one past it. The link window is at least the stream window.
        type Set = fn(&mut Settings, u64);
        let (now, set): (u64, Set) = match field.as_str() {
            "stream_window" => (u64::from(base.stream_window), |s, v| s.stream_window = v as u32),
            "link_window" => (u64::from(base.link_window), |s, v| {
                s.stream_window = MIN_WINDOW;
                s.link_window = v as u32;
            }),
            "max_streams" => (base.max_streams as u64, |s, v| s.max_streams = v as usize),
            "frame_size" => (base.frame_size as u64, |s, v| s.frame_size = v as usize),
            "keepalive" | "dead_after" => {
                let now = if field == "keepalive" { base.keepalive } else { base.dead_after };
                if secs(default) != Some(now) {
                    faults.push(format!("row {field}: the default {default}, the crate has {now:?}"));
                }
                if low != "-" || high != "-" {
                    faults.push(format!("row {field}: a duration has no limit cells"));
                }
                continue;
            }
            other => {
                faults.push(format!("row {other}: no setting of this name"));
                continue;
            }
        };
        if size(default) != Some(now) {
            faults.push(format!("row {field}: the default {default}, the crate has {now}"));
        }
        let try_value = |v: u64| {
            let mut s = base;
            set(&mut s, v);
            s.check().is_ok()
        };
        let (Some(lo), Some(hi)) = (size(low), size(high)) else {
            faults.push(format!("row {field}: the limits {low:?} and {high:?} are not sizes"));
            continue;
        };
        for (v, ok) in [(lo, true), (hi, true), (lo - 1, false), (hi + 1, false)] {
            if try_value(v) != ok {
                faults.push(format!("row {field}: check of {v} gives {}", if ok { "an error" } else { "no error" }));
            }
        }
    }
    let want: BTreeSet<String> =
        ["stream_window", "link_window", "max_streams", "frame_size", "keepalive", "dead_after"]
            .map(String::from)
            .into();
    if seen != want {
        faults.push(format!("the rows {seen:?}, the crate has {want:?}"));
    }
    check_all("Settings", faults);
}

#[test]
fn rule_ids() {
    let mut faults = Vec::new();
    let defined: Vec<u32> = WIRE
        .lines()
        .filter_map(|l| l.trim_start().strip_prefix("- **W-"))
        .filter_map(|l| l.get(..2)?.parse().ok())
        .collect();
    let want: Vec<u32> = (1..=defined.len() as u32).collect();
    if defined != want {
        faults.push(format!("the rules are not W-01 to W-{:02} in order: {defined:?}", defined.len()));
    }
    for (i, _) in WIRE.match_indices("W-") {
        let n: Option<u32> = WIRE.get(i + 2..i + 4).and_then(|d| d.parse().ok());
        if !n.is_some_and(|n| defined.contains(&n)) {
            faults.push(format!("the reference {:?} names no rule", WIRE.get(i..i + 4)));
        }
    }
    let range = format!("W-01 to W-{:02}", defined.len());
    if !README.contains(&range) {
        faults.push(format!("the README does not give the range {range}"));
    }
    let version = format!("protocol version {}", PREFACE[PREFACE.len() - 1]);
    if !WIRE.contains(&version) {
        faults.push(format!("the status line does not name the {version}"));
    }
    check_all("the rules", faults);
}
