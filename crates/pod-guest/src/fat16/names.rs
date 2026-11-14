//! The names of the root: 8.3 names, and VFAT long names with their 8.3
//! alias.
//!
//! A long name goes in long-name entries before its 8.3 entry: the last
//! part first, with the bit `0x40` in its sequence number; 13 UCS-2 units
//! in each entry; the checksum of the 11 bytes of the alias in each one.
//! A reader takes a long name only when each entry of the chain is there,
//! in order, with the checksum of the 8.3 entry after it.

use pod_core::Class;

use crate::{Result, failure};

/// The longest long name, in characters: three long-name entries.
pub const MAX_LONG_NAME: usize = 32;
/// The UCS-2 units of one long-name entry.
const UNITS: usize = 13;
/// The places of the 13 units in a long-name entry.
const UNIT_AT: [usize; UNITS] = [1, 3, 5, 7, 9, 14, 16, 18, 20, 22, 24, 28, 30];
/// The attribute byte of a long-name entry.
pub(super) const LONG_ATTR: u8 = 0x0F;

/// The name that a caller gives to `put`, `get` or `remove`.
pub(super) enum Name {
    /// An 8.3 name: its 11 upper-case bytes and its case byte.
    Short([u8; 11], u8),
    /// A long name, as the caller wrote it.
    Long(String),
}

/// Read `name`: an 8.3 name, else a long name of 1 to [`MAX_LONG_NAME`]
/// characters, else a [`Class::Usage`] failure that names it.
pub(super) fn parse(name: &str) -> Result<Name> {
    match parse_short(name) {
        Ok((bare, case)) => Ok(Name::Short(bare, case)),
        Err(short) => {
            check_long(name).map_err(|why| {
                failure(Class::Usage, format!("{name:?} is not an 8.3 name ({short}) and not a long name: {why}"))
            })?;
            Ok(Name::Long(name.to_string()))
        }
    }
}

/// Why `name` is not a long name: its length, a control character, a
/// character that FAT refuses, or a space or a dot at its end.
fn check_long(name: &str) -> std::result::Result<(), String> {
    let count = name.chars().count();
    if count == 0 || count > MAX_LONG_NAME {
        return Err(format!("1 to {MAX_LONG_NAME} characters"));
    }
    if let Some(c) = name.chars().find(|c| c.is_control() || "\"*/:<>?\\|".contains(*c) || c.len_utf16() > 1) {
        return Err(format!("the character {c:?}"));
    }
    if name.ends_with([' ', '.']) || name.trim_start_matches('.').is_empty() {
        return Err("a space or a dot at the end, or only dots".to_string());
    }
    Ok(())
}

/// The checksum of an 8.3 name in each long-name entry before it: a rotate
/// right and an add, byte by byte.
pub fn checksum(short: &[u8; 11]) -> u8 {
    short.iter().fold(0u8, |sum, b| ((sum & 1) << 7).wrapping_add(sum >> 1).wrapping_add(*b))
}

/// The 8.3 alias `BASIS~N.EXT` of a long name, with the first `N` from 1
/// that `taken` does not hold. The basis is the upper-case name with no
/// space and no dot but the last; a character outside the 8.3 set is `_`.
pub(super) fn alias(long: &str, taken: impl Fn(&[u8; 11]) -> bool) -> Result<[u8; 11]> {
    let clean = |s: &str| -> Vec<u8> {
        s.chars()
            .filter(|c| *c != ' ' && *c != '.')
            .map(|c| {
                let u = c.to_ascii_uppercase();
                if u.is_ascii_alphanumeric() || "$%'-_@~!#&(){}^".contains(u) { u as u8 } else { b'_' }
            })
            .collect()
    };
    let (base, ext) = match long.rsplit_once('.') {
        Some((b, e)) if !b.trim_start_matches('.').is_empty() => (clean(b), clean(e)),
        _ => (clean(long), Vec::new()),
    };
    for n in 1u32..1_000_000 {
        let tail = format!("~{n}");
        let keep = base.len().min(8 - tail.len());
        let mut out = [b' '; 11];
        out[..keep].copy_from_slice(&base[..keep]);
        out[keep..keep + tail.len()].copy_from_slice(tail.as_bytes());
        for (i, b) in ext.iter().take(3).enumerate() {
            out[8 + i] = *b;
        }
        if !taken(&out) {
            return Ok(out);
        }
    }
    Err(failure(Class::Unavailable, format!("no free 8.3 alias for {long:?}")))
}

/// The long-name entries of `long` for the alias `short`, in the order of
/// the directory: the last part first.
pub(super) fn long_entries(long: &str, short: &[u8; 11]) -> Vec<[u8; 32]> {
    let units: Vec<u16> = long.encode_utf16().collect();
    let count = units.len().div_ceil(UNITS);
    let sum = checksum(short);
    let mut out = Vec::with_capacity(count);
    for part in (0..count).rev() {
        let mut e = [0u8; 32];
        // The 1-based number of the part; the last part has the bit 0x40.
        e[0] = (part + 1) as u8 | if part + 1 == count { 0x40 } else { 0 };
        e[11] = LONG_ATTR;
        e[13] = sum;
        for (k, at) in UNIT_AT.iter().enumerate() {
            // A NUL ends a name that does not fill its last entry, and
            // 0xFFFF fills the rest.
            let unit = match units.get(part * UNITS + k) {
                Some(u) => *u,
                None if part * UNITS + k == units.len() => 0x0000,
                None => 0xFFFF,
            };
            e[*at..*at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        out.push(e);
    }
    out
}

/// The long name of the chain `entries` (in the order of the directory)
/// before the 8.3 entry `short`; `None` when the chain is not whole, not in
/// order, or has another checksum.
pub(super) fn read_long(entries: &[[u8; 32]], short: &[u8; 11]) -> Option<String> {
    let count = entries.len();
    let sum = checksum(short);
    let mut units = Vec::with_capacity(count * UNITS);
    for (i, e) in entries.iter().rev().enumerate() {
        let want = (i + 1) as u8 | if i + 1 == count { 0x40 } else { 0 };
        if e[0] != want || e[11] != LONG_ATTR || e[13] != sum {
            return None;
        }
        for at in UNIT_AT {
            units.push(u16::from_le_bytes([e[at], e[at + 1]]));
        }
    }
    let end = units.iter().position(|u| *u == 0x0000 || *u == 0xFFFF).unwrap_or(units.len());
    String::from_utf16(&units[..end]).ok().filter(|s| !s.is_empty())
}

/// `(the name in 11 upper-case bytes, the case byte)` of an 8.3 name, or
/// why it is not one.
pub(super) fn parse_short(name: &str) -> std::result::Result<([u8; 11], u8), &'static str> {
    let (base, ext) = match name.split_once('.') {
        Some((b, e)) => (b, e),
        None => (name, ""),
    };
    if ext.contains('.') {
        return Err("more than one dot");
    }
    if base.is_empty() || base.len() > 8 || ext.len() > 3 {
        return Err("8 characters then 3, at most");
    }
    let ok = |s: &str| s.bytes().all(|c| c.is_ascii_alphanumeric() || b"$%'-_@~!#&(){}^".contains(&c));
    if !ok(base) || !ok(ext) {
        return Err("a character outside the 8.3 set");
    }
    let mut out = [b' '; 11];
    for (i, c) in base.bytes().enumerate() {
        out[i] = c.to_ascii_uppercase();
    }
    for (i, c) in ext.bytes().enumerate() {
        out[8 + i] = c.to_ascii_uppercase();
    }
    // The "NT case" byte: Windows shows the base in lower case when bit 3 is
    // set, and the extension when bit 4 is set. With it, a name comes back
    // from the volume as the caller wrote it.
    let lower_only = |s: &str| s.bytes().any(|c| c.is_ascii_lowercase()) && !s.bytes().any(|c| c.is_ascii_uppercase());
    let mut case = 0u8;
    if lower_only(base) {
        case |= 0x08;
    }
    if lower_only(ext) {
        case |= 0x10;
    }
    Ok((out, case))
}

/// The 8.3 name of an entry, with its case byte.
pub(super) fn render_short(e: &[u8; 32]) -> String {
    let mut base = String::from_utf8_lossy(&e[0..8]).trim_end().to_string();
    let mut ext = String::from_utf8_lossy(&e[8..11]).trim_end().to_string();
    if e[12] & 0x08 != 0 {
        base = base.to_ascii_lowercase();
    }
    if e[12] & 0x10 != 0 {
        ext = ext.to_ascii_lowercase();
    }
    if ext.is_empty() { base } else { format!("{base}.{ext}") }
}
