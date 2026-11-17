//! The Cap'n Proto wire format: the parts that the tunnel protocol uses.
//!
//! Reference: <https://capnproto.org/encoding.html>.
//!
//! * A message is a list of segments. Each segment is a list of 64-bit words.
//!   The framing is: `u32` (segment count minus 1), one `u32` size in words for
//!   each segment, padding to 8 bytes, then the segments.
//! * The first word of segment 0 is the root pointer.
//! * A struct has a data section (words) and a pointer section (pointers).
//! * Pointer kinds: struct (0), list (1), far (2), other/capability (3).
//!
//! [`Builder`] writes one segment. [`Message`] reads any number of segments,
//! with far pointers, and limits the work that a hostile message can cause.

mod reader;

use crate::fail::{IoFail, OrFail, Result, bail};
use pod_core::{Class, Stage};

/// The largest message that is read, in bytes.
pub const MAX_MESSAGE_BYTES: usize = 64 << 20;
/// The largest number of segments that is read.
pub const MAX_SEGMENTS: usize = 512;
/// The deepest pointer nesting that is followed.
const MAX_DEPTH: u32 = 64;

// ── list element sizes ──────────────────────────────────────────────────────

const ELEM_BYTE: u64 = 2;
const ELEM_POINTER: u64 = 6;
const ELEM_COMPOSITE: u64 = 7;

/// A struct in a [`Builder`]: where its sections are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StructRef {
    data: usize,
    data_words: u16,
    ptrs: usize,
    ptr_count: u16,
}

/// Writes one message in one segment.
#[derive(Debug, Default)]
pub struct Builder {
    words: Vec<u64>,
}

impl Builder {
    /// Make a message. Word 0 is the root pointer.
    pub fn new() -> Self {
        Self { words: vec![0] }
    }

    fn alloc(&mut self, words: usize) -> usize {
        let start = self.words.len();
        self.words.resize(start + words, 0);
        start
    }

    fn struct_pointer(at: usize, target: usize, data: u16, ptrs: u16) -> u64 {
        let offset = target as i64 - at as i64 - 1;
        ((offset as u64 & 0x3fff_ffff) << 2) | (u64::from(data) << 32) | (u64::from(ptrs) << 48)
    }

    fn list_pointer(at: usize, target: usize, elem: u64, count: u64) -> u64 {
        let offset = target as i64 - at as i64 - 1;
        1 | ((offset as u64 & 0x3fff_ffff) << 2) | (elem << 32) | (count << 35)
    }

    fn new_struct(&mut self, data: u16, ptrs: u16) -> StructRef {
        let start = self.alloc(usize::from(data) + usize::from(ptrs));
        StructRef { data: start, data_words: data, ptrs: start + usize::from(data), ptr_count: ptrs }
    }

    /// Make the root struct.
    pub fn init_root(&mut self, data: u16, ptrs: u16) -> StructRef {
        let root = self.new_struct(data, ptrs);
        self.words[0] = Self::struct_pointer(0, root.data, data, ptrs);
        root
    }

    fn pointer_slot(s: StructRef, index: u16) -> usize {
        assert!(index < s.ptr_count, "pointer index {index} out of range");
        s.ptrs + usize::from(index)
    }

    /// Make a struct in pointer `index` of `s`.
    pub fn init_struct(&mut self, s: StructRef, index: u16, data: u16, ptrs: u16) -> StructRef {
        let slot = Self::pointer_slot(s, index);
        let child = self.new_struct(data, ptrs);
        self.words[slot] = Self::struct_pointer(slot, child.data, data, ptrs);
        child
    }

    /// Make a list of `count` structs in pointer `index` of `s`.
    pub fn init_struct_list(&mut self, s: StructRef, index: u16, count: usize, data: u16, ptrs: u16) -> Vec<StructRef> {
        let slot = Self::pointer_slot(s, index);
        let size = usize::from(data) + usize::from(ptrs);
        let tag = self.alloc(1 + count * size);
        self.words[slot] = Self::list_pointer(slot, tag, ELEM_COMPOSITE, (count * size) as u64);
        // The tag word has the struct-pointer form; its offset is the count.
        self.words[tag] = ((count as u64 & 0x3fff_ffff) << 2) | (u64::from(data) << 32) | (u64::from(ptrs) << 48);
        (0..count)
            .map(|i| {
                let start = tag + 1 + i * size;
                StructRef { data: start, data_words: data, ptrs: start + usize::from(data), ptr_count: ptrs }
            })
            .collect()
    }

    fn put_bytes_at(&mut self, slot: usize, bytes: &[u8], extra_nul: bool) {
        let len = bytes.len() + usize::from(extra_nul);
        let start = self.alloc(len.div_ceil(8));
        self.words[slot] = Self::list_pointer(slot, start, ELEM_BYTE, len as u64);
        for (i, byte) in bytes.iter().enumerate() {
            let word = start + i / 8;
            self.words[word] |= u64::from(*byte) << ((i % 8) * 8);
        }
    }

    /// Set pointer `index` of `s` to a Text value (a byte list with a NUL).
    pub fn set_text(&mut self, s: StructRef, index: u16, text: &str) {
        let slot = Self::pointer_slot(s, index);
        self.put_bytes_at(slot, text.as_bytes(), true);
    }

    /// Set pointer `index` of `s` to a Data value.
    pub fn set_data(&mut self, s: StructRef, index: u16, data: &[u8]) {
        let slot = Self::pointer_slot(s, index);
        self.put_bytes_at(slot, data, false);
    }

    /// Set pointer `index` of `s` to a `List(Text)`.
    pub fn set_text_list(&mut self, s: StructRef, index: u16, items: &[String]) {
        let slot = Self::pointer_slot(s, index);
        let start = self.alloc(items.len());
        self.words[slot] = Self::list_pointer(slot, start, ELEM_POINTER, items.len() as u64);
        for (i, item) in items.iter().enumerate() {
            self.put_bytes_at(start + i, item.as_bytes(), true);
        }
    }

    /// Set pointer `index` of `s` to capability `cap` of the cap table.
    pub fn set_capability(&mut self, s: StructRef, index: u16, cap: u32) {
        let slot = Self::pointer_slot(s, index);
        self.words[slot] = 3 | (u64::from(cap) << 32);
    }

    fn data_byte(&mut self, s: StructRef, byte: usize) -> (usize, u32) {
        assert!(byte < usize::from(s.data_words) * 8, "data offset {byte} out of range");
        (s.data + byte / 8, ((byte % 8) * 8) as u32)
    }

    fn set_bits(&mut self, s: StructRef, byte: usize, width: u32, value: u64) {
        let (word, shift) = self.data_byte(s, byte);
        let mask = if width == 64 { u64::MAX } else { ((1u64 << width) - 1) << shift };
        self.words[word] = (self.words[word] & !mask) | ((value << shift) & mask);
    }

    /// Set the `u8` field at element index `index` (byte `index`).
    pub fn set_u8(&mut self, s: StructRef, index: usize, value: u8) {
        self.set_bits(s, index, 8, u64::from(value));
    }

    /// Set the `u16` field at element index `index` (byte `2 * index`).
    pub fn set_u16(&mut self, s: StructRef, index: usize, value: u16) {
        self.set_bits(s, index * 2, 16, u64::from(value));
    }

    /// Set the `u32` field at element index `index` (byte `4 * index`).
    pub fn set_u32(&mut self, s: StructRef, index: usize, value: u32) {
        self.set_bits(s, index * 4, 32, u64::from(value));
    }

    /// Set the `u64` field at element index `index` (word `index`).
    pub fn set_u64(&mut self, s: StructRef, index: usize, value: u64) {
        let (word, _) = self.data_byte(s, index * 8);
        self.words[word] = value;
    }

    /// Set the Bool field at bit `bit`.
    pub fn set_bool(&mut self, s: StructRef, bit: usize, value: bool) {
        let (word, _) = self.data_byte(s, bit / 8);
        let mask = 1u64 << (bit % 64);
        if value {
            self.words[word] |= mask;
        } else {
            self.words[word] &= !mask;
        }
    }

    /// The framed message: segment table and the segment.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(8 + self.words.len() * 8);
        out.extend_from_slice(&0u32.to_le_bytes());
        out.extend_from_slice(&(self.words.len() as u32).to_le_bytes());
        for word in &self.words {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out
    }
}

// ── reading ─────────────────────────────────────────────────────────────────

/// A received message.
#[derive(Debug)]
pub struct Message {
    segments: Vec<Vec<u64>>,
    budget: std::sync::atomic::AtomicU64,
}

/// A struct in a [`Message`].
#[derive(Clone, Copy, Debug)]
pub struct StructReader<'a> {
    msg: &'a Message,
    segment: usize,
    data: usize,
    data_words: u16,
    ptrs: usize,
    ptr_count: u16,
    depth: u32,
}

/// What a pointer refers to.
#[derive(Clone, Copy, Debug)]
enum Target {
    Null,
    Struct {
        segment: usize,
        start: usize,
        data: u16,
        ptrs: u16,
    },
    List {
        segment: usize,
        start: usize,
        elem: u64,
        count: u64,
        /// Only for a composite list: the tag word.
        tag: u64,
    },
    Capability(u32),
}

/// Read the framing of one message from `bytes`. Return the segment words
/// and the number of bytes that the message used.
fn split_segments(bytes: &[u8]) -> Result<Option<(Vec<Vec<u64>>, usize)>> {
    if bytes.len() < 4 {
        return Ok(None);
    }
    let count = u32::from_le_bytes(bytes[0..4].try_into().unwrap()) as usize + 1;
    if count > MAX_SEGMENTS {
        bail!(Stage::EdgeStream, Class::Protocol, "the message has {count} segments");
    }
    let table = 4 + count * 4;
    let header = table + (table % 8);
    if bytes.len() < table {
        return Ok(None);
    }
    let mut sizes = Vec::with_capacity(count);
    let mut total = 0usize;
    for i in 0..count {
        let at = 4 + i * 4;
        let size = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
        total = total.saturating_add(size.saturating_mul(8));
        sizes.push(size);
    }
    if total > MAX_MESSAGE_BYTES {
        bail!(Stage::EdgeStream, Class::Protocol, "the message is {total} bytes");
    }
    if bytes.len() < header + total {
        return Ok(None);
    }
    let mut segments = Vec::with_capacity(count);
    let mut at = header;
    for size in sizes {
        let words = bytes[at..at + size * 8].as_chunks::<8>().0.iter().map(|c| u64::from_le_bytes(*c)).collect();
        segments.push(words);
        at += size * 8;
    }
    Ok(Some((segments, header + total)))
}

impl Message {
    fn new(segments: Vec<Vec<u64>>) -> Self {
        let words: u64 = segments.iter().map(|s| s.len() as u64).sum();
        Self {
            segments,
            // Each word may be read a few times; more than that is an attack
            // (pointers that point at the same data again and again).
            budget: std::sync::atomic::AtomicU64::new(words.saturating_mul(8).max(1024)),
        }
    }

    /// Parse one framed message from the start of `bytes`. Return `None` when
    /// `bytes` does not hold a full message yet.
    pub fn parse(bytes: &[u8]) -> Result<Option<(Self, usize)>> {
        Ok(split_segments(bytes)?.map(|(segments, used)| (Self::new(segments), used)))
    }

    /// Read one framed message from a tokio reader.
    pub async fn read<R>(reader: &mut R) -> Result<Option<Self>>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut first = [0u8; 4];
        match reader.read_exact(&mut first).await {
            Ok(_) => {}
            Err(err) if err.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
            Err(err) => {
                return Err(crate::fail::caused(Stage::EdgeStream, Class::of_io(err.kind()), "reading a message", err));
            }
        }
        Self::read_after(first, reader).await.map(Some)
    }

    async fn read_after<R>(first: [u8; 4], reader: &mut R) -> Result<Self>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let count = u32::from_le_bytes(first) as usize + 1;
        if count > MAX_SEGMENTS {
            bail!(Stage::EdgeStream, Class::Protocol, "the message has {count} segments");
        }
        let table = 4 + count * 4;
        let mut header = vec![0u8; table + (table % 8) - 4];
        reader.read_exact(&mut header).await.io_fail(Stage::EdgeStream, "segment table")?;
        let mut bytes = first.to_vec();
        bytes.extend_from_slice(&header);
        let mut total = 0usize;
        for i in 0..count {
            let at = 4 + i * 4;
            let size = u32::from_le_bytes(bytes[at..at + 4].try_into().unwrap()) as usize;
            total = total.saturating_add(size.saturating_mul(8));
        }
        if total > MAX_MESSAGE_BYTES {
            bail!(Stage::EdgeStream, Class::Protocol, "the message is {total} bytes");
        }
        let start = bytes.len();
        bytes.resize(start + total, 0);
        reader.read_exact(&mut bytes[start..]).await.io_fail(Stage::EdgeStream, "segments")?;
        let (segments, _) = split_segments(&bytes)?.or_fail(Stage::EdgeStream, Class::Protocol, "short message")?;
        Ok(Self::new(segments))
    }

    /// Read one framed message from a `futures` reader.
    pub async fn read_futures<R>(reader: &mut R) -> Result<Self>
    where
        R: futures::io::AsyncRead + Unpin,
    {
        let mut compat = tokio_util::compat::FuturesAsyncReadCompatExt::compat(reader);
        let mut first = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut compat, &mut first)
            .await
            .io_fail(Stage::EdgeStream, "segment count")?;
        Self::read_after(first, &mut compat).await
    }

    /// The root struct.
    pub fn root(&self) -> Result<StructReader<'_>> {
        let root = StructReader { msg: self, segment: 0, data: 0, data_words: 0, ptrs: 0, ptr_count: 1, depth: 0 };
        root.get_struct(0)?.or_fail(Stage::EdgeStream, Class::Protocol, "the message has no root")
    }

    /// Take `words` from the read budget.
    fn spend(&self, words: u64) -> Result<()> {
        use std::sync::atomic::Ordering;
        let mut left = self.budget.load(Ordering::Relaxed);
        loop {
            let Some(next) = left.checked_sub(words) else {
                bail!(Stage::EdgeStream, Class::Protocol, "the message exceeds the read limit");
            };
            match self.budget.compare_exchange_weak(left, next, Ordering::Relaxed, Ordering::Relaxed) {
                Ok(_) => return Ok(()),
                Err(actual) => left = actual,
            }
        }
    }

    fn word(&self, segment: usize, index: usize) -> Result<u64> {
        self.spend(1)?;
        self.segments.get(segment).and_then(|s| s.get(index)).copied().or_fail(
            Stage::EdgeStream,
            Class::Protocol,
            format!("word {index} of segment {segment} is out of range"),
        )
    }

    fn check_range(&self, segment: usize, start: usize, words: u64) -> Result<()> {
        let len =
            self.segments.get(segment).or_fail(Stage::EdgeStream, Class::Protocol, "no such segment")?.len() as u64;
        if start as u64 + words > len {
            bail!(Stage::EdgeStream, Class::Protocol, "an object is outside its segment");
        }
        self.spend(words)
    }

    /// Follow the pointer at `segment[at]`.
    fn follow(&self, segment: usize, at: usize) -> Result<Target> {
        let mut pointer = self.word(segment, at)?;
        let mut segment = segment;
        let mut at = at;
        if pointer == 0 {
            return Ok(Target::Null);
        }
        if pointer & 3 == 2 {
            // A far pointer: the landing pad is in another segment.
            let double = pointer & 4 != 0;
            let pad = ((pointer >> 3) & 0x1fff_ffff) as usize;
            let pad_segment = (pointer >> 32) as usize;
            if !double {
                segment = pad_segment;
                at = pad;
                pointer = self.word(segment, at)?;
            } else {
                // Two words: a far pointer to the content, then a tag.
                let far = self.word(pad_segment, pad)?;
                let tag = self.word(pad_segment, pad + 1)?;
                if far & 3 != 2 {
                    bail!(Stage::EdgeStream, Class::Protocol, "a double-far landing pad is not a far pointer");
                }
                let content_segment = (far >> 32) as usize;
                let content = ((far >> 3) & 0x1fff_ffff) as usize;
                return self.decode(content_segment, content, tag);
            }
        }
        let offset = (((pointer as u32) as i32) >> 2) as i64;
        let start = at as i64 + 1 + offset;
        if start < 0 {
            bail!(Stage::EdgeStream, Class::Protocol, "a pointer points before its segment");
        }
        self.decode(segment, start as usize, pointer)
    }

    fn decode(&self, segment: usize, start: usize, pointer: u64) -> Result<Target> {
        match pointer & 3 {
            0 => {
                let data = ((pointer >> 32) & 0xffff) as u16;
                let ptrs = (pointer >> 48) as u16;
                self.check_range(segment, start, u64::from(data) + u64::from(ptrs))?;
                Ok(Target::Struct { segment, start, data, ptrs })
            }
            1 => {
                let elem = (pointer >> 32) & 7;
                let count = pointer >> 35;
                let words = match elem {
                    0 => 0,
                    1 => count.div_ceil(64),
                    2 => count.div_ceil(8),
                    3 => count.div_ceil(4),
                    4 => count.div_ceil(2),
                    5 | 6 => count,
                    _ => count + 1,
                };
                self.check_range(segment, start, words)?;
                let tag = if elem == ELEM_COMPOSITE { self.word(segment, start)? } else { 0 };
                Ok(Target::List { segment, start, elem, count, tag })
            }
            3 => {
                if pointer & 0xffff_fffc != 0 {
                    bail!(Stage::EdgeStream, Class::Protocol, "an unknown kind of other pointer");
                }
                Ok(Target::Capability((pointer >> 32) as u32))
            }
            _ => bail!(Stage::EdgeStream, Class::Protocol, "a far pointer points to a far pointer"),
        }
    }
}

#[cfg(test)]
mod tests;
