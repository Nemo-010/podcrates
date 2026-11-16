# The wire of the link of pod-link

Status: normative. This document gives the rules of the link of
`pod-link`, protocol version 1 (the last byte of the preface). The code of
the crate in the same commit does these rules. A change of a rule, of the
order of the checks or of a constant changes this document in the same
commit. The test `tests/wire_doc.rs` compares each table of this document
with the constants and the decoder of the crate, and each rule id with
its definition.

The carriers (tcp, ws, h2, quic, udp, poll, dns, icmp, s3, split) and the
ARQ are not part of this document: the README of the crate gives their
bytes. A carrier gives the link one byte stream in each direction, in
order and with no loss.

Words of this document:

- "The end" is the end of the link that applies the rule. "The peer" is
  the other end.
- "The link fails" means: the end queues `GOAWAY` with the code
  `PROTOCOL` as its last frame, and the link ends with the error
  `Error::Frame` (a rule of the decoder) or `Error::Protocol` (a rule of
  the link).
- A rule marked "(this crate)" tells what this implementation does. A
  peer does not check it, and another implementation can do it in a
  different way.

## Rules

### The frames

- **W-01** Each end first writes the preface: the 8 bytes `PODLINK` and
  the byte 1 (the table "Constants", row `PREFACE`). When the first bytes
  from the peer are not the preface, the link fails
  (`FrameError::Preface`). The end compares each byte when it comes, so a
  wrong first byte fails before the 8 bytes come.
- **W-02** After the preface, each frame is a header of 8 bytes and a
  body. The header is the type (1 byte), the stream id (4 bytes) and the
  length of the body (3 bytes). Each number has a fixed width and is big
  endian. No number has a variable length.
- **W-03** The table "Frame types" gives the type byte, the id and the
  body of each frame. When a type byte is not in the table, the link fails
  (`FrameError::UnknownKind`). The end checks the type byte when it is the
  first byte that waits, before the header is whole.
- **W-04** A stream frame (`OPEN`, `DATA`, `CLOSE`, `RESET`) has a stream
  id that is not 0; else the link fails (`FrameError::LinkId`). A link
  frame (`PING`, `PONG`, `GOAWAY`) has the stream id 0; else the link
  fails (`FrameError::StreamId`). `WINDOW` takes each id: the id 0 is the
  link.
- **W-05** When the length of a body is not the length of its type, the
  link fails (`FrameError::BadLength`). A `DATA` body has 1 byte to
  `MAX_RECORD` bytes: an empty body fails (`FrameError::EmptyData`), and a
  longer body fails (`FrameError::TooLong`). The end checks the length in
  the header, before the body comes.
- **W-06** When the credit of a `WINDOW` is 0, the link fails
  (`FrameError::ZeroCredit`).
- **W-07** Each value of a `RESET` code and of a `GOAWAY` code is valid.
  The table "Codes" gives the codes with a name. A `RESET` code from 16
  is a code of the caller (`Stream::reset`); the protocol keeps 0 to 15.
- **W-08** After the first error, the decoder reads no more bytes and
  gives the same error again.

### The streams

- **W-09** The dialer opens the streams with odd ids, and the listener
  opens the streams with even ids. Each id that an end opens is larger
  than each id that the same end opened before. When an `OPEN` from the
  peer has the parity of the end, or an id that is not larger than the
  last id that the peer opened, the link fails.
- **W-10** (this crate) The first id of the dialer is 1, the first id of
  the listener is 2, and each next id adds 2. When no id of its parity
  is left, `Link::open` fails with `Error::IdsExhausted`.
- **W-11** When the end holds `max_streams` streams, or queued its
  `GOAWAY`, it answers an `OPEN` with `RESET` and the code `REFUSED`. The
  id of a refused stream is used: W-09 and W-15 apply to it.
- **W-12** An end does not wait for an answer to its `OPEN`: its `DATA`
  can follow at once.
- **W-13** `CLOSE` is a half close: its sender sends no more `DATA` on
  the stream. When `DATA` comes after the `CLOSE` of the peer on the same
  stream, the link fails. The other direction stays open.
- **W-14** `RESET` ends the stream in both directions. The end keeps the
  first reset of a stream, by either end. `DATA` that comes for a reset
  stream that is still in the table uses the credit of the stream and of
  the link, and the end drops it; its bytes go back to the credit of the
  link.
- **W-15** A stream existed when its id is an id of the end that is lower
  than the next id of the end, or an id of the peer that is not larger
  than the last id that the peer opened. A frame (`DATA`, `WINDOW`,
  `CLOSE`, `RESET`) of a stream that existed and is not in the table is
  dropped; the bytes of a `DATA` go back to the credit of the link. When
  a frame comes for a stream that never existed, the link fails.
- **W-16** (this crate) A drop of the handle of a stream removes the
  stream from the table. When the stream has no reset, the end sends
  `CLOSE` if it did not close its side, and `RESET` with the code
  `CANCEL` if the peer did not close its side. The bytes that wait unread
  go back to the credit of the link.

### The credit

- **W-17** Each new stream starts with a credit of `INITIAL_WINDOW` bytes
  in each direction. The link starts with a credit of `INITIAL_WINDOW`
  bytes in each direction.
- **W-18** Each byte of a `DATA` body uses one byte of the credit of its
  stream and one byte of the credit of the link. The sender sends no byte
  past either credit. When a `DATA` body is longer than the credit of the
  link or of the stream that the end gave, the link fails.
- **W-19** `WINDOW` with a stream id adds its credit to that stream;
  `WINDOW` with the id 0 adds its credit to the link. When the credit of
  a stream or of the link becomes more than `MAX_CREDIT`, the link fails.
- **W-20** (this crate) At the start, each end sends `WINDOW` 0 with
  `link_window` less `INITIAL_WINDOW`, when it is more than 0.
- **W-21** (this crate) The credit of a stream goes back when its reader
  took half the window of the stream. When the reader emptied the buffer
  of the stream at that time, the window doubles, up to `stream_window`.
  The credit of the link goes back with a credit of a stream, or when
  `INITIAL_WINDOW` bytes wait. A stream that received `CLOSE` or a reset
  gives no more credit of its own.

### The end of the link

- **W-22** `GOAWAY` is the last frame of its sender. A `GOAWAY` with the
  code `NORMAL` ends the link with `Error::Closed`; a `GOAWAY` with each
  other code ends the link with `Error::PeerGoAway`.
- **W-23** (this crate) `Link::close` sends the frames that wait, then
  `GOAWAY` with the code `NORMAL`. Then the end waits at most 2 s for the
  peer to end the carrier, and ends the link with `Error::Closed`.
- **W-24** An end that fails the link for a broken rule sends `GOAWAY`
  with the code `PROTOCOL` as its last frame (the words "the link fails").
- **W-25** When the carrier ends before a `GOAWAY` of the peer, and
  before the carrier took the `GOAWAY` of the end, the link ends with
  `Error::CarrierEnded`.

### The keepalive

- **W-26** An end answers each `PING` with a `PONG` that has the same 8
  bytes. The value of a `PING` has no other meaning. A `PONG` whose value
  the end did not send is not an error.
- **W-27** (this crate) The value of each `PING` is a counter from 0. A
  `PONG` with the value of the last `PING` gives the round trip time
  (`Link::rtt`).
- **W-28** The end sends a `PING` after `keepalive` of silence. The
  section "Time" gives the start of each timer.
- **W-29** After `dead_after` of silence, the end ends the link with
  `Error::Dead`. It sends no `GOAWAY`.

### The memory

- **W-30** At most `CONTROL_LIMIT` frames that are not `DATA` wait for
  the carrier. When one more frame comes into the queue (an answer to a
  peer that sends and does not read), the link fails.
- **W-31** (this crate) At most `queue_limit` bytes of `DATA` wait for the
  carrier: the larger of 4 times `frame_size` and `MIN_QUEUE`. A writer
  waits for room.
- **W-32** (this crate) The writer sends `WINDOW`, `PING` and `PONG`
  before the other frames. It sends the other frames in the order of the
  queue, so the frames of one stream keep their order.

## The order of the checks

When a frame breaks two rules, the first check in this order gives the
error.

### The decoder

1. The preface, one byte at a time (W-01).
2. When fewer than 8 bytes wait: a first byte that is not a type
   (W-03).
3. When the header is whole: the type (W-03), then the id 0 on a stream
   frame (W-04), then an id on a link frame (W-04), then the length: a
   fixed length (`BadLength`), or for `DATA` an empty body (`EmptyData`)
   then a body over `MAX_RECORD` (`TooLong`) (W-05).
4. When the body is whole: the credit 0 of a `WINDOW` (W-06).

### The link, for each frame type

- `OPEN`: the parity and the order of the id (W-09), then the limit of
  streams and the `GOAWAY` of the end (W-11), then the limit of the queue
  for the `RESET` (W-30).
- `DATA`: the credit of the link (W-18), then the table: a stream that
  existed (W-15) or that never existed (W-15), then a `CLOSE` of the
  peer (W-13), then the credit of the stream (W-18), then a reset of the
  stream (W-14).
- `WINDOW` 0: the limit of credit of the link (W-19).
- `WINDOW` of a stream: the table (W-15), then the limit of credit of the
  stream (W-19).
- `CLOSE` and `RESET`: the table (W-15).
- `PING`: the limit of the queue (W-30).
- `PONG` and `GOAWAY`: no check.

## Time

- **W-33** Each duration T of a timer fires at the first moment when
  `now >= t0 + T`. At exactly `t0 + T` the timer fires.
- **W-34** The t0 of `dead_after` is the last moment when the end read
  one or more bytes from the carrier. The t0 of `keepalive` is the later
  of that moment and of the last `PING` of the end.
- **W-35** (this crate) When both timers fire at the same moment, the end
  first applies `dead_after`: the link ends, and no `PING` goes.

## Constants

### Frame types

| Type | Frame | Id | Body bytes | Body |
| --- | --- | --- | --- | --- |
| 1 | `OPEN` | a stream | 0 | none: the new stream |
| 2 | `DATA` | a stream | 1 to 1 MiB | the bytes of the stream |
| 3 | `WINDOW` | a stream or 0 | 4 | the credit, not 0 |
| 4 | `CLOSE` | a stream | 0 | none: the sender writes no more |
| 5 | `RESET` | a stream | 4 | the code |
| 6 | `PING` | 0 | 8 | an opaque value |
| 7 | `PONG` | 0 | 8 | the value of the `PING` |
| 8 | `GOAWAY` | 0 | 4 | the code |

### Codes

| Frame | Code | Name | What |
| --- | --- | --- | --- |
| `RESET` | 0 | `CANCEL` | the end of the stream at the wish of its owner |
| `RESET` | 1 | `REFUSED` | the peer did not take the stream (W-11); a later open can work |
| `RESET` | 2 | `PROTOCOL` | the stream broke the protocol |
| `GOAWAY` | 0 | `NORMAL` | the end of the link at the wish of its owner |
| `GOAWAY` | 1 | `PROTOCOL` | the peer broke the protocol (W-24) |

### Limits

| Name | Value | What |
| --- | --- | --- |
| `PREFACE` | `50 4f 44 4c 49 4e 4b 01` | the first bytes of each end (W-01) |
| `HEADER` | 8 | the bytes of a frame header (W-02) |
| `MAX_RECORD` | 1 MiB | the largest `DATA` body (W-05) |
| `INITIAL_WINDOW` | 16 KiB | the first credit of a stream and of the link (W-17) |
| `MIN_WINDOW` | 16 KiB | the smallest window of a setting |
| `MAX_WINDOW` | 8 MiB | the largest window of a setting |
| `MAX_CREDIT` | 4294967295 | the most credit of a stream or of the link (W-19) |
| `MAX_STREAMS` | 4096 | the largest `max_streams` |
| `MIN_FRAME` | 1 KiB | the smallest `frame_size` |
| `CONTROL_LIMIT` | 8192 | the frames that are not `DATA` that wait (W-30) |
| `MIN_QUEUE` | 64 KiB | the smallest queue of `DATA` (W-31) |

### Settings

Each end has its own settings; the peer does not know them.
`Settings::check` refuses a value out of its limits.

| Field | Default | Smallest | Largest | What |
| --- | --- | --- | --- | --- |
| `stream_window` | 1 MiB | 16 KiB | 8 MiB | the largest receive window of a stream (W-21) |
| `link_window` | 8 MiB | 16 KiB | 8 MiB | the most bytes of all streams that the end holds unread; not less than `stream_window` |
| `max_streams` | 256 | 1 | 4096 | the streams of the link at the end, from both ends (W-11) |
| `frame_size` | 16 KiB | 1 KiB | 1 MiB | the largest `DATA` body that the end sends |
| `keepalive` | 10 s | - | - | the silence before the end sends a `PING` (W-28); more than 0 |
| `dead_after` | 30 s | - | - | the silence after which the link ends (W-29); more than `keepalive` |

A stream that stops reading holds at most its own window of the window of
the link, and the other streams use the rest. With the defaults, seven
stalled streams that grew to 1 MiB leave 1 MiB to the others, and a
stream that stalls before it grows holds 16 KiB.
