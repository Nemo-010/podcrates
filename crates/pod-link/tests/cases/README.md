# The scripted cases of the link

Each file `NAME.case` is one case: one end of a link against a peer whose
bytes the case gives, on a paused clock. `tests/cases.rs` runs each case,
and the file `count` gives the number of cases. `WIRE.md` gives the rules
(W-01 to W-35) and the table of the classes of defects.

A line that starts with `#` is a comment. The header comes first, one
`key: value` on each line:

| Key | Value |
| --- | --- |
| `role` | `dialer` or `listener`: the role of the end under test (default `listener`) |
| `settings` | `FIELD=VALUE ...` of the end; a duration is `2s` or `1500ms` |
| `ring` | the bytes of the memory carrier in each direction (default 1 MiB) |
| `rules` | the rules of `WIRE.md` that the case holds |
| `class` | the class of defect: `credit`, `streams`, `close`, `time` or `memory` |

The steps follow, one on each line. A frame is in its `Debug` form, and
the body of a `Data` is HEX: pieces joined by a dot, each hex digits or
hex digits and `*N` for N copies (`61*16384`).

| Step | What |
| --- | --- |
| `send FRAME` | the peer writes the frame |
| `send-many N FRAME` | the peer writes the frame N times |
| `expect FRAME` | the next frame of the end is this frame |
| `expect-quiet` | the end sends no frame |
| `expect-eof` | the end sends no frame and ends its carrier |
| `expect-end ERROR` | the link ended; its error in the `Debug` form starts with ERROR |
| `open ID` | the end opens a stream, and gets the id ID |
| `accept ID` | the end accepts the stream ID |
| `write ID N` | the end writes N bytes `61` on the stream; a write that waits for credit goes on at each later step |
| `read ID N` | the end reads N bytes of the stream, which are there |
| `read-end ID` | a read of the stream gives its end |
| `read-fails ID KIND` | a read of the stream fails with the `io::ErrorKind` KIND |
| `close ID` | the end closes its side of the stream |
| `reset ID CODE` | the end resets the stream with CODE |
| `drop ID` | the end drops the handle of the stream |
| `advance DURATION` | the clock moves |

The runner:

- applies the settings before the first step;
- runs the steps in order, and gives the file and the line of a failure;
- moves the clock only at `advance`;
- lets the end run until it does nothing more before each check;
- takes the end of the link as an event: after the end, only `expect`
  steps can follow until an `expect-end`;
- fails when the link ended and no `expect-end` covered it;
- fails when `count` and the number of cases differ.
