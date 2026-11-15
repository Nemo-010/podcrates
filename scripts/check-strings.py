#!/usr/bin/env python3
"""Check the strings of a release binary for the text rules of a command
line (the owner's ruling "The text of a command line"; pod-manual, T-700).

  python3 -I scripts/check-strings.py [--plant] BINARY...

The check reads the section `.rodata` of each ELF file: the section where
the compiler puts the string literals. It takes each run of text there: a
run of printable ASCII, tabs, newlines and valid UTF-8 sequences, at least
MIN characters long. It fails on:

* an emoji or a pictograph, or a bidirectional control, in a run;
* a work id in a run that reads as prose (PROSE: three words of letters,
  each between spaces): T-NNN, COORD-NNN, Q-AN, CNNN or QNN as a word, #NNN as a word
  or after a lower-case name (podnet#584).

What it does not check, and why: a byte that is not UTF-8 and a control
character are everywhere in the binary data of the section; an escape
sequence of a terminal is in the colour table of a library (anstyle of
clap), which writes it only on a terminal; the length of a sentence cannot
be read, since the compiler joins the literals with no separator. The tests
of pod-manual check those over the model and the literals of the program. A run of a
library that breaks a rule and that no program prints is in ALLOWED, with
the reason.

--plant writes a copy of each binary with a planted text in its `.rodata`
(an emoji and a work id) and checks the copy: the run must then exit 1.

Exit 0: no fault. Exit 1: a fault, one line for each. Exit 2: a file that
is not ELF, or that cannot be read.
"""

import re
import struct
import sys
import tempfile
from pathlib import Path

MIN = 6
PROSE = re.compile(r"(?:(?:^|\s)[A-Za-z]{2,}[.,;:]?(?=\s|$).*?){3}", re.S)
WORK_ID = re.compile(
    r"(?<![A-Za-z0-9_-])(T-\d+|COORD-\d+|Q-A\d+|[CQ]\d+|#\d+)(?![A-Za-z])"
    r"|(?<=[a-z])#\d+(?![A-Za-z])"
)
# (a regular expression of a run, the reason): a run of a library that no
# program prints. Each entry needs a reason.
ALLOWED = []


def emoji(c: int) -> bool:
    return (
        0x1F000 <= c <= 0x1FAFF or 0x2600 <= c <= 0x27BF or 0x2B00 <= c <= 0x2BFF or 0x2300 <= c <= 0x23FF
        or 0xFE00 <= c <= 0xFE0F or c in (0x200D, 0x20E3, 0x3030, 0x303D, 0x3297, 0x3299)
        or 0xE0020 <= c <= 0xE007F
    )


def bidi(c: int) -> bool:
    return 0x202A <= c <= 0x202E or 0x2066 <= c <= 0x2069 or c in (0x200E, 0x200F, 0x061C)


def rodata(data: bytes) -> tuple[int, int]:
    """The offset and the size of `.rodata` in an ELF file."""
    if data[:4] != b"\x7fELF":
        raise ValueError("not an ELF file")
    wide, order = data[4] == 2, "<" if data[5] == 1 else ">"
    if wide:
        shoff, = struct.unpack_from(order + "Q", data, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x3A)
    else:
        shoff, = struct.unpack_from(order + "I", data, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from(order + "HHH", data, 0x2E)

    def section(i):
        at = shoff + i * shentsize
        if wide:
            name, _, _, _, off, size = struct.unpack_from(order + "IIQQQQ", data, at)
        else:
            name, _, _, _, off, size = struct.unpack_from(order + "IIIIII", data, at)
        return name, off, size

    _, stroff, _ = section(shstrndx)
    for i in range(shnum):
        name, off, size = section(i)
        end = data.index(b"\0", stroff + name)
        if data[stroff + name:end] == b".rodata":
            return off, size
    raise ValueError("no .rodata section")


def runs(blob: bytes):
    """Each run of text in `blob`: (offset, text)."""
    i, n = 0, len(blob)
    start, chars = 0, []
    while i <= n:
        b = blob[i] if i < n else None
        step, ch = 1, None
        if b is not None and (0x20 <= b < 0x7F or b in (0x09, 0x0A)):
            ch = chr(b)
        elif b is not None and b >= 0xC2:
            size = 2 if b < 0xE0 else 3 if b < 0xF0 else 4 if b < 0xF5 else 0
            try:
                ch = blob[i:i + size].decode("utf-8") if size else None
                step = size
            except UnicodeDecodeError:
                ch = None
        if ch is None:
            if len(chars) >= MIN:
                yield start, "".join(chars)
            chars, start = [], i + 1
            i += 1
            continue
        if not chars:
            start = i
        chars.append(ch)
        i += step


def faults(path: Path, data: bytes) -> list[str]:
    off, size = rodata(data)
    blob = data[off:off + size]
    out = []
    for at, text in runs(blob):
        if any(re.search(rx, text) for rx, _ in ALLOWED):
            continue
        where = f"{path}: .rodata+{at:#x}"
        for c in text:
            if emoji(ord(c)):
                out.append(f"{where}: the emoji or pictograph U+{ord(c):04X} in {text[:80]!r}")
                break
            if bidi(ord(c)):
                out.append(f"{where}: the bidirectional control U+{ord(c):04X} in {text[:80]!r}")
                break
        if PROSE.search(text):
            for m in WORK_ID.finditer(text):
                context = text[max(0, m.start() - 40):m.end() + 40]
                out.append(f"{where}: the work id {m.group()} in {context!r}")
    return out


def plant(data: bytes) -> bytes:
    """`data` with a planted text over the start of a long run of `.rodata`."""
    off, size = rodata(data)
    planted = "the entry T-700 is here \U0001F680 now ".encode("utf-8")
    for at, text in runs(data[off:off + size]):
        if len(text) >= len(planted) and text.isascii():
            at += off
            return data[:at] + planted + data[at + len(planted):]
    raise ValueError("no run is long enough for the plant")


def main(argv: list[str]) -> int:
    planted = "--plant" in argv
    paths = [Path(a) for a in argv if a != "--plant"]
    if not paths:
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 2
    found = []
    for path in paths:
        try:
            data = path.read_bytes()
            if planted:
                with tempfile.NamedTemporaryFile(suffix=".planted", delete=False) as f:
                    f.write(plant(data))
                copy = Path(f.name)
                try:
                    found += faults(copy, copy.read_bytes())
                finally:
                    copy.unlink()
            else:
                found += faults(path, data)
        except (OSError, ValueError, struct.error) as e:
            print(f"check-strings: {path}: {e}", file=sys.stderr)
            return 2
    for line in found:
        print(line)
    if not found:
        print(f"check-strings: {len(paths)} files, no fault")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
