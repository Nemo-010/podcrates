#!/usr/bin/env python3
"""Check that product code binds no fixed port of the loopback.

  python3 -I scripts/check-loopback.py [--self-test]

Two local services that bind the same port of the loopback break each other:
the loser fails with an error that names neither service, and after a
reboot the other one can lose. The rule (T-831): the product code of a crate
binds a loopback address only on port 0 (the kernel gives a free port) or on
an address that its caller gives. A bind call that names a loopback address
with a fixed port is a fault, unless EXCEPTIONS lists the file with its
reason.

The scan reads each `.rs` file under `crates/*/src`, but not a file named
`tests.rs`, `*_tests.rs` or `test_*.rs`, a file in a directory named
`tests`, or a module under `#[cfg(test)]` (removed by brace matching). It
ignores comments, a dial (`connect`) and each text that is not in the
arguments of a bind call. A scan that reads fewer than MIN_FILES files is a
fault: a scan of nothing proves nothing.

--self-test runs the check on temporary trees with planted faults. It exits
0 only when the check finds each fault and passes the control tree.

Exit 0: no fault. Exit 1: a fault, one line for each.
"""

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MIN_FILES = 200

# A file that binds a fixed port of the loopback, by its path from the root,
# with the reason. Keep this empty when possible.
EXCEPTIONS: dict[str, str] = {}

BIND = re.compile(r"\bbind\w*\s*\(")
PORT = r"\s*,\s*(\d+|[A-Z][A-Z0-9_]*)\b"
LOOPBACK = [
    re.compile(r'"(?:127\.\d+\.\d+\.\d+|localhost|\[::1\]|\[::ffff:127\.[\d.]+\]):(\d+)"'),
    re.compile(r'"(?:127\.\d+\.\d+\.\d+|localhost|::1)"' + PORT),
    re.compile(r"(?:Ipv4Addr|Ipv6Addr)::LOCALHOST\)?" + PORT),
    re.compile(r"Ipv4Addr::new\(\s*127\s*,[^)]*\)\)?" + PORT),
    re.compile(r"\[\s*127\s*,\s*\d+\s*,\s*\d+\s*,\s*\d+\s*\]" + PORT),
]
TEST_MOD = re.compile(r"#\[cfg\(test\)\]\s*(?:#\[[^\]]*\]\s*)*(?:pub(?:\([^)]*\))?\s+)?mod\s+\w+\s*\{")
CHAR = re.compile(r"'(?:\\u\{[0-9a-fA-F]+\}|\\x[0-9a-fA-F]{2}|\\.|[^\\'\n])'")
RAW = re.compile(r'r(#*)"')


def code_view(text: str) -> str:
    """`text` with each comment, string and character literal made blank, at
    the same length: braces and parentheses in them do not count."""
    out = list(text)
    i, n = 0, len(text)

    def blank(a, b):
        for k in range(a, b):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif text.startswith("/*", i):
            depth, j = 1, i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth, j = depth + 1, j + 2
                elif text.startswith("*/", j):
                    depth, j = depth - 1, j + 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c == "r" and (m := RAW.match(text, i)) and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            end = text.find('"' + m.group(1), m.end())
            end = n if end < 0 else end + 1 + len(m.group(1))
            blank(m.end(), end - 1 - len(m.group(1)))
            i = end
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, min(j, n))
            i = j + 1
        elif c == "'" and (m := CHAR.match(text, i)):
            blank(i + 1, m.end() - 1)
            i = m.end()
        else:
            i += 1
    return "".join(out)


def closing(code: str, start: int, open_c: str, close_c: str) -> int:
    """The index after the bracket that closes the one before `start`."""
    depth = 1
    for k in range(start, len(code)):
        if code[k] == open_c:
            depth += 1
        elif code[k] == close_c:
            depth -= 1
            if depth == 0:
                return k + 1
    return len(code)


def product(text: str) -> tuple[str, str]:
    """`text` and its code view, with each `#[cfg(test)]` module made blank."""
    code = code_view(text)
    keep, view = list(text), list(code)
    for m in TEST_MOD.finditer(code):
        end = closing(code, m.end(), "{", "}")
        for k in range(m.start(), end):
            if keep[k] != "\n":
                keep[k] = view[k] = " "
    return "".join(keep), "".join(view)


def faults_in(text: str) -> list[tuple[int, str]]:
    """Each bind call of product code that names a fixed loopback port, by
    its line, with the text of the call."""
    kept, code = product(text)
    found = []
    for m in BIND.finditer(code):
        end = closing(code, m.end(), "(", ")")
        call = kept[m.start() : end]
        bare = re.sub(r"//[^\n]*", "", call)
        for rule in LOOPBACK:
            hit = rule.search(bare)
            if hit and hit.group(1) != "0":
                line = kept.count("\n", 0, m.start()) + 1
                found.append((line, " ".join(call.split())[:120]))
                break
    return found


def scanned(root: Path) -> list[Path]:
    out = []
    for src in sorted(root.glob("crates/*/src")):
        for path in sorted(src.rglob("*.rs")):
            name = path.name
            if name == "tests.rs" or name.endswith("_tests.rs") or name.startswith("test_"):
                continue
            if "tests" in path.relative_to(src).parts[:-1]:
                continue
            out.append(path)
    return out


def check(root: Path, min_files: int = MIN_FILES) -> list[str]:
    files = scanned(root)
    faults = []
    if len(files) < min_files:
        faults.append(f"the scan read {len(files)} files, fewer than {min_files}")
    for path in files:
        rel = path.relative_to(root).as_posix()
        if rel in EXCEPTIONS:
            continue
        for line, call in faults_in(path.read_text(encoding="utf-8", errors="replace")):
            faults.append(f"{rel}:{line}: a bind of a fixed loopback port: {call}")
    return faults


CONTROL = """
use std::net::{Ipv4Addr, Ipv6Addr, TcpListener, UdpSocket};
const OPEN: char = '{';
const CLOSE: &str = "}) bind(";
pub fn ephemeral() {
    let _ = TcpListener::bind("127.0.0.1:0");
    let _ = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).or_else(|_| UdpSocket::bind((Ipv6Addr::LOCALHOST, 0)));
    let _ = TcpListener::bind(("127.0.0.1", 0));
}
pub fn given(port: u16) {
    let _ = TcpListener::bind((Ipv4Addr::LOCALHOST, port));
}
pub fn dial() {
    let _ = std::net::TcpStream::connect("127.0.0.1:22");
    let shown = format!("{} 127.0.0.1:53", 1);
    // TcpListener::bind("127.0.0.1:8080") in a comment.
    let _ = shown;
}
#[cfg(test)]
mod tests {
    #[test]
    fn a() {
        let _ = std::net::TcpListener::bind("127.0.0.1:8080");
        let _ = '}';
    }
}
"""

BANNED = [
    'TcpListener::bind("127.0.0.1:8080")',
    'UdpSocket::bind("localhost:53")',
    'TcpListener::bind("[::1]:443")',
    'TcpListener::bind("127.0.0.2:22")',
    "UdpSocket::bind((Ipv4Addr::LOCALHOST, 5353))",
    'TcpListener::bind(("127.0.0.1", 8080))',
    'TcpListener::bind(("::1", 8080))',
    "TcpListener::bind((Ipv6Addr::LOCALHOST, PORT))",
    "TcpListener::bind((Ipv4Addr::new(127, 0, 0, 1), 9000))",
    "TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 9000)))",
    "tokio::net::TcpListener::bind_addr(\n        (Ipv4Addr::LOCALHOST, 1080),\n    )",
]


def self_test() -> int:
    """Each planted fault must be found, and the control must pass."""

    def plant(root: Path, rel: str, text: str):
        path = root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def control(root: Path):
        plant(root, "crates/a/src/lib.rs", CONTROL)
        plant(root, "crates/a/src/tests.rs", 'fn t() { TcpListener::bind("127.0.0.1:1"); }\n')
        plant(root, "crates/a/src/x/tests/mod.rs", 'fn t() { TcpListener::bind("127.0.0.1:1"); }\n')
        plant(root, "crates/a/tests/it.rs", 'fn t() { TcpListener::bind("127.0.0.1:1"); }\n')

    cases = {"control": (control, 0)}
    for i, spelling in enumerate(BANNED):
        cases[f"banned {i}"] = (
            lambda root, s=spelling: (control(root), plant(root, "crates/b/src/lib.rs", f"pub fn f() {{ let _ = {s}; }}\n")),
            1,
        )
    after_tests = CONTROL + 'pub fn after() { let _ = TcpListener::bind("127.0.0.1:8080"); }\n'
    cases["product code after a test module"] = (lambda root: plant(root, "crates/a/src/lib.rs", after_tests), 1)
    failed = 0
    for name, (build, want) in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            build(root)
            got = check(root, min_files=1)
            if len(got) != want:
                print(f"self-test {name}: want {want} faults, got {len(got)}: {got}")
                failed += 1
    with tempfile.TemporaryDirectory() as tmp:
        if not check(Path(tmp), min_files=1):
            print("self-test an empty tree: the scan of no file passed")
            failed += 1
    if failed:
        return 1
    print(f"self-test: {len(cases) + 1} cases agree")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    faults = check(ROOT)
    for fault in faults:
        print(fault)
    if faults:
        return 1
    print(f"check-loopback: {len(scanned(ROOT))} files, no bind of a fixed loopback port")
    return 0


if __name__ == "__main__":
    sys.exit(main())
