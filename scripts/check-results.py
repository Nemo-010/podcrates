#!/usr/bin/env python3
"""Check the record of the measured results of each crate.

  python3 -I scripts/check-results.py [--self-test]

A crate that has measured results keeps them in `crates/NAME/RESULTS.md`
(T-824, VF-5 of the ingest study), one table, one row for each result,
with the columns of COLUMNS. A result that is worse than the one before
stays. The check: the file has the table, each row has each column filled,
the date is YYYY-MM-DD, and the commit is a short or full hash. A file
with no row is a fault. A crate in MEASURED with no file is a fault: its
README names results.

--self-test runs the check on temporary trees with planted faults.

Exit 0: no fault. Exit 1: a fault, one line for each.
"""

import re
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
COLUMNS = ["Date", "Commit", "Host", "Kernel", "Rustc", "Input", "Runs", "Result", "Note"]
# The crates whose results are measured; each keeps a RESULTS.md.
MEASURED = ["pod-link", "pod-ws"]
# The columns that may be empty.
OPTIONAL = {"Note"}

DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
COMMIT = re.compile(r"^[0-9a-f]{7,40}$")


def cells(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def faults_in(rel: str, text: str) -> list[str]:
    lines = text.splitlines()
    head = [i for i, line in enumerate(lines) if line.startswith("|") and cells(line) == COLUMNS]
    if len(head) != 1:
        return [f"{rel}: no table with the columns {' | '.join(COLUMNS)}, or more than one"]
    out = []
    rows = 0
    for n, line in enumerate(lines[head[0] + 2 :], start=head[0] + 3):
        if not line.startswith("|"):
            break
        row = cells(line)
        rows += 1
        if len(row) != len(COLUMNS):
            out.append(f"{rel}:{n}: {len(row)} cells, not {len(COLUMNS)}")
            continue
        for name, value in zip(COLUMNS, row):
            if not value and name not in OPTIONAL:
                out.append(f"{rel}:{n}: the column {name} is empty")
        if row[0] and not DATE.match(row[0]):
            out.append(f"{rel}:{n}: the date {row[0]!r} is not YYYY-MM-DD")
        if row[1] and not COMMIT.match(row[1]):
            out.append(f"{rel}:{n}: the commit {row[1]!r} is not a hash")
    if rows == 0:
        out.append(f"{rel}: the table has no row")
    return out


def check(root: Path, measured: list[str]) -> list[str]:
    faults = []
    for name in measured:
        if not (root / "crates" / name / "RESULTS.md").is_file():
            faults.append(f"crates/{name}/RESULTS.md: missing; the crate has measured results")
    for path in sorted(root.glob("crates/*/RESULTS.md")):
        rel = path.relative_to(root).as_posix()
        faults.extend(faults_in(rel, path.read_text(encoding="utf-8")))
    return faults


GOOD = """# Results

| Date | Commit | Host | Kernel | Rustc | Input | Runs | Result | Note |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| 2026-11-17 | 957876d | a host | Linux 6.18 | 1.99.1 | 16 MiB | 20 | 521 to 1165 MiB/s | |
"""


def self_test() -> int:
    def tree(root: Path, text: str | None):
        if text is not None:
            (root / "crates" / "a").mkdir(parents=True)
            (root / "crates" / "a" / "RESULTS.md").write_text(text, encoding="utf-8")

    row = "| 2026-11-17 | 957876d | a host | Linux 6.18 | 1.99.1 | 16 MiB | 20 | 521 MiB/s | |"
    cases = {
        "control": (GOOD, 0),
        "no file of a measured crate": (None, 1),
        "no table": ("# Results\n\nNone.\n", 1),
        "no row": (GOOD.replace(row + "\n", "").replace(GOOD.splitlines()[-1] + "\n", ""), 1),
        "an empty column": (GOOD.replace("| 20 |", "|  |"), 1),
        "a bad date": (GOOD.replace("2026-11-17", "17.11.2026"), 1),
        "a bad commit": (GOOD.replace("957876d", "HEAD"), 1),
        "a short row": (GOOD.replace("| 20 |", "|"), 1),
    }
    failed = 0
    for name, (text, want) in cases.items():
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            tree(root, text)
            got = check(root, ["a"])
            if len(got) != want:
                print(f"self-test {name}: want {want} faults, got {len(got)}: {got}")
                failed += 1
    if failed:
        return 1
    print(f"self-test: {len(cases)} cases agree")
    return 0


def main() -> int:
    if sys.argv[1:] == ["--self-test"]:
        return self_test()
    faults = check(ROOT, MEASURED)
    for fault in faults:
        print(fault)
    if faults:
        return 1
    print(f"check-results: {len(list(ROOT.glob('crates/*/RESULTS.md')))} files, no fault")
    return 0


if __name__ == "__main__":
    sys.exit(main())
