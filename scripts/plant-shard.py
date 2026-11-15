#!/usr/bin/env python3
"""The plants of one shard of plants.yml: each group whole, in one shard.

    python3 scripts/plant-shard.py SHARDS SHARD

The groups go to the shards from the largest down, each to the shard with
the fewest plants, so that the shards run about the same count. A group
stays in one shard: its plants build the same crates, and the build of one
plant serves the next. Prints the ids of shard SHARD (0 to SHARDS - 1), one
line, sorted. A plant with no group is a group of its own.
"""

from __future__ import annotations

import sys
from pathlib import Path

DIR = Path(__file__).resolve().parent / "plants"


def groups() -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for f in sorted(DIR.glob("*.plant")):
        group = f.stem
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.startswith("GROUP="):
                group = line.split("=", 1)[1].strip().strip("'\"") or f.stem
        out.setdefault(group, []).append(f.stem)
    return out


def shards(count: int) -> list[list[str]]:
    load = [[] for _ in range(count)]
    for _, ids in sorted(groups().items(), key=lambda kv: (-len(kv[1]), kv[0])):
        min(load, key=len).extend(ids)
    return [sorted(ids) for ids in load]


def main(argv: list[str]) -> int:
    if len(argv) != 2 or not all(a.isdigit() for a in argv):
        print(__doc__.strip().splitlines()[2].strip(), file=sys.stderr)
        return 64
    count, index = int(argv[0]), int(argv[1])
    if count < 1 or index >= count:
        print(f"plant-shard: shard {index} of {count} does not exist", file=sys.stderr)
        return 64
    print(" ".join(shards(count)[index]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
