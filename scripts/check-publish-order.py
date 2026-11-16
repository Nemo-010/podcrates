#!/usr/bin/env python3
"""Check that `cargo publish --workspace` can order the crates.

  python3 -I scripts/check-publish-order.py [--self-test]

cargo packs a crate before each crate that depends on it, and keeps each
dev-dependency that has a version. A crate P with a versioned
dev-dependency on a crate D of the workspace, where D depends on P, makes a
cycle: the pack of P asks for a version of D that is not there yet. Give
such a dev-dependency a path only (cargo drops it from the package). Each
crate that cargo packs also has its text of the licence, `LICENSE` beside
its manifest: a consumer's inventory of the licences of a release reads it
(PodUtils/podvm#456). Exit 1 with each cycle and each crate with no
`LICENSE`; exit 0 with the count of crates.
"""

import json
import subprocess
import sys
import tempfile
from pathlib import Path


def licence_faults(packages: list[dict]) -> list[str]:
    out = []
    for p in packages:
        if p.get("publish") == []:
            continue
        if not (Path(p["manifest_path"]).parent / "LICENSE").is_file():
            out.append(f"{p['name']}: no LICENSE beside {p['manifest_path']}")
    return out


def faults(packages: list[dict]) -> list[str]:
    names = {p["name"] for p in packages}
    packed = {p["name"] for p in packages if p.get("publish") != []}
    needs: dict[str, set[str]] = {p["name"]: set() for p in packages}
    for p in packages:
        for d in p["dependencies"]:
            if d["name"] in names and d.get("kind") in (None, "build"):
                needs[p["name"]].add(d["name"])

    def closure(start: str) -> set[str]:
        seen: set[str] = set()
        todo = [start]
        while todo:
            for n in needs[todo.pop()]:
                if n not in seen:
                    seen.add(n)
                    todo.append(n)
        return seen

    out = []
    for p in packages:
        if p["name"] not in packed:
            continue
        for d in p["dependencies"]:
            if d.get("kind") != "dev" or d["name"] not in names or d["req"] == "*":
                continue
            if p["name"] in closure(d["name"]):
                out.append(
                    f"{p['name']} has the versioned dev-dependency {d['name']} {d['req']}, "
                    f"and {d['name']} depends on {p['name']}: give the dev-dependency a path only"
                )
    return out


def self_test() -> int:
    def pkg(name, deps, publish=None):
        return {"name": name, "publish": publish, "dependencies": deps}

    dev = {"name": "b", "kind": "dev", "req": "^1.0"}
    cycle = [pkg("a", [dev]), pkg("b", [{"name": "a", "kind": None, "req": "^1.0"}])]
    assert len(faults(cycle)) == 1, "a versioned dev-dependency in a cycle is a fault"
    cycle[0]["dependencies"][0]["req"] = "*"
    assert not faults(cycle), "a path-only dev-dependency is no fault"
    cycle[0]["dependencies"][0]["req"] = "^1.0"
    cycle[0]["publish"] = []
    assert not faults(cycle), "a crate that is not packed is no fault"
    with tempfile.TemporaryDirectory() as tmp:
        manifest = Path(tmp) / "Cargo.toml"
        manifest.write_text("")
        crate = {"name": "c", "publish": None, "manifest_path": str(manifest)}
        assert len(licence_faults([crate])) == 1, "a packed crate with no LICENSE is a fault"
        (Path(tmp) / "LICENSE").write_text("0BSD")
        assert not licence_faults([crate]), "a packed crate with a LICENSE is no fault"
        (Path(tmp) / "LICENSE").unlink()
        crate["publish"] = []
        assert not licence_faults([crate]), "a crate that is not packed needs no LICENSE"
    print("check-publish-order: self-test passed")
    return 0


def main(argv: list[str]) -> int:
    if argv[:1] == ["--self-test"]:
        return self_test()
    meta = subprocess.run(
        ["cargo", "metadata", "--no-deps", "--format-version", "1"],
        capture_output=True, text=True, check=True,
    ).stdout
    packages = json.loads(meta)["packages"]
    found = faults(packages) + licence_faults(packages)
    for line in found:
        print(f"check-publish-order: {line}", file=sys.stderr)
    if found:
        return 1
    print(f"check-publish-order: {len(packages)} crates, no cycle of a versioned dev-dependency, a LICENSE in each packed crate")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
