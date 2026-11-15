# Handoff

The state of unfinished work, for a session with no memory of the last
one. Read this page first, then `AGENTS.md`, `TODO/PROGRESS.md` (the
state, the work order, the questions), `docs/maintenance.md` (the
procedures, the tools and the rules of the work), `docs/design.md` and
`docs/decisions.md`. Keep this page current: remove a line when its work
is done. Git and the record keep finished work.

## The first steps of the next session

1. Start the watcher (`sh scripts/agent/watch-org.sh 90` under the Monitor
   tool) and read the open COORD issues `(to podcrates)`.
2. A push of this session's account starts no workflow: each run comes
   by a `[gh action] requested` issue (`docs/maintenance.md`, "A run of a
   workflow"). Read the answers of #165 (`guest-windows.yml`, the proof of
   T-640: a `RESULT:` line counts six cold boots) and #168 (the checks of a
   push at `a634d3a`). Then close T-645 with the run of `secrets.yml`.
3. Release `v0.51.0`: the release commit (the notes
   `docs/releases/v0.51.0.md`, the bump) waits on the local `main` until
   #168 is green. Push it, then ask for `ci.yml` on it and `release.yml`
   (a dry run, then `version=0.51.0`) in one request. Then write the
   hand-off `(to all)`: it answers PodUtils/podnet#572, PodUtils/podvm#380,
   PodUtils/podssh#253, PodUtils/podvm#389, #390 and #393 (most of #393 is
   `pod-qga` of `v0.45.0`; `osinfo` is new), and tells podvm that T-644 and
   T-649 (PodUtils/podvm#384, #386) are open. Ask podvm there whether its
   runs of experiment 450 copy the OVMF variable store fresh for each run.
4. Record the takes of `v0.50.0` on #164 (COORD-104): podvm `0573bcd8` and
   podnet `779c712` and podrunner `cbb5372` are in; podssh waits.
5. The move of podssh (PodUtils/podssh#248, the ruling "The move of
   podssh"): parts 2 and 3 of `pod-egress` (T-035, partial) start again
   from `main`: part 2 is `vless/`, `vmess/`, `trojan/`, `shadowsocks/`;
   part 3 is `eice/`, `iap/` of podssh-ws at podssh `2ffb7cd7`, which
   podssh froze. The import and the edition commits of each are on the
   branches `wip/egress-part2` and `wip/egress-part3` (based on part 1);
   the adaptation that was not committed is lost. Start each agent from
   its branch, merge it to `main` as usual, then delete the `wip/` branch.
   Give each the brief of part 1 (each road behind its own feature, on the
   shared parts of the crate; an adoption patch with `.needs` =
   pod-egress). podssh's map of the glue is in the body of
   PodUtils/podssh#248. Then step 3 of the move: `pod-tor`, `pod-iroh`,
   `pod-cloudflare`, `pod-ts`; then `pod-relay-serve`.
6. Then the work order of `TODO/PROGRESS.md`.

## In flight

- The last tags: `v0.50.0` at `26fb91f` (ci 43669018284, adoption 43669018236,
  release 43672638621; the hand-off #164, COORD-104): step 1 of the move.
- The moved crates of step 1 (`pod-transit`, `pod-acme`, `pod-piping`,
  `pod-opentunnel`, `pod-derp`) are in `v0.50.0`; their trial patches in
  `adoption/podssh/` name `v0.50.0`. Part 1 of `pod-egress` is on `main`;
  its patch names `v0.51.0`.
- The owner reserves the names of `pod-actions-store`,
  `pod-actions-results`, `pod-udf`, `pod-qga` and of the crates of the
  move on crates.io ("Owner actions" of `TODO/PROGRESS.md`);
  `scripts/check-crates-io-names.py` reports the missing names.
- The open threads of this session:
  - T-539 is in `v0.41.0`; T-540 (open) tests it against a kernel pty.
  - T-557 (open): a finding of T-542.
  - T-526 (partial): the fix of `kcp` upstream. podnet sets the profile of
    `kcp` with its take of the udp carrier (#139, PodUtils/podnet#527).
- The red runs of this session have fixes on `main`: T-532 and T-535
  (the bounds of the tests under an emulator; the nightly at `1335e9a`,
  run 43467939399, passes each job, riscv64 and armv7 too), T-534 and T-536 (the port of the registry
  of `pod-oci`), T-537 (a tox node that is down), T-497 (the build of the
  icmp carrier on macOS; `scripts/agent/check-macos.sh`, T-533, checks it
  here). T-351 still waits for the proof of a first "no answer".
  - `plants.yml` at `6b183f6` (run 43448941361): the plant
    `link-udp-fragment-taken` was missed; its `EXPECT` takes the stall
    now (T-521, Correction). The next run of `plants.yml` proves it.
- podswarm's tracker is PodUtils/podswarm#1 (moved from #107). githome
  builds its side of a live test (#83): it waits for T-106 (the
  conformance binary of `pod-testkit`) and T-100 (`pod-broker`), which
  stay in M8 under the ruling "Open questions".
- `pod-warp`: podnet and podssh took the crate in `v0.37.0`; their WARP
  code holds fixes only (#135). T-339 (partial) holds the rest.
- The disk of a cloud session is small: `target/debug/incremental` grows
  to some GB. Run the workspace tests with `CARGO_INCREMENTAL=0` when the
  disk is short.
- T-040 (partial): the trials of podvm, with each import for podvm.

## What waits

- podvm (on `v0.42.0`, `296a1fc1`, PodUtils/podvm#325; `v0.2.0-beta.14`
  out): T-330 (its pair commands); T-207 (`pod-netlab`, #70) for
  PodUtils/podvm@T-1662; `exec_attached` of `pod-incus` if
  PodUtils/podvm@T-1722 asks. Write to podvm by COORD issues only.
- podnet (on `v0.42.0`, `654c0f1`, PodUtils/podnet#550; T-574 for its
  filter of raw sockets): the rest of its link workstream (#133: T-494, T-500, then group
  d), then T-029 (`pod-cloudflare`) on the chain to WARP (the owner's
  order). Write to podnet by COORD issues only.
- podssh (on `v0.42.0`, `7e457b4`, PodUtils/podssh#241; T-560 is open,
  as its role serves the one form over HTTP/2): the live runs of its PodUtils/podssh@T-737 (the brokers) and
  PodUtils/podssh@T-571 (`syncthing-relay`); `sandhole` and
  `openbare-xyz` wait for PodUtils/podssh@T-743 and PodUtils/podssh@T-740.
- podrunner (on `v0.42.0`, `05ceaec`, PodUtils/podrunner#96): its session
  runs with podvm. Its T-108 fills `cpu_s` and `peak_rss_mib` with
  `v0.40.0` (PodUtils/podrunner#86). Write to it by an issue with
  `(to podrunner)` in the title.
- podswarm (#107 to #125): the owner's ruling "podswarm" (2026-11-13).
  T-439, T-444, T-447 and T-448 help a sibling and are in the work order;
  the other asks wait until the podswarm session starts.
- `pod-git` (T-217 to T-220) is blocked: `PodUtils/podforge`, deferred
  (the owner; #75, #131). M8 (cfb and githome, #35 and #36) waits (the
  ruling "Priority").

## Channels

- Each session talks with the others by COORD issues alone, no direct
  message (the owner, 2026-11-12, the ruling "Tonight"). A session writes
  only to its own repository: link a consumer's COORD issue from the
  hand-off issue of podcrates. Do not start a session of a consumer.
- Workflows: dispatch them with the GitHub MCP tool
  (`docs/maintenance.md`, "A run of a workflow"). `services.yml` with the
  kind `forward-url` reads the banners of the SSH forward relays (no
  session has SSH).
