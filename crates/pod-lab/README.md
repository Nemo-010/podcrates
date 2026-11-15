# pod-lab

The classes of hostile hosts as profiles, the check of a profile on a
host, and a lab that holds a profile for a command. New code for the ask
of podrunner (PodUtils/podrunner#180) with the profiles of podvm
(PodUtils/podvm#424); entry T-692. Linux only: on another target the
library holds its exit codes alone.

A profile is data. Each part of a profile names the rows of
`pod-hostprobe` that it must make refuse (with which errno) or allow, and
the mechanism that holds it in a lab. Thus a lab that allows what it
must refuse fails its own check.

## API

| Item | What |
| --- | --- |
| `PROFILES`, `find(profiles, name)` | the table, and a profile by its name |
| `Profile`, `Part`, `Observe`, `Expect`, `IdFact`, `LabFact`, `Hold`, `Call` | the data of a profile |
| `check(profile, &Findings) -> Verdict` | each part against the findings of `pod-hostprobe` |
| `check_report(profile, json)` (feature `report`) | the same against the JSON report of `pod_hostprobe::report` |
| `check_with(profile, &Findings, lab)` | the same, with a measurement of each `LabFact` |
| `rows(profile)`, `measure(&hostprobe::Settings, rows)` | the rows that a profile names, and a run of those rows only, each in its probe child |
| `Verdict`, `PartVerdict`, `Seen`, `State` | the verdict: each part `holds`, `fails` or `unseen`, each observation with its row and errno |
| `run(&Settings, profile, cmd, Options) -> Result<Ran, RunError>` | a command in a lab of the profile |
| `Options { partial, stdout }` | run in the parts that hold, and report the others; the output of the command |
| `Settings { hostprobe, lab_flag, profiles }` | the flags of the probe children and of the lab process, and the table that the lab process reads |
| `dispatch(&Settings)` | the start of a binary that calls `run`: the work of a probe child or of the lab process |
| `exit_code(status)` | the code of a shell: the code, or 128 and the signal |
| `codes::{EXIT_*, facts}` | the exit codes of `podlab`; `facts()` (feature `manual`): its exit codes and its variables as the facts of a `pod-manual` model, the one table of them |
| `manual::{manual, docs, DOCS_BASE}` (feature `cli`) | the manual of `podlab`: the clap tree of its parser with the facts, the table of the profiles and the examples |

### `check`

A row that did not run (a skip of `pod-hostprobe`) never holds a part:
the part is `unseen`. A part holds only when each observation holds. One
observation that fails makes the part fail. A row that the findings do
not have, a `LabFact` and an `Observe::Nothing` are `unseen` in a check
of findings.

### `run`

`run` starts the binary again with the lab flag: a lab process with one
thread. The lab process:

1. closes each descriptor from 3 up;
2. mounts a tmpfs on `/tmp` in a new mount namespace (as root), or in a
   user namespace that maps the caller to 0 and then a second one that
   maps it back, so the command runs as its own user with no
   capability;
3. opens `/dev/null` at the descriptors 3 to 9, not close-on-exec;
4. restricts itself with Landlock (no TCP port; or a path hidden: a rule
   on each entry of each directory on the way to the path, except the
   next step);
5. installs one seccomp filter, from the BPF program of `pod-confine`,
   after `no_new_privs`;
6. measures the profile from inside: each row in its own probe child
   (which inherits the lab), the identity, and each `LabFact`;
7. replaces itself with the command when each part holds (or with
   `partial`). Else it exits 125, and the command does not run.

The command keeps the standard streams of the caller. `TMPDIR` is `/tmp`
where a part mounts a tmpfs there. A tmpfs on `/tmp` hides a command
under `/tmp`: give such a command as `/proc/self/exe` or from another
directory.

## The profiles

`podlab list` prints the table. The parts, and what holds each one in a
lab with no root:

| Profile | Parts | Observed by | Held by |
| --- | --- | --- | --- |
| `userns-off` | `userns-refused` | `unshare(CLONE_NEWUSER)`, `clone(CLONE_NEWUSER)` and the user namespace leg refused (EPERM, ENOSPC) | seccomp |
| `bind-denied` | `tcp-bind-refused`, `tcp-connect-refused`, `unix-allowed` | `bind(127.0.0.1:0)+listen` EACCES; inside the lab: bind of `[::1]:0` and connect EACCES, AF_UNIX socket, bind and connect allowed | Landlock (ABI 4); the host |
| `getsockname-denied` | `getsockname-refused` | inside the lab: EOPNOTSUPP | seccomp (not on targets with `socketcall`) |
| `proxy-only` | `direct-refused`, `proxy-reaches` | no row (T-692, part 2) | the network labs of podnet (part 2) |
| `small-tmp` | `tmpdir-small` | inside the lab: `statfs` of `/tmp`, at most 1 GiB | tmpfs |
| `root-unreadable` | `root-list-refused`, `open-by-name` | `readdir(/)` EACCES; `open(/bin, O_RDONLY) by name` allowed | Landlock; the host |
| `nonroot-nocaps` | `not-root`, `no-caps`, `no-new-privs`, `seccomp-filter` | the identity; `setuid(0)`, `mknod(chr 1:3 /tmp/nodprobe)`, `ptrace(PTRACE_TRACEME)` EPERM | a caller that is not root; `no_new_privs`; the default list of `pod-confine` |
| `no-kvm` | `kvm-absent` | `open(/dev/kvm, O_RDWR)` ENOENT or EACCES | Landlock |
| `arm64-tcg` | `arm64`, `kvm-absent` | no row (T-695); as `no-kvm` | the machine tier of podvm (part 2); Landlock |
| `inherited-fds` | `fds-open` | inside the lab: 3 to 9 open, not close-on-exec | the lab process |
| `chroot-denied` | `chroot-refused` | `chroot(/tmp)` EPERM | seccomp |
| `userns-mount-denied` | `userns-made`, `userns-mount-refused` | `unshare(CLONE_NEWUSER)` and `clone(CLONE_NEWUSER)` allowed; the user namespace leg EPERM or EACCES | the host; seccomp of the mount calls |
| `cgroup-v1` | `cgroup-v1` | no row (T-695) | the machine tier of podvm (part 2) |
| `landlock-old` | `landlock-below-4` | `landlock_create_ruleset(VERSION)`: no Landlock or ABI below 4 | seccomp (`ENOSYS`: the form with no Landlock) |
| `proc-masked` | `proc-hidden` | `open /proc/self/mem O_RDONLY` ENOENT or EACCES | Landlock |
| `noexec-tmp` | `tmp-noexec` | `exec(/tmp/execprobe)` EACCES | tmpfs with `MS_NOEXEC` |

The facts that no row of `pod-hostprobe` measures: the network rows and
`getsockname` (T-693); the size of `TMPDIR` and the inherited
descriptors (T-694); the machine of `uname(2)`, the cgroup version and
the `hidepid` form of `/proc` (T-695). The printed texts name no entry.

## Features

* `report`: `check_report`, through the feature `report` of
  `pod-hostprobe`.
* `manual`: `codes::facts`, the facts of `podlab` for `pod-manual`.
* `cli`: the binary `podlab` (clap), `report` and `manual`. The help and
  the manual come from the model of `pod-manual` (module `manual`):
  `podlab --help`, `podlab COMMAND --help`, `podlab help COMMAND`,
  `podlab man [--no-pager] [--roff | --json] [SECTION...]`. `man/podlab.1`
  and `man/llms.txt` are generated from the model with no version and no
  date: `cargo test -p pod-lab --features cli -- --ignored
  write_the_generated_files` writes them. A build with
  `SOURCE_DATE_EPOCH` gives the date of the man page of the binary.

## Settings

`Settings::default()`: the probe child flag `--podlab-probe-child`, the
lab flag `--podlab-lab`, the table `PROFILES`. The crate reads no
environment variable and prints nothing; `podlab` prints.

## Tests

* `src/table/tests.rs`: each profile of the asks, a part and an
  observation in each, each row name a row of `pod-hostprobe`, each
  errno one that a filter can give, the filter of each profile compiles.
* `src/check/tests.rs`: `check` against made-up findings and a report.
* `src/text.rs`: each printed text and each string literal of the code:
  the rules of `pod_manual::rules`.
* `src/bin/podlab/tests.rs`: the checks of `pod-manual` over the manual of
  `podlab`: the text rules, the model against the parser of clap, the
  generated files, the variables of the code both ways, the exit codes
  both ways, the help of each command.
* `tests/cli.rs`: the binary prints its manual with no pager, one section,
  the JSON and the man page, refuses an unknown section with exit 2, and
  answers `--help`, `help COMMAND` and `--help --json` from the model.
* `tests/lab.rs` (no libtest): `inherited-fds`, `bind-denied` (with
  AF_UNIX), `small-tmp`, a profile that no lab here holds, a part whose
  check from inside fails. As root it starts again as uid 65534.
  `scripts/ci/userns-tests.sh` runs it where a skip fails.
* Plants: `scripts/plants/lab-*`.
