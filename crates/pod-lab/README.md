# pod-lab

The classes of hostile hosts as profiles, the check of a profile on a
host, and a lab that holds a profile for a command. New code for the ask
of podrunner (PodUtils/podrunner#180) with the profiles of podvm
(PodUtils/podvm#424), podssh (PodUtils/podssh#268) and podnet
(PodUtils/podnet#585), with podnet's data of the network classes
(PodUtils/podnet#592); entries T-692, T-701 and T-716. `LANES.md` gives the
commands that each project runs in each profile. Linux only: on another target the
library holds its exit codes alone.

A profile is data. Each part of a profile names the rows of
`pod-hostprobe` that it must make refuse (with which errno) or allow, and
the mechanism that holds it in a lab. Thus a lab that allows what it
must refuse fails its own check.

## API

| Item | What |
| --- | --- |
| `PROFILES`, `find(profiles, name)` | the table, and a profile by its name |
| `Profile`, `Part`, `Observe`, `Expect`, `IdFact`, `LabFact`, `Hold`, `Call`, `When` | the data of a profile |
| `Net`, `Proxy`, `NetFact`, `Ca`; module `net` | the stand-ins of a network lab, the facts that the lab measures through them, and their addresses, names and ports |
| `check(profile, &Findings) -> Verdict` | each part against the findings of `pod-hostprobe` |
| `check_report(profile, json)` (feature `report`) | the same against the JSON report of `pod_hostprobe::report` |
| `check_with(profile, &Findings, lab)` | the same, with a measurement of each `LabFact` |
| `rows(profile)`, `measure(&hostprobe::Settings, rows)` | the rows that a profile names, and a run of those rows only, each in its probe child |
| `Verdict`, `PartVerdict`, `Seen`, `State` | the verdict: each part `holds`, `fails` or `unseen`, each observation with its row and errno |
| `run(&Settings, profile, cmd, Options) -> Result<Ran, RunError>` | a command in a lab of the profile |
| `Options { partial, stdout, allow_connect }` | run in the parts that hold, and report the others; the output of the command; the TCP ports that a connect may reach where a part refuses each TCP connect |
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
2. makes each mount of the profile in one new mount namespace (as root),
   or in a user namespace that maps the caller to 0 and then a second one
   that maps it back, so the command runs as its own user with no
   capability: a tmpfs on `/tmp`; a tmpfs on `/dev` with `null`, `zero`,
   `full`, `random` and `urandom` of the host and a FIFO at `/dev/tty`;
   `/etc/passwd` and `/etc/group` with no line of the caller; a bind of
   `HOME` with `noexec`, or of `/etc/ssl` read-only; an empty read-only
   tmpfs on `/proc` (last); a new network namespace, whose loopback is
   down, or (a network lab) whose loopback is up with the addresses, the
   resolver files and the listening sockets of the stand-ins;
3. starts the stand-ins of a network lab (below);
4. opens `/dev/null` at the descriptors 3 to 9, not close-on-exec, and
   starts a new session with no controlling terminal;
5. restricts itself with Landlock (no TCP port; or a path hidden: a rule
   on each entry of each directory on the way to the path, except the
   next step);
6. drops each capability: the ambient set, the bounding set, the three
   sets, then `no_new_privs`, so that an exec as root gets none back;
7. installs one seccomp filter, from the BPF program of `pod-confine`,
   after `no_new_privs` (a rule can test an argument: the family and the
   type of `socket(2)`);
8. measures the profile from inside: each row in its own probe child
   (which inherits the lab), the identity, and each `LabFact`;
9. replaces itself with the command when each part holds (or with
   `partial`). Else it exits 125, and the command does not run.

The command keeps the standard streams of the caller. `TMPDIR` is `/tmp`
where a part mounts a tmpfs there. A tmpfs on `/tmp` hides a command
under `/tmp`: give such a command as `/proc/self/exe` or from another
directory.

### A network lab

A network class (`proxy-only` and the six classes of podnet's data) is a
network namespace with no route out, in the user namespace of the mounts.
Its loopback is up, and the stand-ins of the class listen on it. Nothing
in the lab reaches the network of the host: each answer of "the outside"
comes from a stand-in.

* The stand-in process: the lab forks it two times before Landlock and
  the filter, so it is no child of the command. It holds a pidfd of the
  lab process, which is the command after the exec. It serves each
  connection in a thread, and exits when the command ends.
* Two certificate authorities, made for each run with P-256 keys of the
  kernel's random bytes: the CA of the stand-in servers (the public roots
  of the lab) and the CA of the stand-in proxy. `SSL_CERT_FILE` of the
  command is a new file of the temporary directory with the CA of the
  servers, and the CA of the proxy where the proxy terminates TLS. The
  stand-in removes the file when the command ends.
* The stand-in TLS server listens on `0.0.0.0:443`. It shows a leaf for
  the name of the ClientHello (or for the address that it reached), and
  answers each request with 200 and `pod-lab stand-in`.
* The stand-in proxy listens on `127.0.0.1:3128`. `HTTPS_PROXY`,
  `https_proxy`, `HTTP_PROXY` and `http_proxy` of the command name it;
  in a class with no proxy, the lab removes each variable of a proxy.
  After a 200, the proxy is the server of the target itself.
* The names: `listed.test` is on the list of a class, `other.test` is not
  (RFC 6761 names). The address outside is `192.0.2.1` (RFC 5737): a
  class of direct connects puts `192.0.2.0/24` on the loopback; in another
  class no route reaches it (`ENETUNREACH`). `ipv6-only` puts
  `fd00:6c61:62::1` on the loopback.

| Profile | The stand-ins |
| --- | --- |
| `proxy-only` | the proxy asks for the credential `podlab` with a made-up password (407 with none), reaches the ports 443, 80 and 8443 (403 for another port); a seccomp filter refuses UDP |
| `proxy-tls-reterminate` | `tls-reterminated`, `ssh-port-silent` | inside the lab: TLS through the proxy to `listed.test` ends at the CA of the proxy, to `other.test` at the CA of the server; `CONNECT listed.test:22` 200, then no byte in 1 s | a network lab |
| `proxy-per-name` | `answer-per-name` | inside the lab: `CONNECT` 200 for `listed.test`, 504 for `other.test`, a reset for `192.0.2.1` | a network lab |
| `sni-allowlist` | `sni-reset` | inside the lab: a ClientHello to `192.0.2.1:443` for `listed.test` gets a ServerHello; for `other.test`, or with no name, a reset | a network lab |
| `no-proxy-no-dns` | `no-resolver`, `literal-reaches` | inside the lab: a lookup fails, no `nameserver` line, `127.0.0.1:53` refused; TLS to `192.0.2.1:443` checks the address | a network lab |
| `ws-upgrade-refused` | `upgrade-refused` | inside the lab: an HTTPS `GET` through the proxy 200, with `Upgrade: websocket` 403 | a network lab |
| `ipv6-only` | `no-ipv4-route`, `ipv6-reaches` | inside the lab: `connect(192.0.2.1:443)` ENETUNREACH, `127.0.0.1:443` reaches; `[fd00:6c61:62::1]:443` reaches | a network lab |

A part whose text says "Assumed:" holds the form of the class that podssh
or podnet named, not a measurement of a real network.

## The profiles

`podlab list` prints the table. The parts, and what holds each one in a
lab with no root:

| Profile | Parts | Observed by | Held by |
| --- | --- | --- | --- |
| `userns-off` | `userns-refused` | `unshare(CLONE_NEWUSER)`, `clone(CLONE_NEWUSER)` and the user namespace leg refused (EPERM, ENOSPC) | seccomp |
| `bind-denied` | `tcp-bind-refused`, `tcp-connect-refused`, `unix-allowed` | `bind(127.0.0.1:0)+listen` EACCES; inside the lab: bind of `[::1]:0` and connect EACCES, AF_UNIX socket, bind and connect allowed | Landlock (ABI 4); the host |
| `getsockname-denied` | `getsockname-refused` | inside the lab: EOPNOTSUPP | seccomp (not on targets with `socketcall`) |
| `proxy-only` | `direct-refused`, `proxy-reaches`, `proxy-credential`, `port-refused`, `udp-refused` | inside the lab: `connect(192.0.2.1:443)` ENETUNREACH; `CONNECT listed.test:443` 200 and TLS to the CA of the server; 407 with no credential; 403 for port 22; as `udp-denied` | a network lab with the stand-in proxy; seccomp |
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
| `listen-denied` | `bind-allowed`, `listen-refused` | inside the lab: bind allowed; `bind(127.0.0.1:0)+listen` EACCES or EPERM, and inside the lab: listen after bind EACCES or EPERM | the host; seccomp of `listen` (EACCES) |
| `udp-denied` | `udp-refused` | inside the lab: a UDP socket of each family, or its connect, EPERM or EACCES | seccomp of `socket(AF_INET or AF_INET6, SOCK_DGRAM)` (EPERM), `io_uring_setup` |
| `raw-denied` | `raw-refused` | inside the lab: `socket(AF_INET, SOCK_RAW)` and `socket(AF_PACKET)` EPERM | seccomp of the raw and packet sockets (EPERM), `io_uring_setup` |
| `no-ptmx` | `ptmx-absent`, `no-ctty`, `tty-opens` | `stat(/dev/ptmx)` and `open(/dev/ptmx, O_RDWR)` ENOENT; inside the lab: `/dev/pts` ENOENT, `tty_nr` 0, `/dev/tty` opens and a read has no data | a tmpfs on `/dev`; a new session |
| `no-passwd-entry` | `no-id-lines` | inside the lab: no line of the uid in `/etc/passwd`, of the gid in `/etc/group` | binds of the two files |
| `noexec-home` | `home-noexec`, `tmp-exec` | inside the lab: `HOME` writable and noexec; `exec(/tmp/execprobe)` allowed | a bind of `HOME` with `noexec`; the host |
| `no-proc` | `proc-absent` | inside the lab: `/proc/self/exe` ENOENT | an empty tmpfs on `/proc` |
| `seccomp-nonewprivs` | `no-new-privs`, `no-caps`, `calls-refused` | the identity; `mknod(chr 1:3 /tmp/nodprobe)`, `unshare(CLONE_NEWUSER)`, `unshare(CLONE_NEWNS)`, `mount(2) bogus target`, `chroot(/tmp)`, `ptrace(PTRACE_TRACEME)` EPERM | `no_new_privs`; the drop of the capabilities (also for root); seccomp |
| `no-tun` | `tun-absent` | `open(/dev/net/tun, O_RDWR)` ENOENT or EACCES | Landlock |
| `no-net-admin` | `no-net-admin`, `tun-absent` | the identity (`CapEff` with no bit 12); as `no-tun` | the drop of the capabilities; Landlock |
| `ro-etc-ssl` | `etc-ssl-read-only` | inside the lab: `statfs(/etc/ssl)` `ST_RDONLY` | a read-only bind |
| `no-loopback` | `loopback-absent`, `unix-allowed` | inside the lab: `connect(127.0.0.1:1)` ENETUNREACH; AF_UNIX allowed | a network namespace; the host |
| `proxy-tls-reterminate` | `tls-reterminated`, `ssh-port-silent` | no row (T-716) | the network labs of podnet (part 2) |
| `proxy-per-name` | `answer-per-name` | no row (T-716) | the network labs of podnet (part 2) |
| `sni-allowlist` | `sni-reset` | no row (T-716) | the network labs of podnet (part 2) |
| `no-proxy-no-dns` | `no-resolver`, `literal-reaches` | no row (T-716) | the network labs of podnet (part 2) |
| `ws-upgrade-refused` | `upgrade-refused` | no row (T-716) | the network labs of podnet (part 2) |
| `ipv6-only` | `no-ipv4-route`, `ipv6-reaches` | no row (T-716) | the network labs of podnet (part 2) |

The facts that no row of `pod-hostprobe` measures: the network rows and
`getsockname` (T-693); the size of `TMPDIR` and the inherited
descriptors (T-694); the machine of `uname(2)`, the cgroup version and
the `hidepid` form of `/proc` (T-695); the socket facts of `listen-denied`,
`udp-denied`, `raw-denied` and `no-loopback` (T-714); the file facts of
`no-ptmx`, `no-passwd-entry`, `noexec-home`, `no-proc` and `ro-etc-ssl`
(T-715); the facts of the network classes (T-745). The printed texts name
no entry.

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
lab flag `--podlab-lab`, the table `PROFILES`. The crate prints nothing;
`podlab` prints. Only the lab process reads the environment: `HOME` (the
bind of `noexec-home`) and `TMPDIR` (the new files of `no-passwd-entry`,
of the resolver of `no-proxy-no-dns`, and the certificate file of a
network lab). In a network lab it sets `SSL_CERT_FILE` and the variables
of a proxy for the command.

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
  check from inside fails; `tests/lab/hosts.rs`: each class of podssh and
  podnet that a lab here holds, with a payload that shows each part, and
  a class of the machine tier that the run refuses; `tests/lab/net.rs`:
  each network class with a payload that reads `HTTPS_PROXY` and
  `SSL_CERT_FILE` as a program does, then the removal of the certificate
  file. As root each case runs as root, then again as uid 65534. `scripts/ci/userns-tests.sh` runs it where a
  skip fails.
* Plants: `scripts/plants/lab-*`.
