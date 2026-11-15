# The lanes of the projects

A lane is the list of commands that a project runs in each profile before
a release. Each command runs in a lab:

```sh
podlab run PROFILE -- COMMAND...
```

`podlab run` stops with exit 125 when a part of the profile does not
hold, and the command does not run. `podlab list` gives each profile and
what holds each part. A profile whose parts are "not here" needs a
network lab (part 2 of the crate): its lane waits for that lab.

The sources: PodUtils/podssh#268 (podssh), PodUtils/podnet#585 (podnet),
PodUtils/podrunner#180 (podrunner) and PodUtils/podvm#424 (podvm).

## podssh

The commands of a release, in each profile below:

1. `podssh doctor`.
2. `podssh ssh` and `podssh proxy`, through the relay and through a node.
3. `podssh cp` of 200 MiB, in each direction.
4. `podssh serve` with `vi`, `less` and Ctrl-C.
5. `podssh pipe`.
6. A session that continues after a kill of its relay link.

| Profile | Held here | The commands |
| --- | --- | --- |
| `bind-denied` | yes | 1, 2, 5, 6 |
| `listen-denied` | yes | 1, 2, 5, 6 |
| `udp-denied` | yes | 1, 2, 3 |
| `no-ptmx` | yes | 1, 4 |
| `no-passwd-entry` | yes | 1, 2, 3 |
| `noexec-home` | yes | 1, 2, 3 |
| `no-proc` | yes | 1, 2, 5 |
| `seccomp-nonewprivs` | yes | 1, 2, 3, 4, 5 |
| `ro-etc-ssl` | yes | 1, 2 |
| `no-tun` | yes | 1, 2 |
| `proxy-only` | no | 1 to 6 |
| `proxy-tls-reterminate` | no | 1, 2 |
| `proxy-per-name` | no | 1, 2 |
| `sni-allowlist` | no | 1, 2 |
| `no-proxy-no-dns` | no | 1, 2 |
| `ws-upgrade-refused` | no | 1, 2, 6 |

An example:

```sh
podlab run no-ptmx -- podssh doctor
podlab run seccomp-nonewprivs -- podssh doctor
```

podssh runs these commands today with `scripts/release-short.sh BINARY
--net`, its release check, and `scripts/test_in_box.sh` with
`scripts/sandbox-check.sh`. Its Podman box is the first form of
`proxy-only`, `no-ptmx` and `seccomp-nonewprivs`.

## podnet

| Profile | Held here | The commands |
| --- | --- | --- |
| `bind-denied` | yes | `net shim` with a dynamic client (.NET, Python), `PODNET_VNET_FORWARD`; `link` over the carriers of AF_UNIX |
| `udp-denied` | yes | `tunnel` (the fallback to HTTP/2), `warp` (TCP), `wg:FILE` over `warp` |
| `raw-denied` | yes | `link` over `icmp`, `pod --allow-raw icmp` |
| `no-net-admin` | yes | `pod run` (the seccomp and the netns-raw backends), `warp proxy` |
| `no-loopback` | yes | `doctor`, `net proxy --listen unix:PATH` |
| `proxy-only` | no | `doctor`, `tunnel --quick`, `warp proxy` (MASQUE over TCP 443), `relay`, `send` and `receive` |
| `ipv6-only` | no | `doctor`, `tunnel`, `warp proxy` |

An example:

```sh
podlab run no-loopback -- podnet net proxy --listen unix:/tmp/podnet.sock
podlab run no-net-admin -- podnet warp proxy
```

podnet gives the network profiles of part 2 (`proxy-only` and the classes
of podssh that need a proxy) as data in the form of the table.

## podrunner

podrunner runs its installer and a corpus of real projects in each of its
profiles before each release (its user-path gate):

```sh
podlab run PROFILE -- sh install.sh
podlab run PROFILE -- podrunner run JOB
```

Its profiles: `userns-off`, `bind-denied`, `getsockname-denied`,
`proxy-only`, `small-tmp`, `root-unreadable`, `nonroot-nocaps`, `no-kvm`,
`arm64-tcg` and `inherited-fds`. Until it takes the crate, its lanes are
the scripts `scripts/lab/PROFILE.sh` of podrunner.

## podvm

podvm runs a payload in a lab of each of its profiles:

```sh
podlab run PROFILE -- podvm run IMAGE CMD
```

Its profiles: `chroot-denied`, `userns-mount-denied`, `cgroup-v1`,
`landlock-old`, `proc-masked`, `noexec-tmp` and `wsl2`, with
`bind-denied`, `getsockname-denied`, `userns-off`, `small-tmp` and
`inherited-fds`. Its own host form is `podvm lab run PROFILE -- CMD`. The
form of the machine tier is `podvm run --podvm-tier=machine --podvm-lab
PROFILE IMAGE CMD`: a guest with the knobs of the profile, for
`cgroup-v1`, `arm64-tcg`, `landlock-old` with an ABI from 1 to 3, and
`wsl2`. `wsl2` is not in the table of the crate: only the machine tier
holds it.
