//! The profiles: the hosts of PodUtils/podrunner#180 and of
//! PodUtils/podvm#424, each as data. A printed text names no issue and no
//! entry: `source` names the consumer, and `entry` is a number for the
//! tests and the README.
//!
//! A row name is the name of `pod_hostprobe::probes::PROBES`, character for
//! character: a test checks each one.

use linux_raw_sys::errno as e;
use pod_hostprobe::probes::USERNS_LEG;
use pod_hostprobe::sys as k;

use crate::profile::{Call, Expect, Hold, IdFact, LabFact, Observe, Part, Profile};

const EPERM: i32 = e::EPERM as i32;
const EACCES: i32 = e::EACCES as i32;
const ENOENT: i32 = e::ENOENT as i32;
const ENOSPC: i32 = e::ENOSPC as i32;
const ENOSYS: i32 = e::ENOSYS as i32;
const EOPNOTSUPP: i32 = e::EOPNOTSUPP as i32;

/// The size of the `TMPDIR` of `small-tmp`: 1 GiB.
pub const SMALL_TMP: u64 = 1 << 30;

/// The last descriptor of `inherited-fds`: 3 to 9 are open.
pub const INHERITED_LAST: i32 = 9;

const NEWUSER: u32 = k::CLONE_NEWUSER as u32;

/// The calls of `userns-off`: a host with `user.max_user_namespaces` 0 or
/// `kernel.unprivileged_userns_clone` 0. `clone3` gets `ENOSYS`, as a
/// filter cannot read its flags behind a pointer, and the C library then
/// uses `clone`.
const USERNS_OFF: &[Call] = &[
    Call { name: "unshare(CLONE_NEWUSER)", nr: k::SYS_UNSHARE, errno: EPERM, flags: Some((0, NEWUSER)) },
    Call {
        name: "clone(CLONE_NEWUSER)",
        nr: k::SYS_CLONE,
        errno: EPERM,
        flags: Some((k::CLONE_FLAGS_ARG as u8, NEWUSER)),
    },
    Call { name: "clone3", nr: k::SYS_CLONE3, errno: ENOSYS, flags: None },
];

const GETSOCKNAME: &[Call] = &[Call { name: "getsockname", nr: k::SYS_GETSOCKNAME, errno: EOPNOTSUPP, flags: None }];

const CHROOT: &[Call] = &[Call { name: "chroot", nr: k::SYS_CHROOT, errno: EPERM, flags: None }];

/// The mount calls: a user namespace of AppArmor's
/// `apparmor_restrict_unprivileged_userns` holds no capability, so each
/// mount in it fails.
const MOUNTS: &[Call] = &[
    Call { name: "mount", nr: k::SYS_MOUNT, errno: EPERM, flags: None },
    Call { name: "fsopen", nr: k::SYS_FSOPEN, errno: EPERM, flags: None },
    Call { name: "fsmount", nr: k::SYS_FSMOUNT, errno: EPERM, flags: None },
    Call { name: "move_mount", nr: k::SYS_MOVE_MOUNT, errno: EPERM, flags: None },
    Call { name: "open_tree", nr: k::SYS_OPEN_TREE, errno: EPERM, flags: None },
];

/// A kernel with no Landlock: the version query and the two other calls
/// give `ENOSYS`.
const NO_LANDLOCK: &[Call] = &[
    Call { name: "landlock_create_ruleset", nr: k::SYS_LANDLOCK_CREATE_RULESET, errno: ENOSYS, flags: None },
    Call { name: "landlock_add_rule", nr: k::SYS_LANDLOCK_ADD_RULE, errno: ENOSYS, flags: None },
    Call { name: "landlock_restrict_self", nr: k::SYS_LANDLOCK_RESTRICT_SELF, errno: ENOSYS, flags: None },
];

const READ_DIR: u64 = k::LANDLOCK_ACCESS_FS_READ_DIR as u64;
const READ_FILE: u64 = k::LANDLOCK_ACCESS_FS_READ_FILE as u64;
const WRITE_FILE: u64 = k::LANDLOCK_ACCESS_FS_WRITE_FILE as u64;

/// The machine tier of podvm and the network labs of podnet: part 2 of
/// T-692.
const MACHINE: &str = "the machine tier of podvm";
const NETWORK: &str = "the network labs of podnet";

const fn row(row: &'static str, expect: Expect) -> Observe {
    Observe::Row { row, expect }
}

const NO_KVM: Part = Part {
    name: "kvm-absent",
    about: "/dev/kvm does not open",
    observe: &[row("open(/dev/kvm, O_RDWR)", Expect::Refused(&[ENOENT, EACCES]))],
    hold: Hold::Hide { path: "/dev/kvm", rights: READ_FILE | WRITE_FILE },
};

/// Each profile, in the order of `podlab list`.
pub static PROFILES: &[Profile] = &[
    Profile {
        name: "userns-off",
        about: "no user namespace for the caller",
        source: "podrunner",
        parts: &[Part {
            name: "userns-refused",
            about: "unshare and clone with CLONE_NEWUSER fail",
            observe: &[
                row("unshare(CLONE_NEWUSER)", Expect::Refused(&[EPERM, ENOSPC])),
                row("clone(CLONE_NEWUSER)", Expect::Refused(&[EPERM, ENOSPC])),
                row(USERNS_LEG, Expect::Refused(&[EPERM, ENOSPC])),
            ],
            hold: Hold::Seccomp(USERNS_OFF),
        }],
    },
    Profile {
        name: "bind-denied",
        about: "TCP bind and connect of AF_INET and AF_INET6 give EACCES; AF_UNIX holds",
        source: "podrunner",
        parts: &[
            Part {
                name: "tcp-bind-refused",
                about: "a TCP bind of each family gives EACCES",
                observe: &[
                    row("bind(127.0.0.1:0)+listen", Expect::Refused(&[EACCES])),
                    Observe::Lab(LabFact::Inet6BindRefused),
                ],
                hold: Hold::LandlockTcp,
            },
            Part {
                name: "tcp-connect-refused",
                about: "a TCP connect gives EACCES",
                observe: &[Observe::Lab(LabFact::InetConnectRefused)],
                hold: Hold::LandlockTcp,
            },
            Part {
                name: "unix-allowed",
                about: "socket, bind and connect of AF_UNIX succeed",
                observe: &[Observe::Lab(LabFact::UnixAllowed)],
                hold: Hold::Host,
            },
        ],
    },
    Profile {
        name: "getsockname-denied",
        about: "getsockname gives EOPNOTSUPP",
        source: "podrunner",
        parts: &[Part {
            name: "getsockname-refused",
            about: "getsockname of a TCP socket gives EOPNOTSUPP",
            observe: &[Observe::Lab(LabFact::GetsocknameRefused)],
            hold: Hold::Seccomp(GETSOCKNAME),
        }],
    },
    Profile {
        name: "proxy-only",
        about: "no direct connection out; only an HTTP proxy reaches out",
        source: "podrunner",
        parts: &[
            Part {
                name: "direct-refused",
                about: "a direct TCP connect to an outside address fails",
                observe: &[Observe::Nothing { needs: "a direct TCP connect to an outside address", entry: 692 }],
                hold: Hold::Elsewhere(NETWORK),
            },
            Part {
                name: "proxy-reaches",
                about: "a CONNECT through the proxy of the lab reaches out",
                observe: &[Observe::Nothing { needs: "a CONNECT through the proxy of the lab", entry: 692 }],
                hold: Hold::Elsewhere(NETWORK),
            },
        ],
    },
    Profile {
        name: "small-tmp",
        about: "TMPDIR on a tmpfs of 1 GiB",
        source: "podrunner",
        parts: &[Part {
            name: "tmpdir-small",
            about: "TMPDIR holds at most 1 GiB",
            observe: &[Observe::Lab(LabFact::TmpdirAtMost(SMALL_TMP))],
            hold: Hold::Tmpfs { size: Some(SMALL_TMP), noexec: false },
        }],
    },
    Profile {
        name: "root-unreadable",
        about: "readdir(\"/\") gives EACCES; an open by name holds",
        source: "podrunner",
        parts: &[
            Part {
                name: "root-list-refused",
                about: "a listing of / gives EACCES",
                observe: &[row("readdir(/)", Expect::Refused(&[EACCES]))],
                hold: Hold::Hide { path: "/", rights: READ_DIR },
            },
            Part {
                name: "open-by-name",
                about: "an open of /bin by name succeeds",
                observe: &[row("open(/bin, O_RDONLY) by name", Expect::Allowed)],
                hold: Hold::Host,
            },
        ],
    },
    Profile {
        name: "nonroot-nocaps",
        about: "a user that is not root, no capability, NoNewPrivs and a seccomp filter",
        source: "podrunner",
        parts: &[
            Part {
                name: "not-root",
                about: "the uid is not 0, and setuid(0) fails",
                observe: &[Observe::Identity(IdFact::NotRoot), row("setuid(0)", Expect::Refused(&[EPERM]))],
                hold: Hold::NonRoot,
            },
            Part {
                name: "no-caps",
                about: "no effective capability, and mknod of a device fails",
                observe: &[
                    Observe::Identity(IdFact::NoCaps),
                    row("mknod(chr 1:3 /tmp/nodprobe)", Expect::Refused(&[EPERM])),
                ],
                hold: Hold::NonRoot,
            },
            Part {
                name: "no-new-privs",
                about: "NoNewPrivs is 1",
                observe: &[Observe::Identity(IdFact::NoNewPrivs)],
                hold: Hold::NoNewPrivs,
            },
            Part {
                name: "seccomp-filter",
                about: "a seccomp filter (the default list of pod-confine)",
                observe: &[
                    Observe::Identity(IdFact::SeccompFilter),
                    row("ptrace(PTRACE_TRACEME)", Expect::Refused(&[EPERM])),
                ],
                hold: Hold::ConfineDefaults,
            },
        ],
    },
    Profile { name: "no-kvm", about: "no /dev/kvm", source: "podrunner", parts: &[NO_KVM] },
    Profile {
        name: "arm64-tcg",
        about: "an arm64 host with no KVM: each guest runs on TCG",
        source: "podrunner",
        parts: &[
            Part {
                name: "arm64",
                about: "the host is aarch64",
                observe: &[Observe::Nothing { needs: "the machine of uname(2)", entry: 695 }],
                hold: Hold::Elsewhere(MACHINE),
            },
            NO_KVM,
        ],
    },
    Profile {
        name: "inherited-fds",
        about: "descriptors 3 to 9 open at the start",
        source: "podrunner",
        parts: &[Part {
            name: "fds-open",
            about: "descriptors 3 to 9 are open and not close-on-exec",
            observe: &[Observe::Lab(LabFact::FdsOpen { last: INHERITED_LAST })],
            hold: Hold::Fds { last: INHERITED_LAST },
        }],
    },
    Profile {
        name: "chroot-denied",
        about: "chroot gives EPERM",
        source: "podvm",
        parts: &[Part {
            name: "chroot-refused",
            about: "chroot(/tmp) gives EPERM",
            observe: &[row("chroot(/tmp)", Expect::Refused(&[EPERM]))],
            hold: Hold::Seccomp(CHROOT),
        }],
    },
    Profile {
        name: "userns-mount-denied",
        about: "a user namespace is made, and a mount in it fails (apparmor_restrict_unprivileged_userns)",
        source: "podvm",
        parts: &[
            Part {
                name: "userns-made",
                about: "unshare and clone with CLONE_NEWUSER succeed",
                observe: &[
                    row("unshare(CLONE_NEWUSER)", Expect::Allowed),
                    row("clone(CLONE_NEWUSER)", Expect::Allowed),
                ],
                hold: Hold::Host,
            },
            Part {
                name: "userns-mount-refused",
                about: "a tmpfs mount in the user namespace fails",
                observe: &[row(USERNS_LEG, Expect::Refused(&[EPERM, EACCES]))],
                hold: Hold::Seccomp(MOUNTS),
            },
        ],
    },
    Profile {
        name: "cgroup-v1",
        about: "the cgroup v1 hierarchy, no cgroup2",
        source: "podvm",
        parts: &[Part {
            name: "cgroup-v1",
            about: "/sys/fs/cgroup is cgroup v1",
            observe: &[Observe::Nothing { needs: "the cgroup version of /sys/fs/cgroup", entry: 695 }],
            hold: Hold::Elsewhere(MACHINE),
        }],
    },
    Profile {
        name: "landlock-old",
        about: "a Landlock ABI below 4 (no TCP rules); a lab gives the form with no Landlock",
        source: "podvm",
        parts: &[Part {
            name: "landlock-below-4",
            about: "no Landlock, or an ABI below 4",
            observe: &[row("landlock_create_ruleset(VERSION)", Expect::LandlockBelow(4))],
            hold: Hold::Seccomp(NO_LANDLOCK),
        }],
    },
    Profile {
        name: "proc-masked",
        about: "no /proc; no row measures the form with hidepid",
        source: "podvm",
        parts: &[Part {
            name: "proc-hidden",
            about: "/proc/self/mem does not open",
            observe: &[row("open /proc/self/mem O_RDONLY", Expect::Refused(&[ENOENT, EACCES]))],
            hold: Hold::Hide { path: "/proc", rights: READ_FILE | READ_DIR | WRITE_FILE },
        }],
    },
    Profile {
        name: "noexec-tmp",
        about: "/tmp is mounted noexec",
        source: "podvm",
        parts: &[Part {
            name: "tmp-noexec",
            about: "an exec of a file in /tmp gives EACCES",
            observe: &[row("exec(/tmp/execprobe)", Expect::Refused(&[EACCES]))],
            hold: Hold::Tmpfs { size: None, noexec: true },
        }],
    },
];

/// The profile of this name in `profiles`.
pub fn find<'a>(profiles: &'a [Profile], name: &str) -> Option<&'a Profile> {
    profiles.iter().find(|p| p.name == name)
}

#[cfg(test)]
mod tests;
