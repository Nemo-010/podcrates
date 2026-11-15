use super::*;
use crate::profile::Observe;

#[test]
fn each_profile_of_the_asks_is_in_the_table() {
    let names: Vec<&str> = PROFILES.iter().map(|p| p.name).collect();
    for want in [
        "userns-off",
        "bind-denied",
        "getsockname-denied",
        "proxy-only",
        "small-tmp",
        "root-unreadable",
        "nonroot-nocaps",
        "no-kvm",
        "arm64-tcg",
        "inherited-fds",
        "chroot-denied",
        "userns-mount-denied",
        "cgroup-v1",
        "landlock-old",
        "proc-masked",
        "noexec-tmp",
        "listen-denied",
        "udp-denied",
        "raw-denied",
        "no-ptmx",
        "no-passwd-entry",
        "noexec-home",
        "no-proc",
        "seccomp-nonewprivs",
        "no-tun",
        "no-net-admin",
        "ro-etc-ssl",
        "no-loopback",
        "proxy-tls-reterminate",
        "proxy-per-name",
        "sni-allowlist",
        "no-proxy-no-dns",
        "ws-upgrade-refused",
        "ipv6-only",
    ] {
        assert!(names.contains(&want), "the table has no profile {want}");
    }
    assert_eq!(names.len(), 34, "{names:?}");
}

#[test]
fn each_profile_names_a_part_and_each_part_an_observation() {
    for p in PROFILES {
        assert!(!p.parts.is_empty(), "{} has no part", p.name);
        assert!(!p.about.is_empty() && !p.source.is_empty(), "{}", p.name);
        for part in p.parts {
            assert!(!part.observe.is_empty(), "{}/{} has no observation", p.name, part.name);
        }
    }
}

#[test]
fn each_row_name_is_a_row_of_pod_hostprobe() {
    for p in PROFILES {
        for part in p.parts {
            for o in part.observe {
                if let Observe::Row { row, .. } = o {
                    assert!(pod_hostprobe::probes::find(row).is_some(), "{}/{}: no row {row:?}", p.name, part.name);
                }
            }
        }
    }
}

#[test]
fn the_names_are_unique_and_found() {
    for (i, p) in PROFILES.iter().enumerate() {
        assert!(PROFILES[i + 1..].iter().all(|q| q.name != p.name), "{} two times", p.name);
        assert_eq!(find(PROFILES, p.name).map(|q| q.name), Some(p.name));
        for (j, part) in p.parts.iter().enumerate() {
            assert!(p.parts[j + 1..].iter().all(|q| q.name != part.name), "{}/{} two times", p.name, part.name);
        }
    }
    assert!(find(PROFILES, "no-such-profile").is_none());
}

/// A part that no row observes names the entry that adds its row.
#[test]
fn each_fact_with_no_row_names_its_entry() {
    for p in PROFILES {
        for part in p.parts {
            for o in part.observe {
                let entry = match o {
                    Observe::Lab(f) => f.entry(),
                    Observe::Nothing { entry, .. } => *entry,
                    _ => continue,
                };
                assert!(
                    (692..=699).contains(&entry) || (714..=716).contains(&entry),
                    "{}/{}: {entry}",
                    p.name,
                    part.name
                );
            }
        }
    }
}

/// Each refused row names an errno that a seccomp filter can give, and
/// each errno of a filter call is one too.
#[test]
fn each_errno_is_one_that_a_filter_can_give() {
    let ok = |n: i32| (1..=4095).contains(&n);
    for p in PROFILES {
        for part in p.parts {
            for o in part.observe {
                if let Observe::Row { expect: Expect::Refused(e), .. } = o {
                    assert!(!e.is_empty() && e.iter().all(|&n| ok(n)), "{}/{}", p.name, part.name);
                }
            }
            if let Hold::Seccomp(calls) = part.hold {
                assert!(calls.iter().all(|c| ok(c.errno)), "{}/{}", p.name, part.name);
            }
        }
    }
}

/// The deny rules of each filter compile into one BPF program.
#[test]
fn the_filter_of_each_profile_compiles() {
    for p in PROFILES {
        let rules: Vec<_> = p.parts.iter().flat_map(|part| crate::hold::deny_rules(part.hold)).collect();
        if !rules.is_empty() {
            pod_confine::deny::program(&rules).unwrap_or_else(|f| panic!("{}: {f}", p.name));
        }
    }
}

/// The classes of podssh and podnet that a lab here holds: each part has a
/// hold here, and each network class that needs a proxy or a route out has
/// none.
#[test]
fn the_classes_of_podssh_and_podnet_are_held_or_named_elsewhere() {
    let held = [
        "listen-denied",
        "udp-denied",
        "raw-denied",
        "no-ptmx",
        "no-passwd-entry",
        "noexec-home",
        "no-proc",
        "seccomp-nonewprivs",
        "no-tun",
        "no-net-admin",
        "ro-etc-ssl",
        "no-loopback",
    ];
    for name in held {
        let p = find(PROFILES, name).expect("a profile");
        assert!(p.parts.iter().all(|x| x.hold.here()), "{name}");
    }
    for name in ["proxy-tls-reterminate", "proxy-per-name", "sni-allowlist", "no-proxy-no-dns", "ws-upgrade-refused"] {
        let p = find(PROFILES, name).expect("a profile");
        assert!(p.parts.iter().all(|x| !x.hold.here()), "{name}");
    }
    assert!(find(PROFILES, "ipv6-only").expect("a profile").parts.iter().all(|x| !x.hold.here()));
}
