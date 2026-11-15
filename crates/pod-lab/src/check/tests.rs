use pod_hostprobe::sys::{EACCES, ENOENT, ENOSYS, EPERM};
use pod_hostprobe::verdict::Outcome;

use super::*;
use crate::table::{PROFILES, find};

fn profile(name: &str) -> &'static Profile {
    find(PROFILES, name).expect("a profile of the table")
}

/// Made-up findings: each row of `rows`, and the identity of `id`.
fn findings(rows: &[(&'static str, Outcome)]) -> Findings {
    let mut f = Findings::empty();
    f.rows = rows.to_vec();
    f
}

fn part<'a>(v: &'a Verdict, name: &str) -> &'a PartVerdict {
    v.parts.iter().find(|p| p.part == name).expect("a part of the verdict")
}

#[test]
fn a_chroot_refused_with_eperm_holds() {
    let v = check(profile("chroot-denied"), &findings(&[("chroot(/tmp)", Outcome::denied(EPERM))]));
    assert!(v.holds(), "{v:?}");
    assert_eq!(v.parts[0].seen[0].errno, Some(1));
}

#[test]
fn a_refused_part_that_is_allowed_fails() {
    let v = check(profile("chroot-denied"), &findings(&[("chroot(/tmp)", Outcome::ok())]));
    assert!(v.fails() && !v.holds(), "{v:?}");
    assert_eq!(v.parts[0].state, State::Fails);
}

#[test]
fn a_refusal_with_another_errno_fails() {
    let v = check(profile("root-unreadable"), &findings(&[("readdir(/)", Outcome::denied(ENOENT))]));
    let p = part(&v, "root-list-refused");
    assert_eq!(p.state, State::Fails, "{p:?}");
    assert!(p.seen[0].detail.contains("ENOENT") && p.seen[0].detail.contains("EACCES"), "{p:?}");
}

#[test]
fn an_allowed_row_that_is_refused_fails_the_part() {
    let f =
        findings(&[("readdir(/)", Outcome::denied(EACCES)), ("open(/bin, O_RDONLY) by name", Outcome::denied(EACCES))]);
    let v = check(profile("root-unreadable"), &f);
    assert_eq!(part(&v, "root-list-refused").state, State::Holds);
    assert_eq!(part(&v, "open-by-name").state, State::Fails);
    assert!(v.fails());
}

#[test]
fn a_skipped_row_is_unseen_and_never_holds() {
    let v = check(profile("chroot-denied"), &findings(&[("chroot(/tmp)", Outcome::skip(Some(EPERM), "no /tmp"))]));
    assert_eq!(v.parts[0].state, State::Unseen, "{v:?}");
    assert!(!v.holds() && !v.fails());
}

#[test]
fn a_row_that_the_findings_lack_is_unseen() {
    let v = check(profile("chroot-denied"), &Findings::empty());
    assert_eq!(v.parts[0].state, State::Unseen);
    assert!(v.parts[0].seen[0].detail.contains("no such row"));
}

#[test]
fn a_fact_with_no_row_is_unseen_with_its_entry() {
    let v = check(profile("inherited-fds"), &Findings::empty());
    assert_eq!(v.parts[0].state, State::Unseen);
    assert!(v.parts[0].seen[0].detail.contains("no row of pod-hostprobe"), "{v:?}");
}

#[test]
fn a_lab_measures_its_own_facts() {
    let held = |fact: LabFact| Seen { what: fact.name(), state: State::Holds, errno: None, detail: String::new() };
    let v = check_with(profile("inherited-fds"), &Findings::empty(), &held);
    assert!(v.holds(), "{v:?}");
}

#[test]
fn one_fail_beats_an_unseen_in_a_part() {
    // bind-denied/tcp-bind-refused: a row that fails and a lab fact unseen.
    let v = check(profile("bind-denied"), &findings(&[("bind(127.0.0.1:0)+listen", Outcome::ok())]));
    assert_eq!(part(&v, "tcp-bind-refused").state, State::Fails);
    assert_eq!(part(&v, "tcp-connect-refused").state, State::Unseen);
}

#[test]
fn landlock_old_holds_with_no_landlock_or_an_old_abi() {
    let p = profile("landlock-old");
    let row = "landlock_create_ruleset(VERSION)";
    assert!(check(p, &findings(&[(row, Outcome::denied(ENOSYS))])).holds());
    assert!(check(p, &findings(&[(row, Outcome::ok_with("ABI 3"))])).holds());
    assert!(check(p, &findings(&[(row, Outcome::ok_with("ABI 4"))])).fails());
    assert_eq!(check(p, &findings(&[(row, Outcome::ok_with("no number"))])).parts[0].state, State::Unseen);
    assert_eq!(check(p, &findings(&[(row, Outcome::denied(EPERM))])).parts[0].state, State::Unseen);
}

#[test]
fn the_identity_facts_read_the_status_fields() {
    let p = profile("nonroot-nocaps");
    let mut f = findings(&[
        ("setuid(0)", Outcome::denied(EPERM)),
        ("mknod(chr 1:3 /tmp/nodprobe)", Outcome::denied(EPERM)),
        ("ptrace(PTRACE_TRACEME)", Outcome::denied(EPERM)),
    ]);
    f.identity.uid = 1000;
    f.identity.cap_eff = Some("0000000000000000".to_string());
    f.identity.no_new_privs = Some("1".to_string());
    f.identity.seccomp = Some("2".to_string());
    assert!(check(p, &f).holds(), "{:?}", check(p, &f));
    f.identity.uid = 0;
    f.identity.cap_eff = Some("000001ffffffffff".to_string());
    f.identity.seccomp = None;
    let v = check(p, &f);
    assert_eq!(part(&v, "not-root").state, State::Fails);
    assert_eq!(part(&v, "no-caps").state, State::Fails);
    assert_eq!(part(&v, "no-new-privs").state, State::Holds);
    assert_eq!(part(&v, "seccomp-filter").state, State::Unseen);
}

#[test]
fn a_part_with_no_observation_at_all_is_unseen() {
    assert_eq!(PartVerdict::new("x", Vec::new()).state, State::Unseen);
}

#[cfg(feature = "report")]
#[test]
fn a_report_of_pod_hostprobe_checks_as_its_findings() {
    use pod_hostprobe::select::Selection;
    let f = findings(&[("chroot(/tmp)", Outcome::denied(EPERM))]);
    let text = pod_hostprobe::report::write(&f, &Selection::choose(&f));
    let v = check_report(profile("chroot-denied"), &text).expect("the report reads");
    assert!(v.holds(), "{v:?}");
    assert!(check_report(profile("chroot-denied"), "{}").is_err());
}
