use super::*;

#[test]
fn the_rules_find_each_fault() {
    for bad in [
        "see T-692",
        "call C673",
        "PodUtils/podvm#424",
        "issue #12 says",
        "a\u{7}bell",
        "ok \u{1F600}",
        "Q12 waits",
        "the ruling Q-A8",
        "COORD-090 asks",
        "colour \u{1b}[31mred",
        "a star \u{2B50}",
        "a check \u{2705}",
        "a flag \u{1F1FA}\u{1F1F8}",
        "hidden \u{202E}txt",
        "a heart \u{2764}\u{FE0F}",
    ] {
        assert!(!faults(bad, Kind::Description).is_empty(), "{bad:?}");
    }
    for good in [
        "chroot(/tmp) gives EPERM",
        "TCP bind\tand\nconnect",
        "CapEff is 0",
        "AF_INET6",
        "Concat",
        "PART-2",
        "PKCS#1 keys",
        "C1x is a word",
        "128+N",
        "64-80",
        "x86_64-unknown-linux-musl",
        "--format {{.ID}}",
    ] {
        assert_eq!(faults(good, Kind::Description), vec![], "{good:?}");
    }
}

#[test]
fn the_work_ids_are_found_with_their_text() {
    assert_eq!(work_ids("T-700 and C681, Q12; #181 and podnet#584"), ["T-700", "C681", "Q12", "#181", "#584"]);
    assert_eq!(work_ids("PKCS#1 ABC12 x-T-1"), Vec::<String>::new());
}

#[test]
fn a_sentence_ends_at_a_stop_a_semicolon_a_colon_or_a_line() {
    assert_eq!(
        sentences("One two. Three: four; five\nsix? warp.json stays"),
        ["One two.", "Three:", "four;", "five", "six?", "warp.json stays"]
    );
    assert_eq!(words("Run -x, then 42 -- ."), 4);
}

#[test]
fn each_kind_has_its_limit() {
    let at = |n: usize| "word ".repeat(n);
    assert!(faults(&at(25), Kind::Description).is_empty());
    assert!(matches!(faults(&at(26), Kind::Description)[..], [Fault::Long { words: 26, limit: 25, .. }]));
    assert!(faults(&at(20), Kind::Procedure).is_empty());
    assert!(matches!(faults(&at(21), Kind::Procedure)[..], [Fault::Long { words: 21, limit: 20, .. }]));
}

#[test]
fn bytes_that_are_not_utf8_are_a_fault() {
    assert_eq!(byte_faults(b"ok \xff no", Kind::Description), vec![Fault::NotUtf8(3)]);
    assert!(byte_faults("ok".as_bytes(), Kind::Description).is_empty());
}

#[test]
fn each_fault_reads_as_text() {
    let text = Fault::Long { words: 30, limit: 25, sentence: "x".into() }.to_string();
    assert!(text.starts_with("a sentence of 30 words"), "{text}");
    assert_eq!(Fault::Emoji('\u{1F600}').to_string(), "the emoji or pictograph U+1F600");
}
