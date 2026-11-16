//! The seeds of the fuzz target `link_frame`: one seed for each case of
//! `crates/pod-link/tests/wire/frames.txt` with at most [`MAX_SEED`] bytes
//! of input, in the form of the target (a first byte of the split and the
//! preface, then the bytes). The seeds on disk are the ones that this file
//! makes, and no other. Write them again with
//! `cargo test --manifest-path fuzz/Cargo.toml --lib write_the_link_frame_seeds -- --ignored`.

use std::path::PathBuf;

const CASES: &str = include_str!("../../crates/pod-link/tests/wire/frames.txt");

/// The most input bytes of a case that becomes a seed: a body of 1 MiB
/// stays out of the tree.
const MAX_SEED: usize = 4096;

/// The bytes of a HEX field of the case file: pieces joined by a dot, each
/// hex digits with an optional `*N`.
fn unhex(text: &str) -> Vec<u8> {
    let mut out = Vec::new();
    for piece in text.split('.') {
        let (digits, times) = piece.split_once('*').map_or((piece, 1), |(d, n)| (d, n.parse().expect("a count")));
        let one: Vec<u8> =
            (0..digits.len()).step_by(2).map(|i| u8::from_str_radix(&digits[i..i + 2], 16).expect("hex")).collect();
        for _ in 0..times {
            out.extend_from_slice(&one);
        }
    }
    out
}

/// The name and the bytes of each seed.
fn seeds() -> Vec<(String, Vec<u8>)> {
    let mut out = Vec::new();
    for line in CASES.lines().filter(|l| !l.starts_with('#') && !l.starts_with("count ")) {
        let Some((input, _)) = line.split_once(" => ") else { continue };
        let [id, preface, split, hex] = input.split(' ').collect::<Vec<_>>()[..] else {
            panic!("the case {line:.60} is not ID PREFACE SPLIT HEX")
        };
        let bytes = unhex(hex);
        if bytes.len() > MAX_SEED {
            continue;
        }
        // The target pushes pieces of 1 to 64 bytes: `all` is 64.
        let step = if split == "all" { 64 } else { split.parse::<u8>().expect("a split").min(64) };
        let mut seed = vec![((step - 1) << 1) | u8::from(preface == "yes")];
        seed.extend_from_slice(&bytes);
        out.push((format!("case-{id}"), seed));
    }
    out
}

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("seeds").join("link_frame")
}

/// The seeds on disk are the ones of [`seeds`], and the target takes each.
#[test]
fn the_seeds_of_link_frame_are_the_cases_of_the_frame_file() {
    let want = seeds();
    assert!(want.len() > 40, "{} seeds", want.len());
    let mut on_disk: Vec<String> = std::fs::read_dir(dir())
        .expect("the seeds of link_frame")
        .map(|e| e.expect("a seed").file_name().into_string().expect("a name"))
        .collect();
    on_disk.sort();
    let mut names: Vec<String> = want.iter().map(|(n, _)| n.clone()).collect();
    names.sort();
    assert_eq!(on_disk, names, "the seeds of link_frame are stale: run write_the_link_frame_seeds");
    for (name, bytes) in want {
        let file = std::fs::read(dir().join(&name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(file == bytes, "{name} is stale: run write_the_link_frame_seeds");
        crate::targets::link_frame(&bytes);
    }
}

#[test]
#[ignore = "writes the seeds of link_frame into fuzz/seeds/link_frame"]
fn write_the_link_frame_seeds() {
    let _ = std::fs::remove_dir_all(dir());
    std::fs::create_dir_all(dir()).unwrap();
    for (name, bytes) in seeds() {
        std::fs::write(dir().join(name), bytes).unwrap();
    }
}
