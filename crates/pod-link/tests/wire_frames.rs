//! The cases of `tests/wire/frames.txt`: each input to the decoder, with
//! the frames or the error that it must give (`WIRE.md`, W-01 to W-08). A
//! failure names the case. Each case that decodes also encodes: the
//! frames give the bytes of the case again.

use pod_link::frame::PREFACE;
use pod_link::{Decoder, Frame};

const CASES: &str = include_str!("wire/frames.txt");

/// One line of the file.
struct Case<'a> {
    id: &'a str,
    preface: bool,
    split: usize,
    bytes: Vec<u8>,
    result: &'a str,
}

/// The bytes of a HEX field: pieces joined by a dot, each hex digits with
/// an optional `*N`.
fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    for piece in text.split('.') {
        let (digits, times) = match piece.split_once('*') {
            Some((d, n)) => (d, n.parse::<usize>().map_err(|_| format!("the count of {piece:?}"))?),
            None => (piece, 1),
        };
        if digits.is_empty() || digits.len() % 2 == 1 {
            return Err(format!("the piece {piece:?} is not whole bytes"));
        }
        let one = (0..digits.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&digits[i..i + 2], 16).map_err(|_| format!("the piece {piece:?}")))
            .collect::<Result<Vec<u8>, String>>()?;
        for _ in 0..times {
            out.extend_from_slice(&one);
        }
    }
    Ok(out)
}

/// The bytes in the form of HEX: a run of 4 or more equal bytes is one
/// piece `bb*N`, and the other bytes join into pieces of hex digits.
fn compact(bytes: &[u8]) -> String {
    let mut pieces: Vec<String> = Vec::new();
    let mut literal = String::new();
    let mut i = 0;
    while i < bytes.len() {
        let run = bytes[i..].iter().take_while(|&&b| b == bytes[i]).count();
        if run >= 4 {
            if !literal.is_empty() {
                pieces.push(std::mem::take(&mut literal));
            }
            pieces.push(format!("{:02x}*{run}", bytes[i]));
            i += run;
        } else {
            literal.push_str(&format!("{:02x}", bytes[i]));
            i += 1;
        }
    }
    if !literal.is_empty() {
        pieces.push(literal);
    }
    pieces.join(".")
}

fn show(frame: &Frame) -> String {
    match frame {
        Frame::Data(id, body) => format!("Data({id}, {})", compact(body)),
        other => format!("{other:?}"),
    }
}

fn parse(line: &str) -> Result<Case<'_>, String> {
    let (input, result) = line.split_once(" => ").ok_or("no \" => \"")?;
    let [id, preface, split, hex] = input.split(' ').collect::<Vec<_>>()[..] else {
        return Err("not ID PREFACE SPLIT HEX".into());
    };
    let preface = match preface {
        "yes" => true,
        "no" => false,
        other => return Err(format!("the preface {other:?}")),
    };
    let split = match split {
        "all" => usize::MAX,
        n => n.parse().map_err(|_| format!("the split {n:?}"))?,
    };
    Ok(Case { id, preface, split, bytes: unhex(hex)?, result })
}

/// Run a case: the frames, and the error with the frames before it.
fn run(case: &Case) -> (String, Vec<Frame>, usize) {
    let mut decoder = if case.preface { Decoder::with_preface() } else { Decoder::new() };
    let mut frames = Vec::new();
    for piece in case.bytes.chunks(case.split.min(case.bytes.len()).max(1)) {
        decoder.push(piece);
        loop {
            match decoder.next() {
                Ok(Some(f)) => frames.push(f),
                Ok(None) => break,
                Err(e) => {
                    // W-08: the same error again, and no more bytes taken.
                    assert_eq!(decoder.next(), Err(e.clone()), "{}: the error does not stay", case.id);
                    decoder.push(&[1; 16]);
                    assert_eq!(decoder.buffered(), 0, "{}: the decoder took bytes after its error", case.id);
                    let list = frames.iter().map(show).collect::<Vec<_>>().join("; ");
                    let text = if list.is_empty() { format!("err {e:?}") } else { format!("err {e:?} after {list}") };
                    return (text, frames, 0);
                }
            }
        }
    }
    let list = frames.iter().map(show).collect::<Vec<_>>().join("; ");
    let text = if list.is_empty() { "ok".to_string() } else { format!("ok {list}") };
    (text, frames, decoder.buffered())
}

#[test]
fn each_case_of_the_frame_file() {
    let mut count = None;
    let mut faults = Vec::new();
    let mut ids = std::collections::BTreeSet::new();
    let mut seen = 0;
    for line in CASES.lines() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(n) = line.strip_prefix("count ") {
            count = Some(n.parse::<usize>().expect("the count line has a number"));
            continue;
        }
        seen += 1;
        let case = match parse(line) {
            Ok(c) => c,
            Err(e) => {
                faults.push(format!("the line {line:.60}: {e}"));
                continue;
            }
        };
        if !ids.insert(case.id) {
            faults.push(format!("{}: the id is used twice", case.id));
        }
        let (got, frames, buffered) = run(&case);
        if got != case.result {
            faults.push(format!("{}: the decoder gives {got:.200}", case.id));
            continue;
        }
        if got.starts_with("ok") {
            // The fixed widths make the encoding unique: the frames give the
            // bytes that the decoder took.
            let taken = &case.bytes[..case.bytes.len() - buffered];
            let mut again = if case.preface && taken.len() >= PREFACE.len() { PREFACE.to_vec() } else { Vec::new() };
            for f in &frames {
                f.encode(&mut again).expect("a decoded frame encodes");
            }
            if again != taken {
                faults.push(format!("{}: the frames encode to {:.200}", case.id, compact(&again)));
            }
        }
    }
    if count != Some(seen) {
        faults.push(format!("the count line says {count:?}, the file has {seen} cases"));
    }
    assert!(faults.is_empty(), "tests/wire/frames.txt:\n{}", faults.join("\n"));
}

#[test]
fn the_file_has_twenty_valid_and_twenty_invalid_cases() {
    let results: Vec<&str> =
        CASES.lines().filter(|l| !l.starts_with('#')).filter_map(|l| l.split_once(" => ")).map(|(_, r)| r).collect();
    let ok = results.iter().filter(|r| r.starts_with("ok")).count();
    let err = results.iter().filter(|r| r.starts_with("err")).count();
    assert!(ok >= 20 && err >= 20, "{ok} valid and {err} invalid cases");
}
