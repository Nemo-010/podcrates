//! The text forms of the case files of the wire (`tests/wire/frames.txt`,
//! `tests/cases/`): bytes as HEX pieces, and a frame as its `Debug` form
//! with the body of a `Data` as HEX.

use pod_link::Frame;

/// The bytes of a HEX field: pieces joined by a dot, each hex digits with
/// an optional `*N` for N copies.
pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
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
pub fn compact(bytes: &[u8]) -> String {
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

/// The text of a frame: its `Debug` form, with the body of a `Data` as HEX.
pub fn show(frame: &Frame) -> String {
    match frame {
        Frame::Data(id, body) => format!("Data({id}, {})", compact(body)),
        other => format!("{other:?}"),
    }
}

/// A frame from its text, the form of [`show`].
pub fn frame(text: &str) -> Result<Frame, String> {
    let bad = || format!("the frame {text:?}");
    let (name, rest) = text.split_once('(').ok_or_else(bad)?;
    let args: Vec<&str> = rest.strip_suffix(')').ok_or_else(bad)?.split(", ").collect();
    let n = |i: usize| -> Result<u64, String> { args.get(i).and_then(|a| a.parse().ok()).ok_or_else(bad) };
    let id = || n(0).and_then(|v| u32::try_from(v).map_err(|_| bad()));
    let word = |i| n(i).and_then(|v| u32::try_from(v).map_err(|_| bad()));
    Ok(match (name, args.len()) {
        ("Open", 1) => Frame::Open(id()?),
        ("Data", 2) => Frame::Data(id()?, unhex(args[1])?),
        ("Window", 2) => Frame::Window(id()?, word(1)?),
        ("Close", 1) => Frame::Close(id()?),
        ("Reset", 2) => Frame::Reset(id()?, word(1)?),
        ("Ping", 1) => Frame::Ping(n(0)?),
        ("Pong", 1) => Frame::Pong(n(0)?),
        ("GoAway", 1) => Frame::GoAway(word(0)?),
        _ => return Err(bad()),
    })
}
