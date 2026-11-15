//! A reader of the Rust source of a program for the checks of its facts:
//! the variables that the code reads or sets, and the constants of its
//! exit codes. It reads the text, not the syntax tree: a test of each
//! program proves that it finds a planted name.

use std::path::{Path, PathBuf};

/// Each `.rs` file under `dirs`, with its test-only items removed
/// ([`non_test`]). A file `tests.rs` or `*_tests.rs`, a directory `tests`,
/// and the file of a test-only module (`#[cfg(test)] mod name;`) are test
/// code, and are left out.
pub fn rust_sources(dirs: &[PathBuf]) -> Vec<(PathBuf, String)> {
    let mut files = Vec::new();
    let mut todo: Vec<PathBuf> = dirs.to_vec();
    while let Some(dir) = todo.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        let mut entries: Vec<PathBuf> = entries.flatten().map(|e| e.path()).collect();
        entries.sort();
        for path in entries {
            let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if path.is_dir() {
                if name != "tests" {
                    todo.push(path);
                }
            } else if path.extension().is_some_and(|e| e == "rs")
                && name != "tests.rs"
                && !name.ends_with("_tests.rs")
                && let Ok(text) = std::fs::read_to_string(&path)
            {
                files.push((path, text));
            }
        }
    }
    let mut skip: Vec<PathBuf> = Vec::new();
    for (path, text) in &files {
        for module in test_modules(text) {
            let dir = path.parent().unwrap_or(Path::new(""));
            let stem = path.file_stem().and_then(|s| s.to_str()).unwrap_or("");
            let base = if matches!(stem, "lib" | "main" | "mod") { dir.to_path_buf() } else { dir.join(stem) };
            skip.push(base.join(format!("{module}.rs")));
            skip.push(base.join(&module));
        }
    }
    files.sort();
    files
        .into_iter()
        .filter(|(p, _)| !skip.iter().any(|s| p == s || p.starts_with(s)))
        .map(|(p, text)| (p, non_test(&text)))
        .collect()
}

/// The marks of an item that only the tests compile.
const TEST_MARKS: &[&str] = &["#[cfg(test)]", "#[cfg(all(test,"];

/// The names of the test-only modules that `text` declares with no body:
/// `#[cfg(test)] mod name;`.
fn test_modules(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for mark in TEST_MARKS {
        for (at, _) in text.match_indices(mark) {
            let rest = &text[at..];
            let Some(close) = rest.find("]\n") else { continue };
            let item = rest[close + 1..].trim_start();
            let item = item.strip_prefix("pub(crate) ").or_else(|| item.strip_prefix("pub ")).unwrap_or(item);
            if let Some(decl) = item.strip_prefix("mod ")
                && let Some((name, _)) = decl.split_once(';').filter(|(n, _)| !n.contains('{'))
            {
                out.push(name.trim().to_string());
            }
        }
    }
    out
}

/// `text` without its test-only items: each `#[cfg(test)]` drops the item
/// that follows it, a line such as `use ...;` or `mod tests;`, or a block
/// such as `mod tests { ... }`, and nothing more.
pub fn non_test(text: &str) -> String {
    let mut out = String::new();
    let mut rest = text;
    while let Some(at) = TEST_MARKS.iter().filter_map(|m| rest.find(m)).min() {
        out.push_str(&rest[..at]);
        // The item starts after the attribute: after its `]` at the end of
        // a line.
        let Some(close) = rest[at..].find("]\n") else { return out };
        let item = &rest[at + close + 1..];
        let (semi, brace) = (item.find(';'), item.find('{'));
        let end = match (semi, brace) {
            (Some(s), Some(b)) if s < b => Some(s + 1),
            (Some(s), None) => Some(s + 1),
            (_, Some(b)) => block_end(item, b),
            (None, None) => None,
        };
        // An item with no end hides the rest.
        let Some(end) = end else { return out };
        rest = &item[end..];
    }
    out.push_str(rest);
    out
}

/// The offset just after the brace that closes the one at `open`.
fn block_end(text: &str, open: usize) -> Option<usize> {
    let mut depth = 0usize;
    for (i, c) in text[open..].char_indices() {
        match c {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(open + i + 1);
                }
            }
            _ => {}
        }
    }
    None
}

/// The calls whose first argument is the name of a variable.
const CALLS: &[&str] = &["var(", "var_os(", "getenv(", "env(", "env_remove(", "remove_var(", "set_var(", "env = "];

/// The names of variables in `code`: the first argument of a call of
/// `CALLS` (`env::var("X")`, `Command::env("X", ..)`, clap's
/// `env = "X"`), a constant `X_VARIABLE: &str = "NAME"`, and each quoted
/// word shaped like a variable (capitals, digits and `_`, with a `_`; or a
/// lower-case `*_proxy`). A name that the compiler reads (`env!`,
/// `option_env!`) and a name of cargo (`CARGO_*`) is no variable of a run.
pub fn variables_read(code: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for (i, _) in code.match_indices('"') {
        let rest = &code[i + 1..];
        let Some(end) = rest.find('"') else { continue };
        let word = &rest[..end];
        let shaped = word.contains('_')
            && !word.ends_with('_')
            && word.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
            && word.starts_with(|c: char| c.is_ascii_uppercase())
            || word.ends_with("_proxy") && word.chars().all(|c| c.is_ascii_lowercase() || c == '_');
        let before = &code[..i];
        let called = CALLS.iter().any(|c| before.ends_with(c)) || before.trim_end().ends_with("_VARIABLE: &str =");
        let named = !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        let compiled = before.ends_with("env!(");
        if (shaped || called && named) && !compiled && !word.starts_with("CARGO_") && !out.iter().any(|w| w == word) {
            out.push(word.to_string());
        }
    }
    out
}

/// The constants of exit codes in `code`: `const PREFIX...: i32 = N;` (or
/// `u8`), with their values.
pub fn exit_constants(code: &str, prefix: &str) -> Vec<(String, i32)> {
    let mut out = Vec::new();
    for line in code.lines() {
        let line = line.trim();
        let Some(rest) = line.split("const ").nth(1) else { continue };
        let Some((name, rest)) = rest.split_once(':') else { continue };
        let name = name.trim();
        if !name.starts_with(prefix) {
            continue;
        }
        let Some((ty, value)) = rest.split_once('=') else { continue };
        if !matches!(ty.trim(), "i32" | "u8") {
            continue;
        }
        if let Ok(n) = value.trim().trim_end_matches(';').trim().parse::<i32>() {
            out.push((name.to_string(), n));
        }
    }
    out
}

/// The directory `src` of the crate at `manifest_dir`, for
/// [`rust_sources`]: `scan::src(env!("CARGO_MANIFEST_DIR"))`.
pub fn src(manifest_dir: &str) -> PathBuf {
    Path::new(manifest_dir).join("src")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The control of [`non_test`]: a read after a test-only import counts,
    /// a read inside a test-only block does not.
    #[test]
    fn a_test_only_item_hides_itself_alone() {
        let text = "use a;\n#[cfg(test)]\nuse b::{c, d};\nconst X: &str = \"READ_AFTER\";\n\
            #[cfg(test)]\nmod tests {\n    fn f() { let _ = \"IN_TESTS\"; }\n}\nconst Y: &str = \"READ_LAST\";\n";
        let kept = non_test(text);
        assert_eq!(variables_read(&kept), vec!["READ_AFTER", "READ_LAST"], "{kept}");
        assert!(kept.contains("use a;") && !kept.contains("use b::"), "{kept}");
    }

    /// The control of the reader: it finds a planted variable.
    #[test]
    fn the_reader_finds_a_planted_variable() {
        let code = r#"let a = std::env::var("PLANTED_NAME"); let b = var_os("Plain"); let c = "not a var"; "PREFIX_";
            let d = option_env!("BUILT_NAME"); let e = env!("BUILT_TOO"); let f = "LATER_NAME";
            cmd.env("TMPDIR", "/tmp"); #[arg(env = "FROM_CLAP")] const PROXY_VARIABLE: &str = "PODNET_X";"#;
        assert_eq!(
            variables_read(code),
            vec!["PLANTED_NAME", "Plain", "LATER_NAME", "TMPDIR", "FROM_CLAP", "PODNET_X"]
        );
    }

    /// A test-only module of another form, and its file, are test code.
    #[test]
    fn a_test_only_module_and_its_file_are_left_out() {
        let dir = std::env::temp_dir().join(format!("pod-manual-scan-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lab")).unwrap();
        let lib = "mod lab;\n#[cfg(all(test, target_os = \"linux\"))]\nmod text;\nconst A: &str = \"READ_LIB\";\n";
        std::fs::write(dir.join("lib.rs"), lib).unwrap();
        std::fs::write(dir.join("text.rs"), "const B: &str = \"IN_TEXT\";").unwrap();
        std::fs::write(dir.join("lab.rs"), "#[cfg(test)]\nmod inner;\nconst C: &str = \"READ_LAB\";").unwrap();
        std::fs::write(dir.join("lab/inner.rs"), "const D: &str = \"IN_INNER\";").unwrap();
        let found: Vec<String> =
            rust_sources(std::slice::from_ref(&dir)).iter().flat_map(|(_, t)| variables_read(t)).collect();
        let _ = std::fs::remove_dir_all(&dir);
        assert_eq!(found, ["READ_LAB", "READ_LIB"]);
    }

    #[test]
    fn the_exit_constants_are_found_with_their_values() {
        let code = "pub const EXIT_USAGE: i32 = 64;\nconst EXIT_X: u8 = 3;\nconst OTHER: i32 = 1;\n// const EXIT_NOTE: &str = \"x\";";
        assert_eq!(exit_constants(code, "EXIT_"), [("EXIT_USAGE".to_string(), 64), ("EXIT_X".to_string(), 3)]);
    }
}
