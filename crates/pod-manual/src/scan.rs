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

/// The functions whose first argument is the name of a variable: Rust's
/// `std::env` and `Command`, clap's builder (`.env("X")`), and C.
pub const CALLS: &[&str] =
    &["var", "var_os", "set_var", "remove_var", "env", "env_remove", "getenv", "secure_getenv", "setenv", "unsetenv"];

/// The suffixes of the name of a constant that holds the names of
/// variables: `const PROXY_VARIABLE: &str = "HTTPS_PROXY";` or
/// `const PROXY_VARIABLES: &[&str] = &["HTTPS_PROXY", "https_proxy"];`.
/// A program names so each variable that it reads by a name that is not a
/// literal of a call.
pub const LISTS: &[&str] = &["_VARIABLE", "_VARIABLES"];

/// The name of the function that `before` calls: `std::env::var(` gives
/// `var`. A macro (`env!(`, `option_env!(`) gives none.
fn callee(before: &str) -> Option<&str> {
    let before = before.trim_end().strip_suffix('(')?.trim_end();
    let start = before.rfind(|c: char| !(c.is_ascii_alphanumeric() || c == '_')).map_or(0, |i| i + 1);
    Some(&before[start..]).filter(|n| !n.is_empty())
}

/// Whether the literal after `before` is the value of clap's `env = "X"`
/// of the derive form.
fn clap_env(before: &str) -> bool {
    let Some(rest) = before.trim_end().strip_suffix('=') else { return false };
    let rest = rest.trim_end();
    rest.strip_suffix("env").is_some_and(|r| r.ends_with(['(', ',', ' ', '\n']))
}

/// Whether the literal at `at` is in the value of a constant or a static
/// whose name ends in one of [`LISTS`].
fn in_list(code: &str, at: usize) -> bool {
    let head = &code[..at];
    let Some(decl) = [head.rfind("const "), head.rfind("static ")].into_iter().flatten().max() else {
        return false;
    };
    let decl = &head[decl..];
    let name = decl.split_whitespace().nth(1).unwrap_or("").trim_end_matches(':');
    let value = decl.split_once('=').map_or(";", |(_, v)| v);
    !value.contains(';') && LISTS.iter().any(|l| name.ends_with(l))
}

/// The names of the variables that `code` reads or sets: the first
/// argument of a call of [`CALLS`] (`env::var("X")`, `Command::env("X",
/// ..)`, `getenv("X")` of C, clap's `.env("X")`), clap's `env = "X"`, and
/// each name in a constant of [`LISTS`]. A quoted word of the form of a
/// variable elsewhere (a constant of C, the name of a hash) is no
/// variable. A name that the compiler reads (`env!`, `option_env!`) is a
/// variable of the build, not of a run, and a name of cargo (`CARGO_*`) is
/// none.
pub fn variables_read(code: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut at = 0;
    while let Some(i) = code[at..].find('"').map(|i| i + at) {
        let rest = &code[i + 1..];
        let Some(end) = rest.find('"') else { break };
        let word = &rest[..end];
        at = i + 1 + end + 1;
        // A C string of Rust: `getenv(c"X".as_ptr())`.
        let before = code[..i].strip_suffix('c').unwrap_or(&code[..i]);
        let called = callee(before).is_some_and(|c| CALLS.contains(&c)) || clap_env(before) || in_list(code, i);
        let named = !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
        if called && named && !word.starts_with("CARGO_") && !out.iter().any(|w| w == word) {
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
        let text = "use a;\n#[cfg(test)]\nuse b::{c, d};\nconst X_VARIABLE: &str = \"READ_AFTER\";\n\
            #[cfg(test)]\nmod tests {\n    fn f() { let _ = var(\"IN_TESTS\"); }\n}\nconst Y: &str = var(\"READ_LAST\");\n";
        let kept = non_test(text);
        assert_eq!(variables_read(&kept), vec!["READ_AFTER", "READ_LAST"], "{kept}");
        assert!(kept.contains("use a;") && !kept.contains("use b::"), "{kept}");
    }

    /// The control of the reader: it finds a planted variable in each form
    /// of a read, and no quoted word that only has the form of a variable.
    #[test]
    fn the_reader_finds_a_planted_variable() {
        let code = r#"let a = std::env::var("PLANTED_NAME"); let b = var_os("Plain"); let c = "not a var"; "PREFIX_";
            let d = option_env!("BUILT_NAME"); let e = env!("BUILT_TOO"); let f = "LATER_NAME";
            cmd.env("TMPDIR", "/tmp"); #[arg(long, env = "FROM_CLAP")] const PROXY_VARIABLE: &str = "PODNET_X";
            Arg::new("x").env("FROM_BUILDER"); libc::getenv(c"FROM_C".as_ptr()); getenv ( "SPACED" );
            const LIST_VARIABLES: &[&str] = &["IN_LIST", "in_list_too"]; std::env::set_var("SET_ONE", "1");"#;
        assert_eq!(
            variables_read(code),
            vec![
                "PLANTED_NAME",
                "Plain",
                "TMPDIR",
                "FROM_CLAP",
                "PODNET_X",
                "FROM_BUILDER",
                "FROM_C",
                "SPACED",
                "IN_LIST",
                "in_list_too",
                "SET_ONE"
            ]
        );
    }

    /// The quoted words of podnet that have the form of a variable and are
    /// none: constants of C, the name of a crate and of a hash.
    #[test]
    fn a_word_of_the_form_of_a_variable_is_no_read() {
        let code = r#"let f = libc_name("F_GETFL"); const OPTS: &[&str] = &["SO_ORIGINAL_DST", "AF_INET", "AF_INET6"];
            let h = Hash::named("SHA2_256"); let c = "pod_proxy"; let t = "https_proxy"; fn x(s: &str) {}
            x("F_SETFL"); let env_name = "NOT_READ"; reverse("ALSO_NOT");"#;
        assert_eq!(variables_read(code), Vec::<String>::new());
    }

    /// A test-only module of another form, and its file, are test code.
    #[test]
    fn a_test_only_module_and_its_file_are_left_out() {
        let dir = std::env::temp_dir().join(format!("pod-manual-scan-{}", std::process::id()));
        std::fs::create_dir_all(dir.join("lab")).unwrap();
        let lib =
            "mod lab;\n#[cfg(all(test, target_os = \"linux\"))]\nmod text;\nconst A_VARIABLE: &str = \"READ_LIB\";\n";
        std::fs::write(dir.join("lib.rs"), lib).unwrap();
        std::fs::write(dir.join("text.rs"), "const B_VARIABLE: &str = \"IN_TEXT\";").unwrap();
        std::fs::write(dir.join("lab.rs"), "#[cfg(test)]\nmod inner;\nconst C_VARIABLE: &str = \"READ_LAB\";").unwrap();
        std::fs::write(dir.join("lab/inner.rs"), "const D_VARIABLE: &str = \"IN_INNER\";").unwrap();
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
