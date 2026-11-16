//! The rows of the classes of podssh and podnet (sockets, files, the way
//! out) on this host, each in its probe child, against what the test reads
//! itself. As root the test runs, then starts itself again as uid 65534
//! with no capability, where the raw socket and the file in `HOME` give
//! another answer. With no libtest (`harness = false`): the binary reads
//! the flag of a probe child first, and has one thread, so it can set the
//! variables that a child inherits.

#[cfg(target_os = "linux")]
fn main() {
    use pod_hostprobe::{Settings, run_child};
    use pod_testkit::host::skip_line;
    use pod_testkit::nobody;

    let settings = Settings::default();
    let args: Vec<String> = std::env::args().collect();
    if args.get(1) == Some(&settings.child_flag) {
        let name = args.get(2).map_or("", String::as_str);
        std::process::exit(run_child(name, &mut std::io::stdout()));
    }
    let again = args.get(1).map(String::as_str) == Some(rows::AGAIN);
    rows::check(&settings, again);
    if nobody::is_root() && !again {
        // `/` of root is not writable for uid 65534: the file in `HOME`
        // gives EACCES there.
        match nobody::again(&[rows::AGAIN], &[("HOME", "/")]) {
            Ok(0) => {}
            Ok(code) => std::process::exit(code),
            Err(why) => skip_line(&why),
        }
    }
}

#[cfg(target_os = "linux")]
#[path = "host_rows/rows.rs"]
mod rows;

#[cfg(not(target_os = "linux"))]
fn main() {}
