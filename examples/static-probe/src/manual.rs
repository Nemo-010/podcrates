//! pod-manual: a model from a clap tree with the exit codes of the failure
//! classes, each writer, the help, a section through the pager with no
//! terminal, and the text rules.

pub fn manual() -> String {
    let cmd =
        clap::Command::new("probe").about("the static probe").subcommand(clap::Command::new("run").about("Run it"));
    let mut m = pod_manual::clap::read(cmd);
    m.facts.exits = pod_manual::facts::failure_classes();
    let json = pod_manual::json::text(&pod_manual::json::document(&m));
    let llms = pod_manual::llms::from_json(&json, &[], "").map_or_else(|e| e, |f| format!("{} bytes", f.index.len()));
    let help = pod_manual::help::render(&m, &["run".to_string()]).unwrap_or_default();
    let req = pod_manual::Request { section: Some("exit-status".into()), ..Default::default() };
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let tty = pod_manual::pager::Tty::none();
    let ran = pod_manual::run(&m, &req, tty, &mut std::io::empty(), &mut out, &mut err);
    format!(
        "pod-manual: {} bytes of text, {} of roff, {} of help, llms {llms}, section {} bytes {:?}, {} findings",
        pod_manual::text::render(&m).len(),
        pod_manual::roff::render(&m).len(),
        help.len(),
        out.len(),
        ran,
        pod_manual::check::texts(&m).len()
    )
}
