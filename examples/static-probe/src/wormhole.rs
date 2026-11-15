//! pod-wormhole: a code of words, a sealed message of the client protocol,
//! and a run of the taker over no mailbox, so that SPAKE2, SecretBox, the
//! mailbox client and the way link in.

pub fn wormhole() -> String {
    let provider = std::sync::Arc::new(pod_tls::crypto::provider());
    let tls = pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("static-probe")));
    let settings = pod_proxy::Settings::new("static-probe", pod_proxy::ProxyChoice::Direct);
    let dialer = pod_proxy::Dialer::new(settings, std::sync::Arc::new(pod_proxy::resolve::System::new()));
    let way = pod_ws::Way::new(std::sync::Arc::new(tls), std::sync::Arc::new(dialer), "static-probe");
    let config = pod_wormhole::Config::new("example.org/static-probe", "static-probe", "0", way);
    let Ok(code) = pod_wormhole::Code::make("7", pod_wormhole::WORDS, &mut pod_core::entropy::OsEntropy) else {
        return "pod-wormhole: no random bytes".into();
    };
    let sealed = pod_wormhole::wormhole::seal(&[7; 32], b"probe").map_or(0, |bytes| bytes.len());
    let ends = pod_wormhole::Ends { mailboxes: Vec::new(), config };
    let run = tokio::runtime::Builder::new_current_thread().enable_all().build().map_or_else(
        |e| e.to_string(),
        |runtime| {
            let met = pod_wormhole::joined(&ends, &code, Default::default(), std::time::Duration::ZERO);
            runtime.block_on(met).err().map_or_else(|| "met".into(), |failed| failed.to_string())
        },
    );
    format!("pod-wormhole: a code of {} words, {sealed} bytes sealed, taker: {run}", code.words())
}
