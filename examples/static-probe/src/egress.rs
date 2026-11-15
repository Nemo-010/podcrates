//! pod-egress: a dialer of each road whose deadline is now, so that each
//! road links in and nothing connects; the arguments of a meek_lite and a
//! WebTunnel bridge, and the upgrade of the Access road.

use std::sync::Arc;
use std::time::Duration;

use pod_core::{Dial, Target};
use pod_egress::{AtEnd, Note, forwarder, via, wstunnel};
use pod_tls::Trust;

pub fn egress() -> String {
    let provider = Arc::new(pod_tls::crypto::provider());
    let tls = pod_tls::Context::new(provider, pod_tls::Settings::new(pod_tls::Words::new("static-probe")));
    let settings = pod_proxy::Settings::new("static-probe", pod_proxy::ProxyChoice::Direct);
    let dialer = pod_proxy::Dialer::new(settings, Arc::new(pod_proxy::resolve::System::new()));
    let way = pod_ws::Way::new(Arc::new(tls), Arc::new(dialer), "static-probe");
    let wait = Duration::from_secs(1);
    let note: Note = Arc::new(pod_core::NoEvents);
    let mut dialers: Vec<Box<dyn Dial>> = Vec::new();
    if let Ok(proxy) = via::Via::parse("https://proxy.example") {
        let dial = via::Dial {
            way: way.clone(),
            trust: Trust::Default,
            timeout: wait,
            offer: via::Offer::Both,
            auth_file: "a file".into(),
        };
        dialers.push(Box::new(via::Client::new(proxy, dial)));
    }
    let builtin = forwarder::builtin::builtin();
    if let Some(template) = builtin.first().and_then(|b| forwarder::Template::parse(b.template).ok()) {
        let dial = forwarder::Dial {
            way: way.clone(),
            trust: Trust::Default,
            timeout: wait,
            at_end: AtEnd::Now,
            note: note.clone(),
        };
        dialers.push(Box::new(forwarder::Forwarder { template, dial }));
    }
    if let Ok(server) = wstunnel::Server::parse("wss://wstunnel.example") {
        let dial = wstunnel::Dial { way: way.clone(), trust: Trust::Default, timeout: wait, at_end: AtEnd::Now };
        dialers.push(Box::new(wstunnel::Tunnel { server, secret: wstunnel::Secret::default(), dial }));
    }
    let target = Target::new("probe.example", 22);
    let dialed = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(runtime) => dialers
            .iter()
            .map(|d| {
                let now = tokio::time::Instant::now();
                let done =
                    runtime.block_on(d.dial(&target, now)).map_or_else(|e| e.class.to_string(), |_| "open".into());
                format!("{} {done}", d.label())
            })
            .collect::<Vec<_>>()
            .join(", "),
        Err(e) => e.to_string(),
    };
    let pair = |k: &str, v: &str| (k.to_string(), v.to_string());
    let meek = pod_egress::meek::Args::parse(&[pair("url", "https://meek.example/"), pair("front", "front.example")])
        .map_or_else(|e| e, |_| "meek_lite".into());
    let webtunnel = pod_egress::webtunnel::Args::parse(&[pair("url", "https://webtunnel.example/secret")])
        .map_or_else(|e| e, |a| a.shown());
    let access = pod_egress::cloudflare::Access::default();
    let upgrade =
        pod_egress::cloudflare::request("tunnel.example", &access, "AAAAAAAAAAAAAAAAAAAAAA==", "static-probe")
            .map_or_else(|e| e, |r| format!("{} bytes", r.len()));
    let _ = pod_egress::wisp::PROTOCOL;
    let _ = pod_egress::pt::Reach { way, trust: Trust::Default, wait };
    format!("pod-egress: {dialed}; {meek}, {webtunnel}, an upgrade of {upgrade}")
}
