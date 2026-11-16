//! A session of the resumable layer whose links go on the HTTP road
//! (PodUtils/podssh#287): where the way refuses the upgrade of a link, each
//! link is a new session of the road to `OPEN_LAYER` (or `ONE_LAYER`), in
//! each form of the road. A stand-in role in memory (`http_road_layer/
//! role.rs`) gives each such session to a far end of the layer that keeps
//! its sessions, whose target echoes. A cut of the road's sessions loses
//! the link, and the session resumes on a new session of the road.

#[path = "http_road_layer/role.rs"]
mod role;

use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use pod_relay::forward_layer::{Dialer, Link, carry_or_road};
use pod_relay::http_road::Form;
use pod_relay::relay::Relay;
use pod_session::resume::Note;
use pod_session::{Ask, OsEntropy, Settings, client};
use role::{LayerRoad, TOKEN};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

const LIMIT: Duration = Duration::from_secs(30);

/// `bytes` through the session and back from the echo.
async fn round(app: &mut DuplexStream, bytes: &[u8]) -> Result<(), String> {
    app.write_all(bytes).await.map_err(|e| e.to_string())?;
    let mut got = vec![0u8; bytes.len()];
    match tokio::time::timeout(LIMIT, app.read_exact(&mut got)).await {
        Ok(Ok(_)) if got == bytes => Ok(()),
        Ok(Ok(_)) => Err("other bytes came back".into()),
        Ok(Err(e)) => Err(e.to_string()),
        Err(_) => Err("no echo in time".into()),
    }
}

fn dialer(role: &Arc<LayerRoad>, form: Form) -> Dialer {
    let relay = Relay { host: "relay.test".into(), port: 443 };
    Dialer::over_road(relay, role.road(), TOKEN, "target.test", 22).unwrap().with_road_form(Some(form))
}

/// A session over the road in `form`: bytes both ways, a cut of the road,
/// and the same session on a new link of the road.
async fn resumes_over(form: Form) {
    let role = LayerRoad::new();
    let dialer = dialer(&role, form);
    assert!(dialer.by_road());
    let first = dialer.link_or_road(&mut |_| {}).await.unwrap_or_else(|m| panic!("{form:?}: {:?}", m.lines("t")));
    assert!(matches!(first, Link::Road { .. }));
    let client = client::start(first, Ask::New, Settings::default(), &mut OsEntropy).await.expect("the session");
    let (mut app, theirs) = tokio::io::duplex(256 * 1024);
    let notes: Arc<Mutex<Vec<Note>>> = Arc::default();
    let heard = notes.clone();
    tokio::spawn(async move {
        let note = move |n: Note| heard.lock().unwrap().push(n);
        carry_or_road(&dialer, client, theirs, note).await
    });
    let big: Vec<u8> = (0..300_000u32).map(|i| (i % 251) as u8).collect();
    for n in 0..3u8 {
        round(&mut app, &[n; 100]).await.unwrap_or_else(|e| panic!("{form:?} before the cut: {e}"));
    }
    round(&mut app, &big).await.unwrap_or_else(|e| panic!("{form:?}: a large write: {e}"));
    role.cut();
    let after = round(&mut app, b"after the cut").await;
    let notes = notes.lock().unwrap().clone();
    after.unwrap_or_else(|e| panic!("{form:?} after the cut: {e}; notes {notes:?}"));
    assert!(notes.iter().any(|n| matches!(n, Note::Resumed { .. })), "{form:?}: {notes:?}");
    let opens = role.opens.load(Ordering::SeqCst) + role.ones.load(Ordering::SeqCst);
    assert!(opens >= 2, "{form:?}: a new session of the road carried the resume ({opens})");
    if form == Form::One {
        assert_eq!(role.opens.load(Ordering::SeqCst), 0, "each link went in the one-POST form");
    } else {
        assert_eq!(role.ones.load(Ordering::SeqCst), 0, "no link went in the one-POST form");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_of_the_layer_resumes_over_the_split_form() {
    resumes_over(Form::Split).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_of_the_layer_resumes_over_the_serial_form() {
    resumes_over(Form::Serial).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_of_the_layer_resumes_over_the_one_post_form() {
    resumes_over(Form::One).await;
}

/// A token that the role does not take: the link is refused for good, with
/// the role's words.
#[tokio::test]
async fn a_refused_token_ends_the_link_for_good() {
    let role = LayerRoad::new();
    let relay = Relay { host: "relay.test".into(), port: 443 };
    let dialer = Dialer::over_road(relay, role.road(), "another-token", "target.test", 22).unwrap();
    let dialer = dialer.with_road_form(Some(Form::Split));
    let missed = dialer.link_or_road(&mut |_| {}).await.err().expect("a refusal");
    assert!(missed.is_final());
    let lines = missed.lines("target.test:22").join("; ");
    assert!(lines.starts_with("the HTTP road to target.test:22: "), "{lines}");
    assert!(lines.contains("layer: missing or wrong token"), "{lines}");
}
