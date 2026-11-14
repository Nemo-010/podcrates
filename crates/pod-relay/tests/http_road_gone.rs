//! A caller that drops its stream in the middle of a session of the HTTP
//! road, between the client and a stand-in of the relay role in memory, on
//! a paused clock: the client sends one `close`, within its bound, so that
//! the role frees the session at once, not at its idle limit.

mod http_road_stand_in;

use std::time::Duration;

use http_road_stand_in::{Plan, StandIn, pattern};
use pod_relay::http_road::client::{End, LIMIT, Target, open};
use pod_relay::http_road::{Form, Tuning};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MIB: usize = 1 << 20;
/// The bytes down that the caller reads before it goes: more than the pipe
/// holds, so that the session is in the middle of its bytes down.
const READ_FIRST: usize = 512 * 1024;

/// The caller writes a little, reads [`READ_FIRST`] bytes of 4 MiB down,
/// and drops its stream. The stand-in gets one `close` within [`LIMIT`],
/// and the session's end says that the client closed it.
async fn dropped_in_the_middle(form: Form) {
    let stand_in = StandIn::new(Plan { down: pattern(4 * MIB, 17), ..Plan::default() });
    let target = Target { host: "target.test", port: 22, family: None };
    let opened = open(&stand_in.road(), &target, "token", Some(form), Tuning::default()).await.expect("the open");
    assert_eq!(opened.form, form);
    let mut stream = opened.stream;
    stream.write_all(b"some bytes up").await.unwrap();
    let mut buf = vec![0u8; 64 * 1024];
    let mut came = 0;
    while came < READ_FIRST {
        match stream.read(&mut buf).await.expect("the bytes down") {
            0 => panic!("{form:?}: the bytes down ended after {came} bytes"),
            n => came += n,
        }
    }
    drop(stream);
    let closed = tokio::time::timeout(LIMIT, stand_in.closed()).await;
    assert!(closed.is_ok(), "{form:?}: no close came within {LIMIT:?} of the caller's drop");
    let end = End::Closed { code: 1000, reason: "client closed".into() };
    assert_eq!(opened.ended.get(), Some(end), "{form:?}");
    // The tasks of the session stop; no second close goes.
    tokio::time::sleep(Duration::from_secs(120)).await;
    let (closes, ended) = stand_in.record(|r| (r.closes, r.ended.clone()));
    assert_eq!(closes, 1, "{form:?}: the requests close");
    assert_eq!(ended, Some((1000, "client closed".into())), "{form:?}");
}

#[tokio::test(start_paused = true)]
async fn the_serial_form_closes_the_session_when_the_caller_drops_its_stream() {
    dropped_in_the_middle(Form::Serial).await;
}

#[tokio::test(start_paused = true)]
async fn the_split_form_closes_the_session_when_the_caller_drops_its_stream() {
    dropped_in_the_middle(Form::Split).await;
}
