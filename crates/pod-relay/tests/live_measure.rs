//! A measurement of the hosted relays (T-812): the default host and each
//! seed of its pool, one at a time. For each host: a pair, a node on this
//! runner whose sessions echo, and one operator session through the relay:
//! the time to the first echo of a small write, 100 round trips of 64 bytes
//! (p50 and p99), then 16 MiB each way at once (under the budget of 60 MiB
//! of a session). Both ends are this test's, so each byte crosses the relay
//! two times. One line for each host, in the form of `pod-link`'s
//! measurement (T-777):
//! `MEASURE scen=relay relay=HOST open_ms=.. rtt_p50_ms=.. rtt_p99_ms=..
//! echo_mib_s=..`, or `MEASURE scen=relay relay=HOST failed=WHY`. On
//! request only, as it mints tokens and makes pairs (`live.yml`, input
//! `relay: live_measure`):
//!
//! ```sh
//! cargo test -p pod-relay --features pair --test live_measure -- --ignored --nocapture
//! ```
//!
//! No line prints a token.
#![cfg(feature = "pair")]

mod support;

use std::sync::Arc;
use std::time::Duration;

use pod_relay::pair::{self, Pair, PairContext};
use pod_relay::pool;
use pod_relay::relay::{Relay, default_relay_host};
use pod_relay::reverse::SessionId;
use pod_relay::reverse::{Exit, Handler, NodeConfig, Opening, OperatorConfig, OperatorLimits, Settings, Wire};
use pod_relay::reverse::{operator, run};
use pod_ws::Trust;
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::sync::Notify;
use tokio::time::Instant;

const MIB: usize = 1024 * 1024;
const LIMIT: Duration = Duration::from_secs(30);
/// The bytes of the bulk part, each way: under the budget of a session.
const BULK: usize = 16 * MIB;
const ROUNDS: usize = 100;
const SMALL: usize = 64;

/// A session whose first byte is [`SINK`] takes its bytes and sends none
/// back (a copy); each other session echoes its bytes.
struct Echo;

/// The first byte of a session of a copy.
const SINK: u8 = b'S';
/// The copy of T-835: sessions of this many bytes, one way, under the cap
/// of 64 MiB of a session of the default relay.
const COPY_SESSION: usize = 56 * MIB;
const COPY_SESSIONS: usize = 5;

impl Handler for Echo {
    type Stream = DuplexStream;

    fn open(&self, _id: SessionId) -> Opening<DuplexStream> {
        Box::pin(async {
            let (node_end, echo_end) = tokio::io::duplex(1024 * 1024);
            tokio::spawn(async move {
                let (mut r, mut w) = tokio::io::split(echo_end);
                let mut first = [0u8; 1];
                if r.read_exact(&mut first).await.is_err() {
                    return;
                }
                if first[0] == SINK {
                    let _ = tokio::io::copy(&mut r, &mut tokio::io::sink()).await;
                    return;
                }
                if w.write_all(&first).await.is_ok() {
                    let _ = tokio::io::copy(&mut r, &mut w).await;
                }
            });
            Ok(node_end)
        })
    }
}

fn now_ms() -> i64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as i64
}

/// The pair as a body of `/v1/pair`, for the operator's own copy.
fn body_of(pair: &Pair) -> Vec<u8> {
    format!(
        r#"{{"name":"{}","node_token":"{}","connect_token":"{}","stop_token":"{}","expires":{}}}"#,
        pair.name,
        pair.node_token(),
        pair.connect_token(),
        pair.stop_token(),
        pair.expires_ms
    )
    .into_bytes()
}

/// The figures of one host.
struct Figures {
    open_ms: f64,
    rtt_p50_ms: f64,
    rtt_p99_ms: f64,
    echo_mib_s: f64,
}

/// The value at `q` (0 to 1) of sorted `values`.
fn at(values: &[f64], q: f64) -> f64 {
    values[((values.len() - 1) as f64 * q).round() as usize]
}

/// One small write and its echo.
async fn echo(
    to: &mut tokio::io::WriteHalf<DuplexStream>,
    from: &mut tokio::io::ReadHalf<DuplexStream>,
) -> Result<(), String> {
    to.write_all(&[7u8; SMALL]).await.map_err(|e| e.to_string())?;
    let mut back = [0u8; SMALL];
    tokio::time::timeout(LIMIT, from.read_exact(&mut back))
        .await
        .map_err(|_| "no echo in 30 s".to_string())?
        .map_err(|e| e.to_string())?;
    Ok(())
}

/// One operator session to the node of `pair`: the figures, or why not.
async fn measure_session(pair: &Pair) -> Result<Figures, String> {
    let (io, user) = tokio::io::duplex(4 * MIB);
    let relay = pair.relay.clone();
    let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
    let started = Instant::now();
    let session = tokio::spawn(async move {
        let config = OperatorConfig {
            relay: &relay,
            name: &name,
            connect_token: &token,
            trust: &Trust::Default,
            ctx: support::live(),
            timeout: LIMIT,
            limits: OperatorLimits::default(),
            wire: Wire::Tls,
        };
        operator::run(&config, io).await.map_err(|e| e.to_string())
    });
    let (mut from, mut to) = tokio::io::split(user);
    echo(&mut to, &mut from).await?;
    let open_ms = started.elapsed().as_secs_f64() * 1e3;
    let mut rtts = Vec::with_capacity(ROUNDS);
    for _ in 0..ROUNDS {
        let at = Instant::now();
        echo(&mut to, &mut from).await?;
        rtts.push(at.elapsed().as_secs_f64() * 1e3);
    }
    rtts.sort_by(f64::total_cmp);
    let bulk: Vec<u8> = (0..BULK).map(|i| (i as u8).wrapping_mul(31)).collect();
    let at_bulk = Instant::now();
    let (sent, got) = tokio::join!(
        async {
            for chunk in bulk.chunks(64 * 1024) {
                to.write_all(chunk).await?;
            }
            to.flush().await
        },
        async {
            let mut got = vec![0u8; BULK];
            let read = tokio::time::timeout(Duration::from_secs(600), from.read_exact(&mut got)).await;
            read.map(|r| r.map(|_| got))
        }
    );
    sent.map_err(|e| e.to_string())?;
    let got = got.map_err(|_| "no echo of the bulk in 600 s".to_string())?.map_err(|e| e.to_string())?;
    let secs = at_bulk.elapsed().as_secs_f64();
    if got != bulk {
        return Err("the bulk came back changed".into());
    }
    let _ = to.shutdown().await;
    let _ = tokio::time::timeout(LIMIT, session).await;
    Ok(Figures {
        open_ms,
        rtt_p50_ms: at(&rtts, 0.5),
        rtt_p99_ms: at(&rtts, 0.99),
        echo_mib_s: (BULK / MIB) as f64 / secs,
    })
}

/// A copy of [`COPY_SESSIONS`] sessions of [`COPY_SESSION`] bytes each,
/// one way, one after another, as a copy that keeps the budget of a session
/// opens the next one (T-835): the seconds of each session and of the whole.
async fn measure_copy(pair: &Pair) -> Result<(Vec<f64>, f64), String> {
    let chunk = vec![5u8; 64 * 1024];
    let started = Instant::now();
    let mut each = Vec::new();
    for _ in 0..COPY_SESSIONS {
        let at = Instant::now();
        let (io, mut user) = tokio::io::duplex(4 * MIB);
        let relay = pair.relay.clone();
        let (name, token) = (pair.name.clone(), pair.connect_token().to_string());
        let session = tokio::spawn(async move {
            let config = OperatorConfig {
                relay: &relay,
                name: &name,
                connect_token: &token,
                trust: &Trust::Default,
                ctx: support::live(),
                timeout: LIMIT,
                limits: OperatorLimits::default(),
                wire: Wire::Tls,
            };
            operator::run(&config, io).await.map_err(|e| e.to_string())
        });
        user.write_all(&[SINK]).await.map_err(|e| e.to_string())?;
        for _ in 0..COPY_SESSION / chunk.len() {
            user.write_all(&chunk).await.map_err(|e| e.to_string())?;
        }
        user.shutdown().await.map_err(|e| e.to_string())?;
        let mut rest = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(600), user.read_to_end(&mut rest)).await;
        let outcome = tokio::time::timeout(Duration::from_secs(600), session)
            .await
            .map_err(|_| "no end of a session of the copy in 600 s".to_string())?
            .map_err(|e| e.to_string())??;
        if !outcome.is_success() {
            return Err(format!("a session of the copy ended {outcome:?}"));
        }
        each.push(at.elapsed().as_secs_f64());
    }
    Ok((each, started.elapsed().as_secs_f64()))
}

/// A pair at `host`, a node of it, one session, then the stop of both.
async fn measure_host(host: &str) -> Result<Figures, String> {
    let relay = Relay { host: host.to_string(), port: 443 };
    let ctx = PairContext { relay: &relay, trust: &Trust::Default, ctx: support::live(), timeout: LIMIT };
    let made = pair::create(&ctx).await.map_err(|e| format!("the pair: {e}"))?;
    let copy = pair::parse(&relay, &body_of(&made), now_ms()).map_err(|e| format!("the copy of the pair: {e}"))?;
    let stop = Arc::new(Notify::new());
    let stopper = stop.clone();
    let node = tokio::spawn(async move {
        let mut config = NodeConfig {
            pair: made,
            label: None,
            trust: &Trust::Default,
            ctx: support::live(),
            timeout: LIMIT,
            settings: Settings::default(),
            repair: None,
            wire: Wire::Tls,
            say: None,
        };
        run(&mut config, Arc::new(Echo), async move { stopper.notified().await }).await
    });
    tokio::time::sleep(Duration::from_secs(2)).await;
    let figures = measure_session(&copy).await;
    if host == default_relay_host() && figures.is_ok() {
        match measure_copy(&copy).await {
            Ok((each, secs)) => {
                let shown: Vec<String> = each.iter().map(|s| format!("{s:.2}")).collect();
                let mib = COPY_SESSIONS * COPY_SESSION / MIB;
                println!(
                    "MEASURE scen=copy relay={host} sessions={COPY_SESSIONS} mib={mib} secs={secs:.2} mib_s={:.2} session_secs={}",
                    mib as f64 / secs,
                    shown.join(",")
                );
            }
            Err(why) => println!("MEASURE scen=copy relay={host} failed={}", why.replace(' ', "_")),
        }
    }
    stop.notify_one();
    let exit = tokio::time::timeout(LIMIT, node).await;
    if !matches!(exit, Ok(Ok(Exit::Stopped))) {
        eprintln!("the node of {host} did not stop as asked");
    }
    let _ = pair::stop(&ctx, &copy).await;
    figures
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "the live relays: run with --ignored"]
async fn the_rate_of_each_hosted_relay() {
    let mut hosts = vec![default_relay_host().to_string()];
    hosts.extend(pool::seed().into_iter().map(str::to_string));
    let mut measured = 0;
    for host in &hosts {
        match measure_host(host).await {
            Ok(f) => {
                measured += 1;
                println!(
                    "MEASURE scen=relay relay={host} open_ms={:.1} rtt_p50_ms={:.1} rtt_p99_ms={:.1} echo_mib_s={:.2}",
                    f.open_ms, f.rtt_p50_ms, f.rtt_p99_ms, f.echo_mib_s
                );
            }
            Err(why) => println!("MEASURE scen=relay relay={host} failed={}", why.replace(' ', "_")),
        }
    }
    assert!(measured > 0, "no hosted relay was measured");
}

#[test]
fn the_value_at_a_quantile() {
    let values = [1.0, 2.0, 3.0, 4.0, 5.0];
    assert_eq!((at(&values, 0.5), at(&values, 0.99), at(&values, 0.0)), (3.0, 5.0, 1.0));
}
