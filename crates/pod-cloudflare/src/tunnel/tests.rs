use super::*;

// A refusal with retry: yes in the first registration is tried again (the
// edge can answer "Tunnel not found" for a new quick tunnel); a refusal with
// retry: no ends the leg at once.
#[tokio::test(start_paused = true)]
async fn a_retryable_refusal_of_the_first_registration_is_tried_again() {
    let refused = |retry: bool| {
        pod_core::Failure::from(rpc::Refused {
            client: "podnet".into(),
            cause: "Unauthorized: Tunnel not found".into(),
            should_retry: retry,
            retry_after: Duration::from_secs(1),
        })
    };
    let mut calls = 0;
    let got = register_retrying(|| {
        calls += 1;
        let n = calls;
        async move { if n < 3 { Err(refused(true)) } else { Ok(n) } }
    })
    .await
    .unwrap();
    assert_eq!(got, 3);
    let mut calls = 0;
    let err = register_retrying(|| {
        calls += 1;
        async { Err::<(), _>(refused(false)) }
    })
    .await
    .unwrap_err();
    assert_eq!(calls, 1);
    assert!(format!("{err:#}").contains("retry: no"));
    let mut calls = 0;
    let _ = register_retrying(|| {
        calls += 1;
        async { Err::<(), _>(refused(true)) }
    })
    .await;
    assert_eq!(calls, REGISTER_TRIES);
}

// The limit of a serial leg attempt is at least the sum of
// the budgets of the steps of the leg, with the tries of the
// registration and the waits between them. It was 8 s for each leg.
#[test]
fn the_serial_limit_covers_the_budgets_of_each_leg() {
    let waits = REGISTER_WAIT_MAX * (REGISTER_TRIES - 1);
    let quic = (quic_dial::HANDSHAKE_TIMEOUT + REGISTER_TIMEOUT) * REGISTER_TRIES + waits;
    let h2 = (crate::edge_h2::DIAL_TIMEOUT * 3 + crate::edge_h2::REGISTER_TIMEOUT * 2) * REGISTER_TRIES + waits;
    let limit = |kind| attempt_limit(kind).expect("a limit");
    assert!(limit(LegKind::QuicDirect) >= quic, "quic");
    assert!(limit(LegKind::H2Direct) >= h2, "http2");
    assert!(limit(LegKind::H2Relay) >= h2, "http2+relay");
    assert_eq!(attempt_limit(LegKind::QuicWarp), None);
    // PodUtils/podnet:docs/tunnels.md and PodUtils/podnet:docs/protocol.md,
    // section 3.3, give these values.
    assert_eq!(limit(LegKind::QuicDirect).as_secs(), 130);
    assert_eq!(limit(LegKind::H2Direct).as_secs(), 280);
}

// A registration that the edge refuses twice with retry: yes
// and a wait of 5 s completes in the serial limit.
#[tokio::test(start_paused = true)]
async fn a_slow_registration_completes_in_the_serial_limit() {
    let mut calls = 0;
    let got = bounded(
        attempt_limit(LegKind::QuicDirect),
        register_retrying(|| {
            calls += 1;
            let n = calls;
            async move {
                tokio::time::sleep(quic_dial::HANDSHAKE_TIMEOUT / 2).await;
                if n < REGISTER_TRIES {
                    Err(pod_core::Failure::from(rpc::Refused {
                        client: "podnet".into(),
                        cause: "Unauthorized: Tunnel not found".into(),
                        should_retry: true,
                        retry_after: REGISTER_WAIT_MAX,
                    }))
                } else {
                    Ok(n)
                }
            }
        }),
    )
    .await
    .unwrap();
    assert_eq!(got, REGISTER_TRIES);
}

#[test]
fn podnet_udp_and_the_probe_shape_the_plan() {
    use crate::udp::{Choice, Egress};
    use LegKind::*;
    let words = crate::testing::podnet_words();
    let all = || vec![QuicDirect, H2Direct, QuicWarp];
    let plan = |udp, egress: Option<Egress>| plan_with_udp(all(), udp, egress.as_ref(), &words);
    assert_eq!(plan(Choice::Off, None).unwrap().0, vec![H2Direct, QuicWarp]);
    assert_eq!(plan(Choice::On, None).unwrap().0, all());
    let refused = Egress::Refused("EPERM".into());
    let (kept, note) = plan(Choice::Probe, Some(refused.clone())).unwrap();
    assert_eq!(kept, vec![H2Direct, QuicWarp]);
    assert!(note.unwrap().contains("refused"));
    // No answer, or an answer, keeps the order.
    for egress in [Egress::Unknown("x".into()), Egress::Answered("x".into())] {
        assert_eq!(plan(Choice::Probe, Some(egress)).unwrap().0, all());
    }
    // PODNET_UDP=off with QUIC on UDP 7844 as the only leg is an error.
    let err = plan_with_udp(vec![QuicDirect], Choice::Off, None, &words).unwrap_err();
    assert_eq!(crate::fail::class_of(&err), Some(Class::Config));
    assert_eq!(plan_with_udp(vec![H2Direct], Choice::Off, None, &words).unwrap().0, vec![H2Direct]);
    let _ = refused;
}

// With a proxy, auto drops QUIC on UDP 7844; an explicit
// quic keeps it, with a note.
#[test]
fn a_proxy_and_the_quic_leg() {
    let words = crate::testing::podnet_words();
    let proxy = pod_proxy::Proxy::parse_trusted("http://127.0.0.1:3128").unwrap().label();
    let auto = leg_plan(Protocol::Auto, Transport::Auto, &words).unwrap();
    let (plan, note) = plan_with_proxy(auto, Protocol::Auto, Some(&proxy), &words);
    assert!(!plan.contains(&LegKind::QuicDirect));
    assert!(note.unwrap().contains("does not try QUIC"));
    let quic = leg_plan(Protocol::Quic, Transport::Direct, &words).unwrap();
    let (plan, note) = plan_with_proxy(quic, Protocol::Quic, Some(&proxy), &words);
    assert_eq!(plan, vec![LegKind::QuicDirect]);
    assert!(note.unwrap().contains("goes around the proxy"));
    let quic = leg_plan(Protocol::Quic, Transport::Direct, &words).unwrap();
    assert_eq!(plan_with_proxy(quic, Protocol::Quic, None, &words).1, None);
}

#[test]
fn the_leg_plan_tries_quic_then_http2_then_warp() {
    use LegKind::*;
    let words = crate::testing::podnet_words();
    let plan = |p, t| leg_plan(p, t, &words).unwrap();
    assert_eq!(plan(Protocol::Auto, Transport::Auto), vec![QuicDirect, H2Direct, QuicWarp]);
    assert_eq!(plan(Protocol::Quic, Transport::Auto), vec![QuicDirect, QuicWarp]);
    assert_eq!(plan(Protocol::Http2, Transport::Auto), vec![H2Direct]);
    assert_eq!(plan(Protocol::Auto, Transport::Direct), vec![QuicDirect, H2Direct]);
    assert_eq!(plan(Protocol::Quic, Transport::Warp), vec![QuicWarp]);
    assert!(leg_plan(Protocol::Http2, Transport::Warp, &words).is_err());
    assert_eq!(plan(Protocol::Auto, Transport::Relay), vec![H2Relay]);
    assert_eq!(plan(Protocol::Http2, Transport::Relay), vec![H2Relay]);
    assert!(leg_plan(Protocol::Quic, Transport::Relay, &words).is_err());
}

/// The relay of the host goes to the leg http2+relay alone, as podnet's
/// `--transport relay`; that leg with no relay is an error of the
/// configuration.
#[test]
fn only_the_relay_leg_takes_the_relay() {
    let mut host = crate::testing::host();
    assert_eq!(relay_for(LegKind::H2Relay, &host).unwrap_err().class, Class::Config);
    host.relay = Some(crate::testing::relay(crate::testing::dial()));
    assert!(relay_for(LegKind::H2Relay, &host).unwrap().is_some());
    for kind in [LegKind::QuicDirect, LegKind::H2Direct, LegKind::QuicWarp] {
        assert!(relay_for(kind, &host).unwrap().is_none(), "{kind}");
    }
}
