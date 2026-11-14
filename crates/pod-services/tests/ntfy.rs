//! The public ntfy servers (PodUtils/podssh#237): the meeting point of
//! `pod_wormhole::ntfy` dials the endpoint `server` of each service of the
//! kind `ntfy-server`, in the order of the ranks. Both ends of a code read
//! one order.

#[test]
fn each_server_is_an_https_endpoint_on_443_with_the_limits_of_a_visitor() {
    let ids: Vec<&str> = pod_services::of_kind("ntfy-server").map(|s| s.id()).collect();
    assert_eq!(ids, ["ntfy-sh", "envs-ntfy", "adminforge-ntfy"]);
    for s in pod_services::of_kind("ntfy-server") {
        let e = s.endpoint("server").unwrap_or_else(|| panic!("{}: no endpoint server", s.id()));
        assert_eq!((e.scheme(), e.port(), e.path()), ("https", 443, Some("/")), "{}", s.id());
        assert!(!s.party().is_empty(), "{}: whose it is", s.id());
        for fact in ["message-bytes-most", "requests-burst", "request-refill-seconds", "messages-per-day"] {
            assert!(s.int(fact).is_some_and(|n| n > 0), "{}: {fact}", s.id());
        }
        // ntfy keeps a body of its whole limit of 4,096 bytes as an attachment.
        assert!(s.int("message-bytes-most").is_some_and(|n| n < 4096), "{}", s.id());
        assert_eq!(s.bool("account-required"), Some(false), "{}", s.id());
    }
}
