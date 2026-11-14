//! The public WebTorrent trackers (PodUtils/podssh#235): the meeting point
//! of `pod_wormhole::tracker` dials the endpoint `tracker` of each service
//! of the kind `webtorrent-tracker`, in the order of the ranks. Both ends
//! of a code read one order. podssh's manual shows the filter list that
//! refuses each one.

#[test]
fn each_tracker_is_a_wss_endpoint_on_443_in_the_order_of_its_rank_with_its_filter_list() {
    let ids: Vec<&str> = pod_services::of_kind("webtorrent-tracker").map(|s| s.id()).collect();
    assert_eq!(ids, ["openwebtorrent-tracker", "webtorrent-dev-tracker"]);
    for s in pod_services::of_kind("webtorrent-tracker") {
        let e = s.endpoint("tracker").unwrap_or_else(|| panic!("{}: no endpoint tracker", s.id()));
        assert_eq!((e.scheme(), e.port(), e.path()), ("wss", 443, Some("/")), "{}", s.id());
        assert!(!s.party().is_empty(), "{}: whose it is", s.id());
        assert!(s.int("sdp-bytes-most").is_some_and(|n| n > 0), "{}: sdp-bytes-most", s.id());
        for fact in ["filter-list", "filter-list-part", "filter-category"] {
            assert!(s.text(fact).is_some_and(|t| !t.is_empty()), "{}: {fact}", s.id());
        }
    }
}
