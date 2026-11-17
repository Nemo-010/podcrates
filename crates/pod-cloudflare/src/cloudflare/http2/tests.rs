use super::super::Credentials;
use super::*;

/// The response headers of one connection. They must not get to the visitor.
/// The filter of the request path has the same list.
const HOP_BY_HOP: &[&str] = &[
    "Connection",
    "Keep-Alive",
    "Proxy-Authenticate",
    "Proxy-Authorization",
    "TE",
    "Trailer",
    "Transfer-Encoding",
    "Upgrade",
];

#[test]
fn a_response_drops_hop_by_hop_headers_like_the_request_does() {
    let mut headers: Vec<(String, String)> =
        vec![("content-type".into(), "text/plain".into()), ("x-keep-me".into(), "yes".into())];
    for name in HOP_BY_HOP {
        headers.push(((*name).to_string(), "chunked".into()));
    }
    let (status, real) = build_origin_response(200, &headers);
    assert_eq!(status, 200);

    let serialized = real
        .iter()
        .find(|(name, _)| name == RESPONSE_HEADERS_HEADER)
        .map(|(_, value)| value.clone())
        .expect("the serialized blob is always present");
    let decoded = decode_headers(&serialized);

    for name in HOP_BY_HOP {
        assert!(
            !decoded.iter().any(|(n, _)| n.eq_ignore_ascii_case(name)),
            "{name} is connection-scoped and must not be replayed: {decoded:?}"
        );
    }
    assert!(
        decoded.iter().any(|(n, v)| n.eq_ignore_ascii_case("content-type") && v == "text/plain"),
        "content-type describes the body and must survive: {decoded:?}"
    );
    assert!(
        decoded.iter().any(|(n, v)| n.eq_ignore_ascii_case("x-keep-me") && v == "yes"),
        "an end-to-end header must survive: {decoded:?}"
    );
}

#[test]
fn a_request_keeps_its_method_and_path_when_a_header_is_refused() {
    // A header that the http crate refuses must not remove the full request.
    // This test stops a POST of the visitor from becoming a GET of `/`.
    let headers =
        vec![("content-type".to_string(), "text/plain".to_string()), ("bad header".to_string(), "value".to_string())];
    let request = build_visitor_request("POST", "/api/submit?x=1", "example.test", &headers);
    assert_eq!(request.method(), "POST", "the method must survive");
    assert_eq!(request.uri().path(), "/api/submit", "the path must survive");
    assert_eq!(request.uri().query(), Some("x=1"), "the query must survive");
    assert_eq!(request.headers().get("host").unwrap(), "example.test");
    assert_eq!(
        request.headers().get("content-type").unwrap(),
        "text/plain",
        "a good header beside a bad one must still be forwarded"
    );
}

#[test]
fn the_control_stream_headers_match_the_source() {
    // From connection/http2.go: InternalUpgradeHeader / ControlStreamUpgrade.
    assert_eq!(CONTROL_STREAM_HEADER.to_ascii_lowercase(), "cf-cloudflared-proxy-connection-upgrade");
    assert_eq!(CONTROL_STREAM_VALUE, "control-stream");
}

#[test]
fn base64_round_trips() {
    for s in ["", "a", "ab", "abc", "hello world", "\u{0}binary"] {
        let enc = base64_encode(s.as_bytes());
        assert_eq!(base64_decode(&enc).as_deref(), Some(s.as_bytes()), "round trip failed for {s:?} via {enc:?}");
    }
}

#[test]
fn base64_matches_the_known_encoding() {
    // The RFC 4648 vectors with no padding: cloudflared uses
    // base64.RawStdEncoding, not StdEncoding with padding.
    assert_eq!(base64_encode(b""), "");
    assert_eq!(base64_encode(b"f"), "Zg");
    assert_eq!(base64_encode(b"fo"), "Zm8");
    assert_eq!(base64_encode(b"foo"), "Zm9v");
    assert_eq!(base64_encode(b"foob"), "Zm9vYg");
    assert_eq!(base64_encode(b"fooba"), "Zm9vYmE");
    assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
}

#[test]
fn headers_round_trip_through_the_encoded_form() {
    let headers = vec![
        ("Host".to_string(), "example.com".to_string()),
        ("User-Agent".to_string(), "curl/8.22.0".to_string()),
        ("X-Binary".to_string(), "\u{1}\u{2}\u{3}".to_string()),
    ];
    let encoded = encode_headers(&headers);
    assert!(!encoded.ends_with(';'), "SerializeHeaders omits the last separator");
    assert_eq!(encoded.matches(';').count(), headers.len() - 1);
    assert_eq!(decode_headers(&encoded), headers);
}

#[test]
fn a_malformed_encoded_header_is_skipped_not_fatal() {
    let encoded = format!("{}:{};garbage;!!!:???;", base64_encode(b"A"), base64_encode(b"B"));
    assert_eq!(
        decode_headers(&encoded),
        vec![("A".to_string(), "B".to_string())],
        "one bad entry must not lose the good ones"
    );
}

#[test]
fn a_control_stream_is_recognised() {
    let headers = vec![(CONTROL_STREAM_HEADER.to_string(), CONTROL_STREAM_VALUE.to_string())];
    assert_eq!(classify_stream(&headers), StreamKind::Control);
}

#[test]
fn a_configuration_push_wins_over_the_visitor_case() {
    // A push can also have a proxy-source header. A push sent to an origin
    // sends a control message to a web server.
    let headers = vec![
        (CONTROL_STREAM_HEADER.to_string(), "update-configuration".to_string()),
        (PROXY_SRC_HEADER.to_string(), "127.0.0.1:8080".to_string()),
    ];
    assert_eq!(classify_stream(&headers), StreamKind::Configuration);
}

#[test]
fn a_visitor_stream_carries_its_destination() {
    let headers = vec![(PROXY_SRC_HEADER.to_string(), "10.0.0.5:8080".to_string())];
    assert_eq!(classify_stream(&headers), StreamKind::Visitor { address: "10.0.0.5".into(), port: 8080 });
}

#[test]
fn a_request_with_no_special_headers_is_a_visitor() {
    let headers = vec![("host".to_string(), "example.com".to_string())];
    assert_eq!(classify_stream(&headers), StreamKind::Visitor { address: String::new(), port: 0 });
}

#[test]
fn header_matching_is_case_insensitive_as_http_requires() {
    let headers = vec![("cf-cloudflared-proxy-connection-upgrade".to_string(), "control-stream".to_string())];
    assert_eq!(classify_stream(&headers), StreamKind::Control);
}

#[test]
fn pseudo_and_cf_headers_are_not_forwarded_to_the_origin() {
    assert!(is_control_header(":authority"));
    assert!(is_control_header("cf-int-something"));
    assert!(is_control_header("cf-cloudflared-response-headers"));
    assert!(is_control_header("CF-Proxy-Src"));
    assert!(!is_control_header("host"));
    assert!(!is_control_header("content-type"));
}

#[test]
fn the_edge_tls_config_offers_no_alpn() {
    // An offer of h2 here makes this transport hang.
    let config = edge_tls(&crate::testing::tls()).expect("config");
    assert!(config.alpn_protocols.is_empty(), "the HTTP/2 edge transport must offer no ALPN");
}

#[test]
fn a_visitor_request_carries_method_path_and_authority() {
    let req =
        build_visitor_request("POST", "/api?x=1", "example.com", &[("content-type".into(), "application/json".into())]);
    assert_eq!(req.method(), "POST");
    assert_eq!(req.uri().path(), "/api");
    assert_eq!(req.uri().query(), Some("x=1"));
    assert_eq!(req.headers().get("host").unwrap(), "example.com");
    assert!(req.headers().contains_key("content-type"));
}

#[test]
fn credentials_are_not_needed_to_describe_a_stream() {
    // A reminder at compile time: the framing of a stream does not use the
    // credentials. The credentials go on the control stream only.
    let creds = Credentials {
        account_tag: "abc".into(),
        tunnel_secret: vec![0u8; 32],
        tunnel_id: "00000000-0000-0000-0000-000000000000".into(),
    };
    assert_eq!(creds.tunnel_secret.len(), 32);
    assert!(creds.tunnel_id_bytes().is_ok());
}
