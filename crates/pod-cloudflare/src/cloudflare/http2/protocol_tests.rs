use super::*;

// connection/header.go: `var headerEncoding = base64.RawStdEncoding`.
// The standard alphabet with no padding. The decoder of the edge refuses an
// output with padding. Thus this is a rule of the protocol, not a style.
#[test]
fn header_base64_is_unpadded_standard() {
    for (input, expected) in [
        (&b"a"[..], "YQ"),
        (&b"ab"[..], "YWI"),
        (&b"abc"[..], "YWJj"),
        (&b"abcd"[..], "YWJjZA"),
        (&b"content-type"[..], "Y29udGVudC10eXBl"),
        (&b"host"[..], "aG9zdA"),
        (&b"127.0.0.1:8080"[..], "MTI3LjAuMC4xOjgwODA"),
    ] {
        assert_eq!(base64_encode(input), expected, "base64 of {:?}", String::from_utf8_lossy(input));
        assert!(!base64_encode(input).contains('='), "RawStdEncoding never emits padding");
        assert_eq!(base64_decode(expected).as_deref(), Some(input));
    }
}

#[test]
fn encoded_headers_are_name_then_value_separated_by_colon_and_semicolon() {
    // The same output as SerializeHeaders.
    let encoded =
        encode_headers(&[("host".into(), "example.com".into()), ("cf-connecting-ip".into(), "1.2.3.4".into())]);
    assert_eq!(encoded, "SG9zdA:ZXhhbXBsZS5jb20;Q2YtQ29ubmVjdGluZy1JcA:MS4yLjMuNA");
    assert_eq!(base64_decode("SG9zdA").unwrap(), b"Host");
    // The second pair: the base64 has no padding. Thus decode must not
    // require the '=' that an encoder with padding adds.
    assert_eq!(base64_decode("Q2YtQ29ubmVjdGluZy1JcA").unwrap(), b"Cf-Connecting-Ip");
}

#[test]
fn a_single_header_serializes_without_a_trailing_semicolon() {
    // SerializeHeaders writes a separator only when the buffer is not empty.
    // Thus one header ends in the value, with no ';' after it.
    assert_eq!(encode_headers(&[("host".into(), "a".into())]), "SG9zdA:YQ");
}

#[test]
fn the_visitor_request_forwards_the_origins_headers_unencoded() {
    // The ServeHTTP of cloudflared gives the request of the edge directly to
    // the origin proxy. Thus the headers arrive as usual HTTP/2 headers. Only
    // the response direction is serialized. header.go defines
    // RequestUserHeaders, but no other upstream file uses it.
    let headers = vec![
        ("content-type".to_string(), "text/plain".to_string()),
        ("cf-connecting-ip".to_string(), "1.2.3.4".to_string()),
    ];
    let request = build_visitor_request("POST", "/api/x", "example.com", &headers);

    assert_eq!(request.headers().get("content-type").unwrap(), "text/plain");
    // cf-connecting-ip has none of the four prefixes of
    // IsControlResponseHeader. Thus cloudflared sends it to the origin.
    assert_eq!(request.headers().get("cf-connecting-ip").unwrap(), "1.2.3.4");
    assert!(
        request.headers().get("cf-cloudflared-request-headers").is_none(),
        "the request direction is not serialized; RequestUserHeaders is dead upstream"
    );
    assert_eq!(request.method(), "POST");
    assert_eq!(request.uri().path(), "/api/x");
}

#[test]
fn the_visitor_request_does_not_put_hop_by_hop_headers_on_the_wire() {
    let headers = vec![
        ("connection".to_string(), "keep-alive".to_string()),
        ("transfer-encoding".to_string(), "chunked".to_string()),
        (":method".to_string(), "GET".to_string()),
        ("cf-proxy-internal".to_string(), "x".to_string()),
        ("cf-int-trace".to_string(), "y".to_string()),
        ("accept".to_string(), "*/*".to_string()),
    ];
    let request = build_visitor_request("GET", "/", "example.com", &headers);

    for name in request.headers().keys() {
        let lower = name.as_str().to_ascii_lowercase();
        assert!(!is_control_header(&lower), "{} must not be sent as a real header", lower);
        assert_ne!(lower, "transfer-encoding", "hop-by-hop on the edge stream");
    }
    assert!(request.headers().contains_key("accept"));
    assert!(!request.headers().contains_key("keep-alive"));
    assert_eq!(request.method(), "GET");
    assert_eq!(request.uri().path(), "/");
    assert_eq!(request.headers().get("host").unwrap(), "example.com");
}

#[test]
fn control_header_matching_follows_the_go_prefixes() {
    // IsControlResponseHeader in connection/header.go.
    for name in [":status", "cf-int-something", "cf-cloudflared-request-headers", "cf-proxy-something"] {
        assert!(is_control_header(name), "{} is a control header", name);
    }
    for name in ["content-type", "cf-something", "x-forwarded-for", "cloudflared"] {
        assert!(!is_control_header(name), "{} is a visitor header", name);
    }
}

#[test]
fn a_request_with_no_headers_still_reaches_the_origin() {
    let request = build_visitor_request("GET", "/", "example.com", &[]);
    assert_eq!(request.headers().get("host").unwrap(), "example.com");
    assert_eq!(request.headers().len(), 1, "only the host header");
}

#[test]
fn origin_response_headers_are_serialized_into_one_edge_header() {
    let (status, out) = build_origin_response(
        200,
        &[
            ("Content-Type".into(), "text/html".into()),
            ("Content-Length".into(), "12".into()),
            ("cf-proxy-internal".into(), "drop".into()),
            (":status".into(), "200".into()),
        ],
    );

    assert_eq!(status, 200);
    let real: Vec<&str> = out.iter().filter(|(k, _)| k == "content-length").map(|(_, v)| v.as_str()).collect();
    assert_eq!(real, vec!["12"], "content-length goes on the wire too");

    let serialized = out
        .iter()
        .find(|(k, _)| k == RESPONSE_HEADERS_HEADER)
        .map(|(_, v)| v.clone())
        .expect("the serialized blob is always present");
    let decoded = decode_headers(&serialized);
    assert!(decoded.iter().any(|(k, v)| k == "Content-Type" && v == "text/html"));
    assert!(
        !decoded.iter().any(|(k, _)| k == "cf-proxy-internal" || k == ":status"),
        "control headers are not replayed to the visitor: {:?}",
        decoded
    );
}

#[test]
fn an_origin_switching_protocols_101_becomes_200() {
    // HTTP/2 has no 101. cloudflared changes it (http2.go).
    let (status, _) = build_origin_response(101, &[]);
    assert_eq!(status, 200);
    let (status, _) = build_origin_response(204, &[]);
    assert_eq!(status, 204, "other statuses pass through unchanged");
}

#[test]
fn the_response_meta_header_records_that_an_origin_answered() {
    let (_, out) = build_origin_response(502, &[]);
    assert!(served_by_origin(&out));
    assert!(out.iter().any(|(k, v)| k == RESPONSE_META_HEADER && v == r#"{"src":"origin"}"#));
    assert!(
        !served_by_origin(&[(RESPONSE_HEADERS_HEADER.into(), String::new())]),
        "no meta header means cloudflared served it, not an origin"
    );
}

#[test]
fn hop_by_hop_headers_are_recognised() {
    for name in ["Connection", "keep-alive", "Proxy-Authenticate", "te", "trailer", "Transfer-Encoding", "upgrade"] {
        assert!(is_hop_by_hop(name), "{} is hop-by-hop", name);
    }
    for name in ["content-length", "cf-proxy-x", "accept", "trailers"] {
        assert!(!is_hop_by_hop(name), "{} is not hop-by-hop", name);
    }
}

/// The names in Connection are also hop-by-hop.
#[test]
fn connection_names_its_hop_by_hop_headers() {
    assert_eq!(
        connection_named(["close, X-Hop", " Upgrade ,keep-alive,x-other", ""]),
        vec!["x-hop".to_string(), "x-other".to_string()]
    );
    assert!(connection_named(["Host, Content-Length, Transfer-Encoding"]).is_empty());
}

#[test]
fn header_names_are_canonicalized_like_go_does() {
    // textproto.CanonicalMIMEHeaderKey: the map of the edge holds this form
    // when the name gets to the encoder.
    assert_eq!(canonical_header_name("host"), "Host");
    assert_eq!(canonical_header_name("content-type"), "Content-Type");
    assert_eq!(canonical_header_name("cf-connecting-ip"), "Cf-Connecting-Ip");
    assert_eq!(canonical_header_name("a"), "A");
    assert_eq!(canonical_header_name("x-forwarded-for"), "X-Forwarded-For");
    assert_eq!(canonical_header_name("X-Weird-Header"), "X-Weird-Header");
    // A canonical name does not change. Thus the encoding is stable.
    assert_eq!(canonical_header_name("Content-Type"), "Content-Type");
}

#[test]
fn a_non_token_header_name_is_left_exactly_as_given() {
    // The canonicalization of Go stops at the first byte that is not a
    // letter, a digit or a dash. It then gives the original string.
    for name in ["x_forwarded_for", "weird name", "a.b", "ünicode", ""] {
        assert_eq!(canonical_header_name(name), name, "{} must pass through untouched", name);
    }
}

#[test]
fn canonicalization_does_not_change_what_the_edge_decodes() {
    // The canonicalization is cosmetic: the decoded name is the same header.
    let lower = encode_headers(&[("content-type".into(), "text/plain".into())]);
    let canonical = encode_headers(&[("Content-Type".into(), "text/plain".into())]);
    // "content-type" and "Content-Type" have the same canonical form. Thus
    // the wire form is the same. A name with a different form in Go has a
    // different wire form.
    assert_eq!(lower, canonical);
    assert_eq!(decode_headers(&lower), decode_headers(&canonical));
    assert_eq!(decode_headers(&canonical)[0].0, "Content-Type");

    // CF_CONNECTING_IP is not canonical (the underscore is not a token
    // character). Go does not change it, and the crate must not change it.
    let odd = encode_headers(&[("CF_CONNECTING_IP".into(), "1.2.3.4".into())]);
    assert_eq!(decode_headers(&odd)[0].0, "CF_CONNECTING_IP");
}

/// The recorded output of the `SerializeHeaders` of cloudflared. An exact
/// copy of it in Go made the record (see tools/check-header-oracle.sh).
///
/// The test compares the cases pair by pair. Go serializes in the random
/// order of a map, so the order of the pairs is not part of the format.
/// This test exists because a base64 literal written by hand can have an
/// error. An error of one character, as in `Q2YtY29ubmVjdGluZy1JcA`, is not
/// visible to the eye.
#[test]
fn the_encoding_matches_the_recorded_go_oracle() {
    let recorded = include_str!("../../../tools/header-oracle.txt");
    let mut blocks = recorded.split("---").filter(|b| !b.trim().is_empty());

    let cases: Vec<Vec<(&str, &str)>> = vec![
        vec![("host", "a")],
        vec![("host", "example.com")],
        vec![("X-Binary", "x")],
        vec![("host", "example.com"), ("cf-connecting-ip", "1.2.3.4")],
        vec![("a", "y"), ("b", "z"), ("c", "w")],
    ];

    for (case, block) in cases.iter().zip(blocks.by_ref()) {
        let owned: Vec<(String, String)> = case.iter().map(|(n, v)| (n.to_string(), v.to_string())).collect();
        let mut ours: Vec<String> = encode_headers(&owned).split(';').map(str::to_string).collect();
        ours.sort();

        let mut theirs: Vec<String> = block.lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect();
        theirs.sort();

        assert_eq!(ours, theirs, "header encoding differs from cloudflared's SerializeHeaders for {:?}", case);
    }
    assert!(
        blocks.next().is_none(),
        "tools/header-oracle.txt has more cases than this test covers; \
             add them here or re-record the oracle"
    );
}

#[test]
fn the_sni_is_not_the_hostname_the_srv_record_points_at() {
    // The SNI is h2.cftunnel.com, and the socket goes to the address of the
    // SRV record. A wrong SNI gives the general HTTP frontend of Cloudflare,
    // not the tunnel edge. The symptom is an HTTP/1.1 400 with no ALPN.
    assert_eq!(crate::cloudflare::h2_sni(), "h2.cftunnel.com");
    assert_ne!(crate::cloudflare::h2_sni(), "region1.v2.argotunnel.com");
    assert_ne!(crate::cloudflare::h2_sni(), crate::cloudflare::quic_sni());
}

#[test]
fn the_stream_headers_match_the_edge_names() {
    // The names come from connection/header.go.
    assert_eq!(super::CONTROL_STREAM_HEADER, "Cf-Cloudflared-Proxy-Connection-Upgrade");
    assert_eq!(super::PROXY_SRC_HEADER, "Cf-Cloudflared-Proxy-Src");
    assert_eq!(RESPONSE_HEADERS_HEADER, "cf-cloudflared-response-headers");
    // RequestUserHeaders exists upstream, but no upstream file uses it.
    assert_eq!(RESPONSE_META_HEADER, "cf-cloudflared-response-meta");
}
