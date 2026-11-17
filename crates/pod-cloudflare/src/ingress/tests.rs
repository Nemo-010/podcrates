use super::*;

#[test]
fn parses_services() {
    assert!(matches!(Service::parse("http://127.0.0.1:8080").unwrap(), Service::Http(_)));
    assert!(matches!(Service::parse("https://x:443").unwrap(), Service::Http(_)));
    assert!(matches!(Service::parse("unix:/run/x.sock").unwrap(), Service::Unix(_)));
    assert!(matches!(Service::parse("tcp://db:5432").unwrap(), Service::Tcp(_)));
    assert!(matches!(Service::parse("http_status:404").unwrap(), Service::Status(404)));
    assert!(matches!(Service::parse("static:/srv").unwrap(), Service::Static { spa: false, .. }));
    assert!(matches!(Service::parse("spa:/srv").unwrap(), Service::Static { spa: true, .. }));
    assert!(Service::parse("nope://x").is_err());
}

#[test]
fn wildcard_hosts() {
    assert!(hostname_matches("*.example.com", "a.example.com"));
    assert!(hostname_matches("*.example.com", "example.com"));
    assert!(!hostname_matches("*.example.com", "a.b.example.com"));
    assert!(!hostname_matches("*.example.com", "example.org"));
    assert!(hostname_matches("app.example.com", "APP.example.com"));
}

#[test]
fn resolves_first_match() {
    let ingress = Ingress::new()
        .rule("api.example.com", Some("/v1"), Service::HelloWorld)
        .rule("api.example.com", None, Service::Status(404))
        .catch_all(Service::Status(503));
    assert!(matches!(ingress.resolve("api.example.com", "/v1/x").unwrap().service, Service::HelloWorld));
    assert!(matches!(ingress.resolve("api.example.com", "/other").unwrap().service, Service::Status(404)));
    assert!(matches!(ingress.resolve("other.example.com", "/").unwrap().service, Service::Status(503)));
}

// Issue 269: a path: is a regular expression, unanchored, as in
// cloudflared. A prefix of the builder has no special character.
#[test]
fn a_path_pattern_is_a_regular_expression() {
    let re = PathPattern::regex("^/api/v[0-9]+/").unwrap();
    assert!(re.is_match("/api/v12/x"));
    assert!(!re.is_match("/api/vx/"));
    assert!(!re.is_match("/x/api/v1/"));
    let dot = PathPattern::regex("/a.b").unwrap();
    assert!(dot.is_match("/aXb"));
    assert!(dot.is_match("/x/a.b/y"));
    let end = PathPattern::regex("^/ws$").unwrap();
    assert!(end.is_match("/ws?token=1"));
    assert!(!end.is_match("/ws/x"));
    let err = PathPattern::regex("[").unwrap_err().to_string();
    assert!(err.contains("not a valid regular expression"), "{err}");

    let prefix = PathPattern::prefix("/a.b");
    assert!(prefix.is_match("/a.b/c"));
    assert!(!prefix.is_match("/aXb"));
    assert!(!prefix.is_match("/x/a.b"));
    assert_eq!(prefix.as_str(), "/a.b");

    assert_eq!(prefix.literal_path().as_deref(), Some("/a.b"));
    let literal = PathPattern::regex(r"^/v1\.2/ws$").unwrap();
    assert_eq!(literal.literal_path().as_deref(), Some("/v1.2/ws"));
    assert_eq!(re.literal_path(), None);
    assert_eq!(dot.literal_path(), None);
}

#[test]
fn durations() {
    assert_eq!(humantime("30s").unwrap(), Duration::from_secs(30));
    assert_eq!(humantime("500ms").unwrap(), Duration::from_millis(500));
    assert_eq!(humantime("2m").unwrap(), Duration::from_secs(120));
    assert!(humantime("x").is_err());
}

// T-077: the match reads the decoded path, as cloudflared does.
#[test]
fn a_path_rule_matches_the_decoded_path() {
    let rule = PathPattern::regex("^/a b$").unwrap();
    assert!(rule.is_match("/a%20b"));
    assert!(rule.is_match("/a%20b?q=%20"));
    assert!(!rule.is_match("/a+b"), "a + stays a +");
    let slash = PathPattern::regex("^/x/y$").unwrap();
    assert!(slash.is_match("/x%2Fy"));
    // A % with no two hex digits stays.
    assert_eq!(decode_path("/50%"), "/50%");
    assert_eq!(decode_path("/%zz%4"), "/%zz%4");
    assert_eq!(decode_path("/%41%62"), "/Ab");
    // No anchor: a part of the path matches.
    assert!(PathPattern::regex("b c").unwrap().is_match("/a/b%20c/d"));
}
