//! Entry points for the fuzz targets of `fuzz/` (cargo-fuzz). Each function
//! takes untrusted bytes, runs one parser of the crate on them, and must not
//! panic, hang or allocate much more than the input. The functions give no
//! result: a parse error is a correct answer to bad bytes.
//!
//! [`TARGETS`] is the list of the targets, and [`seeds`] gives the seed
//! inputs of each. A unit test runs each target on its seeds and on
//! deterministic mutations of them, so that the stable test suite also
//! catches a panic.

use crate::cloudflare::capnp::{Message, StructReader};

/// One fuzz target: it takes untrusted bytes.
pub type Target = fn(&[u8]);

/// The name and the function of each target.
pub const TARGETS: &[(&str, Target)] = &[
    ("capnp_message", capnp_message),
    ("rpc_message", rpc_message),
    ("register_response", register_response),
    ("connect_request", connect_request),
    ("srv_record", srv_record),
    ("ingress_rule", ingress_rule),
    ("config_yaml", config_yaml),
    ("h2_header_block", h2_header_block),
    ("request_head", request_head),
];

/// Visit each pointer of a struct, to the depth `depth`.
fn walk(s: &StructReader<'_>, depth: u32) {
    if depth == 0 {
        return;
    }
    for i in 0..8u16 {
        let _ = s.get_u64(i as usize);
        if let Ok(Some(child)) = s.get_struct(i) {
            walk(&child, depth - 1);
        }
        let _ = s.get_text(i);
        let _ = s.get_data(i);
        let _ = s.get_capability(i);
        let _ = s.get_text_list(i);
        if let Ok(list) = s.get_struct_list(i) {
            for item in list.iter().take(16) {
                walk(item, depth - 1);
            }
        }
    }
}

/// A Cap'n Proto message: the framing and a walk of each pointer.
pub fn capnp_message(data: &[u8]) {
    if let Ok(Some((message, used))) = Message::parse(data) {
        assert!(used <= data.len());
        if let Ok(root) = message.root() {
            walk(&root, 8);
        }
    }
}

/// An RPC message of the edge: the readers of the RPC session.
pub fn rpc_message(data: &[u8]) {
    use crate::cloudflare::rpc;
    if let Ok(Some((message, _))) = Message::parse(data) {
        let _ = rpc::payload(&message);
        let _ = rpc::results_struct(&message);
        let _ = rpc::imported_capability(&message);
        if let Ok(root) = message.root() {
            let _ = rpc::exception_reason(&root);
        }
    }
}

/// The results of `registerConnection`.
pub fn register_response(data: &[u8]) {
    if let Ok(Some((message, _))) = Message::parse(data)
        && let Ok(root) = message.root()
    {
        let _ = crate::cloudflare::schema::read_register_results(&root);
    }
}

/// The `ConnectRequest` and `ConnectResponse` of a visitor stream.
pub fn connect_request(data: &[u8]) {
    if let Ok(Some((message, _))) = Message::parse(data)
        && let Ok(root) = message.root()
    {
        let _ = crate::cloudflare::schema::decode_connect_request(&root);
        let _ = crate::cloudflare::schema::decode_connect_response(&root);
    }
}

fn text(data: &[u8]) -> Option<&str> {
    std::str::from_utf8(data).ok()
}

/// The `data` field of an SRV record of DoH.
pub fn srv_record(data: &[u8]) {
    if let Some(text) = text(data) {
        let _ = crate::edge_discovery::parse_srv(text);
    }
}

/// An ingress service and a forward target.
pub fn ingress_rule(data: &[u8]) {
    if let Some(value) = text(data) {
        let _ = crate::ingress::Service::parse(value);
        let _ = crate::ingress::ForwardTarget::parse(value);
    }
}

/// A YAML config file.
pub fn config_yaml(data: &[u8]) {
    if let Some(value) = text(data) {
        let _ = crate::yaml::parse(value);
    }
}

/// The serialized response headers of the HTTP/2 leg.
pub fn h2_header_block(data: &[u8]) {
    if let Some(value) = text(data) {
        let headers = crate::cloudflare::http2::decode_headers(value);
        let _ = crate::cloudflare::http2::decode_origin_response(&headers);
    }
}

/// The HTTP/1.1 head to the origin, from the fields of a `ConnectRequest`
/// of the edge (issue 272): the fields are split at the 0 bytes (the
/// method, the destination, the host, then header names and values). A
/// head that is built has one empty line, at its end, and each line ends
/// with CR LF.
pub fn request_head(data: &[u8]) {
    use crate::cloudflare::stream::{HTTP_HEADER_KEY, HTTP_HOST_KEY, HTTP_METHOD_KEY};
    let fields: Vec<String> = data.split(|b| *b == 0).map(|f| String::from_utf8_lossy(f).into_owned()).collect();
    let field = |i: usize| fields.get(i).cloned().unwrap_or_default();
    let mut metadata = vec![(HTTP_METHOD_KEY.to_string(), field(0)), (HTTP_HOST_KEY.to_string(), field(2))];
    for pair in fields.get(3..).unwrap_or_default().chunks(2) {
        let value = pair.get(1).cloned().unwrap_or_default();
        metadata.push((format!("{HTTP_HEADER_KEY}:{}", pair[0]), value));
    }
    let request = crate::cloudflare::stream::ConnectRequest {
        dest: field(1),
        conn_type: crate::cloudflare::stream::ConnectionType::Http,
        metadata,
    };
    let options = crate::ingress::OriginOptions::default();
    for upgrade in [false, true] {
        if let Ok(head) = crate::proxy::build_request_head(&request, &options, upgrade) {
            assert!(head.ends_with("\r\n\r\n"), "{head:?}");
            assert_eq!(head.matches("\r\n\r\n").count(), 1, "{head:?}");
            let crlf = head.matches("\r\n").count();
            assert_eq!(head.matches('\r').count(), crlf, "{head:?}");
            assert_eq!(head.matches('\n').count(), crlf, "{head:?}");
            // Each header line is a pair of the input, or a line that podnet
            // writes: no field makes a line of its own.
            let pairs: Vec<String> = fields
                .get(3..)
                .unwrap_or_default()
                .chunks(2)
                .map(|p| format!("{}: {}", p[0], p.get(1).cloned().unwrap_or_default()))
                .collect();
            for line in head.trim_end().split("\r\n").skip(1) {
                assert!(
                    pairs.iter().any(|p| p == line)
                        || ["Host: ", "Connection: ", "Upgrade: "].iter().any(|own| line.starts_with(own)),
                    "{line:?} in {head:?}"
                );
            }
        }
    }
}

/// The seed inputs of `target`.
pub fn seeds(target: &str) -> Vec<Vec<u8>> {
    use crate::cloudflare::schema::{ConnectRequest, ConnectionType, encode_connect_request, encode_connect_response};
    let s = |items: &[&str]| items.iter().map(|i| i.as_bytes().to_vec()).collect();
    match target {
        "capnp_message" | "rpc_message" | "register_response" | "connect_request" => vec![
            encode_connect_request(&ConnectRequest {
                dest: "http://localhost/".into(),
                conn_type: ConnectionType::Http,
                metadata: vec![("HttpMethod".into(), "GET".into())],
            }),
            encode_connect_response("", &[("HttpStatus".into(), "200".into())]),
            crate::cloudflare::rpc::our_bootstrap_return(1).to_bytes(),
            crate::cloudflare::rpc::exception_return(2, "refused").to_bytes(),
        ],
        "srv_record" => s(&["1 1 7844 region1.v2.argotunnel.com."]),
        "ingress_rule" => {
            s(&["http://127.0.0.1:8080", "unix:/run/app.sock", "tcp://host:22", "http_status:404", "spa:./site"])
        }
        "config_yaml" => s(&[
            "tunnel: x\ncredentials-file: /c.json\ningress:\n  - hostname: a.example.com\n    service: http://localhost:1\n  - service: http_status:404\n",
        ]),
        "h2_header_block" => s(&["Q29udGVudC1UeXBl:dGV4dC9wbGFpbg;WC1B:Yg"]),
        "request_head" => s(&[
            "GET\0https://x.example/a?b=1\0x.example\0Accept\0*/*\0Cookie\0a=b",
            "POST\0https://x/u\0x\0Transfer-Encoding\0chunked\0Connection\0close, X-Hop\0X-Hop\0one",
            "GET\0https://x/ws\0x\0Upgrade\0websocket\0X-A\0a\r\nInjected: 1",
        ]),
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The crash input of `capnp_message` of podnet's fuzz run 43590953876
    /// (PodUtils/podnet#555), and the same shape by hand: a double-far pointer to a list in segment 10 of a message of 1 segment.
    /// Each reader of a list gives an error, and nothing panics.
    #[test]
    fn fuzz_a_list_in_a_missing_segment_is_an_error() {
        use base64::Engine as _;
        let crash = base64::engine::general_purpose::STANDARD
            .decode("AAAAAAsAAAAAAAAAAQAHAAMIAAAAAABdAgAAAAAAAAA2AAAAAAAAAAA/ACAAAAIAAAAAAAAABZECAAAACgAAAAUAAAACAAAAAAAAADYAAAAAAAAAAD8AIAAAAgAAAAAAAAAAAAAAAAA=")
            .unwrap();
        capnp_message(&crash);
        for (elem, count) in [(2u64, 0u64), (2, 9), (6, 0), (7, 0)] {
            let mut bytes = 0u32.to_le_bytes().to_vec();
            bytes.extend_from_slice(&4u32.to_le_bytes());
            // The root struct (0 data, 1 pointer) at word 1; its pointer is a double far
            // pointer to the pad at word 2: a far pointer to segment 10, then the list tag.
            let words = [1u64 << 48, 2 | 4 | (2 << 3), 2 | (10 << 32), 1 | (elem << 32) | (count << 35)];
            for w in words {
                bytes.extend_from_slice(&w.to_le_bytes());
            }
            let (message, _) = Message::parse(&bytes).unwrap().unwrap();
            let root = message.root().unwrap();
            assert!(root.get_data(0).is_err(), "data {elem} {count}");
            assert!(root.get_text(0).is_err(), "text {elem} {count}");
            assert!(root.get_text_list(0).is_err(), "text list {elem} {count}");
            assert!(root.get_struct_list(0).is_err(), "struct list {elem} {count}");
            assert!(root.get_struct(0).is_err(), "struct {elem} {count}");
        }
    }

    /// Each target on its seeds and on 2000 mutations of them (a fixed
    /// xorshift sequence): no panic. This is the stable part of `fuzz/`.
    #[test]
    fn each_target_survives_mutations() {
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move || {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state
        };
        for (name, target) in TARGETS {
            let seeds = seeds(name);
            assert!(!seeds.is_empty(), "{name} has no seed");
            for seed in &seeds {
                target(seed);
            }
            let rounds = 2000;
            for _ in 0..rounds {
                let mut input = seeds[(next() % seeds.len() as u64) as usize].clone();
                for _ in 0..(1 + next() % 4) {
                    let r = next();
                    match r % 4 {
                        0 if !input.is_empty() => {
                            let i = (r >> 8) as usize % input.len();
                            input[i] ^= (r >> 16) as u8;
                        }
                        1 if !input.is_empty() => {
                            let i = (r >> 8) as usize % input.len();
                            input[i] = [0, 0xff, 0x7f, 0x80][(r >> 16) as usize % 4];
                        }
                        2 => {
                            let i = (r >> 8) as usize % (input.len() + 1);
                            input.insert(i, (r >> 16) as u8);
                        }
                        _ => {
                            let keep = (r >> 8) as usize % (input.len() + 1);
                            input.truncate(keep);
                        }
                    }
                }
                target(&input);
            }
        }
    }
}
