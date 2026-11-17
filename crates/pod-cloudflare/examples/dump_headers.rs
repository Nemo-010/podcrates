//! The header encoding of the crate for the cases of
//! `tools/check-header-oracle.sh`, in the form of its Go oracle: the pairs of
//! each case sorted, then `---`. The script compares this output with the Go
//! code of cloudflared and with `tools/header-oracle.txt`.

use pod_cloudflare::cloudflare::http2::encode_headers;

/// The cases of the oracle: names, then values, each list split by `,`.
const CASES: &[(&str, &str)] = &[
    ("host", "a"),
    ("host", "example.com"),
    ("X-Binary", "x"),
    ("host,cf-connecting-ip", "example.com,1.2.3.4"),
    ("a,b,c", "y,z,w"),
];

fn main() {
    for (names, values) in CASES {
        let values: Vec<&str> = values.split(',').collect();
        let headers: Vec<(String, String)> = names
            .split(',')
            .enumerate()
            .map(|(i, name)| (name.to_string(), values.get(i).copied().unwrap_or("").to_string()))
            .collect();
        let encoded = encode_headers(&headers);
        let mut pairs: Vec<&str> = encoded.split(';').collect();
        pairs.sort_unstable();
        for pair in pairs {
            println!("{pair}");
        }
        println!("---");
    }
}
