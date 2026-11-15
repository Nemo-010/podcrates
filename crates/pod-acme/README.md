# pod-acme

An ACME client (RFC 8555): a certificate for a name from a CA (Let's
Encrypt by default), proven by TLS-ALPN-01 (RFC 8737) on the caller's own
listener, so that nothing else listens and port 443 alone is needed; kept
in a cache directory of the caller's, so that a restart asks the CA for
nothing, and renewed before its end. It also writes the CSR of a tunnel's
name and a self-signed certificate of a pinned key.

The base is podssh's `crates/podssh-cli/src/acme/` (the client of
`podssh relay serve --acme NAME`), with the `Url` of
`crates/podssh-cli/src/update/fetch.rs`.

## API

| Module | What |
| --- | --- |
| crate root | `Acme { name, directory, http, store, events }`: `new(name, directory, http, places, events)`, `host`, `held(now_secs)` (the certificate kept, while it holds), `obtain(&served)` (order, keep, serve); `keep(acme, served, held)` (the first certificate and each renewal, for as long as the caller runs; its end is the failure of the first order); `renew_at(&leaf)`, `next_retry(last)`, `about(&leaf)`, `utc(secs)`, `lets_encrypt()` (the endpoint `directory` of `letsencrypt-acme` of `pod-services`); `RENEW_BEFORE`, `FIRST_RETRY`, `MOST_RETRY`, `REQUEST`; `Failed` |
| `key` | `Key` (a P-256 key: `generate()`, `from_pkcs8(der)`, `pkcs8`, `public`, `pem`, `sign_der`, `sign_fixed`; rcgen's `PublicKeyData` and `SigningKey`; no `Debug` shows the private half), `POINT` |
| `jws` | `Account` (`generate()`, `from_pkcs8(der)`, `pem`, `jwk`, `thumbprint`, `key_authorization(token)`, `sign(kid, nonce, url, payload)`: ES256 in JWS's flattened JSON), `thumbprint(x, y)` (RFC 7638), `b64url` |
| `certs` | `pem(label, der)`, `pem_block(text, label)`, `csr(name, &key)`, `tunnel_csr(hostname, &key)` (the name as its common name, and its wildcard), `challenge(name, key_authorization, now_secs)` (the certificate of TLS-ALPN-01 and its key), `own(name, &key, now_secs)` (a year long, for a pinned key), `Leaf { names, not_before, not_after }`, `leaf(der)`, `load(cert, key)` (a pair as `pod-tls`'s server takes it); `Key` |
| `client` | `Http { client, trust, timeout }` (`send`), `Directory` (`parse`), `Client` (`open`, `account`, `post`, `get_json`, `key`), `json_of`, `problem`, `describe`, `retry_after`, `PEM_CHAIN` |
| `order` | `order(&mut client, name, &served)` (an authorization by TLS-ALPN-01 through `pod_tls::server::Served`, the finalization with a CSR of a new key, the chain checked against the key and the name), `Issued { key, chain, leaf }`, `reason`, `now_secs` |
| `store` | `Store { dir, name }`: `open(directory, name, places)`, `pem_path`, `account()` (made once, never replaced), `held`, `keep(&key, chain)` (replaced whole by a rename); `tag(directory)` (`HOST-DIGEST`), `DIR`, `ACCOUNT` |
| `url` | `Url { host, port, path }` (`parse` of `https://` alone, `shown` with no query) |
| `Failed` | `Directory`, `Store`, `Ca`, `Late`; `stage_and_class()`, `within(before, after)`, `From<Failed> for pod_core::Failure` |

## Keys

A key is drawn here: 32 bytes of the system's entropy (`pod_core::entropy`)
as the scalar, its public point by `p256`, written as PKCS #8 in the form
of ring and OpenSSL (a key that podssh kept with aws-lc-rs reads). Each
signature (the JWS of a request, a CSR, the certificate of a challenge) is
deterministic ECDSA (RFC 6979) of `p256`, pure Rust, as the server of
`pod-tls` signs with its P-256 key: the pure provider of `pod-tls` loads no
private key, so a crypto provider of the caller cannot sign here (C601). A
JWS takes r and s of 32 bytes each. rcgen writes the DER of each CSR and
certificate with no crypto of its own.

## Features

None.

## Settings

| Setting | Default | What |
| --- | --- | --- |
| `Acme::new`'s `directory` | `lets_encrypt()` | the CA's directory, an `https://` URL |
| `Http::client` | none | the caller's `pod_proxy::Client`: the way out, the TLS context, the user agent |
| `Http::trust` | none | the roots of the CA (podssh: its `--ca-file`, else the host's) |
| `Http::timeout` | `REQUEST` (30 s) | each request and its answer |
| `Acme::new`'s `places` | none | the caller's cache directories, in order; the state goes under `acme/HOST-DIGEST/` of the first that holds it or can hold it (mode 0700) |
| `Acme::events` | none | the lines `acme.account`, `acme.issued`, `acme.renewal` |

The crate reads no variable of the environment. A caller with no cache
(podssh's `PODSSH_CACHE_DIR=none`) refuses `--acme` itself, as the state
must outlive a restart.

## Failures

`Failed::Directory` (a directory that is no `https://` URL) is
`Origin`/`Usage`; `Store` (no private directory, a file that does not
load) is `Host`/`Unavailable`; `Ca` (a refusal, a problem document, an
answer that is not ACME, no answer) is `Origin`/`Unavailable`; `Late` (no
certificate within the 600 s of an order) is `Origin`/`Timeout`. The words
are the source's.

## Parity

- [x] the directory, its terms, the refusal of an external account binding;
- [x] the account made once and found by its key, `badNonce` sent again up
  to 8 times, a nonce of the shape of base64url alone;
- [x] the order: the authorization by TLS-ALPN-01 alone, the challenge's
  certificate served while it is asked for, the poll by Retry-After (1 to
  10 s), a final status with the CA's reason, the finalization with a CSR
  of a new key, the chain checked against the key and the name;
- [x] the state: `account.key` and `NAME.pem`, each 0600, the directory
  0700, `NAME.pem` replaced whole by a rename;
- [x] the renewal 30 days before the end, or at a third of a short life;
  the wait after a failed renewal from 5 min, doubled, up to 6 h; the
  certificate of before stays;
- [x] the CSR of a tunnel's name and the certificate of a pinned key.

The differences: the keys are `p256`'s (podssh: aws-lc-rs); the HTTPS
client, the trust, the places of the state and the lines are the caller's
(podssh: its process context and an `mpsc` sender); `Store::open` takes the
places, and the caller refuses `--acme` with no cache; the failures are
`Failed`; `keep` ends with a `Failed`.

## Adoption map

| Consumer | Old path | New path |
| --- | --- | --- |
| podssh | `crates/podssh-cli/src/acme/` (`certs`, `client`, `jws`, `order`, `store`, `renew_at`, `next_retry`, `about`, `lets_encrypt`, the constants) | `pod_acme::{...}`: `acme/mod.rs` re-exports the crate |
| podssh | `Acme::new(name, directory, trust)` (`relay_serve/certs.rs`, `node_publish_end.rs`) | `acme::new(name, directory, trust)`: podssh's glue builds `Http` with `podssh_ws::client::getter(&ProxyChoice::FromEnvironment)`, `REQUEST` and the trust, the places of `cache::candidate_dirs()`, and refuses `PODSSH_CACHE_DIR=none` (78), a bad directory (64) and no private directory (73) as before |
| podssh | `acme::keep(ca, served, held, say)` | `acme::keep(ca, served, held, say)` of the glue: the lines of the `Acme` go to `say`, and the end is `Failed::to_string()` |
| podssh | `certs::Key`, `certs::{pem, pem_block, own, tunnel_csr}` (`pinggy_cert.rs`, `node_opentunnel.rs`) | the same names, from `pod_acme::certs` |
| podssh | the dependencies `rcgen`, `x509-parser` and `aws-lc-rs` of the client | `pod-acme` (git tag); podssh keeps `aws-lc-rs` for russh |
| podssh | PodUtils/podssh:scripts/interop-acme.sh, `acme-interop.yml` | stay in podssh: they run `podssh relay serve --acme` against Pebble |

The adoption trial is `adoption/podssh/pod-acme.patch` with its `.run`,
`.commit` and `.needs` (it applies after `pod-transit`'s patch, which
moves each podcrates tag to `v0.49.0`). podssh's `rcgen` goes to its
`[dev-dependencies]`: only the stand-in release of its tests takes it now.

## Tests

`cargo test -p pod-acme`, unit tests alone (no network): the key, its
PKCS #8 and both forms of its signature checked by `p256`, a key that
ring wrote; the
thumbprint of RFC 7517's key; a JWS checked by `p256`; a key
authorization; the CSR of a name and of a tunnel, and the certificate of
a challenge, read by x509-parser; a pair that a renewal half wrote,
refused; PEM; the directory of RFC 8555; a problem with its subproblems;
Pebble's `badNonce`; Retry-After in both forms; the JSON of 200 and 201
alone; the reason of an order; the state's tag, its account made once and
its certificate replaced whole, each file private; the time of a renewal
and the waits after a failure; the stage and the class of each failure;
the URL of a directory.

The plants (`scripts/plants/`, group `acme`): `acme-csr-subject`,
`acme-challenge-not-critical`, `acme-jws-kid-and-jwk`,
`acme-nonce-any-shape`, `acme-renew-too-early`, `acme-jws-signature-swapped`,
`acme-store-not-private`.

## Sources

`SOURCES` lists each file of podssh at `b9c04657` and the file that it
became.
