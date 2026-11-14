//! The events of NIP-01 and the messages of a relay, with no I/O: a key of
//! secp256k1 for one pairing, the id of an event (SHA-256 of
//! `[0, pubkey, created_at, kind, tags, content]` as compact JSON), its
//! BIP-340 Schnorr signature over the id, the check of a received event,
//! and the reading of each message that a relay sends. A fuzz target can
//! run [`said`] and [`checked`] on untrusted bytes.

use k256::schnorr::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::schnorr::{Signature, SigningKey, VerifyingKey};
use pod_core::entropy::{Entropy, OsEntropy};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::Failed;
use crate::message::{hex, unhex, words};

/// A key of one pairing: drawn fresh, never kept, so that no two pairings
/// of one host share a public key on a relay.
pub struct Key {
    signing: SigningKey,
    /// The x-only public key in lower-case hex, as an event carries it.
    pubkey: String,
}

impl Key {
    /// A new key from the system's random bytes.
    pub fn new() -> Result<Key, Failed> {
        Key::drawn(&mut OsEntropy)
    }

    /// A new key from `entropy`: a draw that is no scalar of the curve (one
    /// in 2^128) is drawn again.
    pub fn drawn(entropy: &mut dyn Entropy) -> Result<Key, Failed> {
        loop {
            let mut bytes = Zeroizing::new([0u8; 32]);
            entropy.fill(&mut bytes[..]).map_err(|_| Failed::NoRandom)?;
            if let Ok(key) = Key::from_secret(&bytes[..]) {
                return Ok(key);
            }
        }
    }

    /// The key of the secret scalar `secret` (32 bytes, big-endian).
    pub fn from_secret(secret: &[u8]) -> Result<Key, Failed> {
        let signing = SigningKey::from_slice(secret).map_err(|_| Failed::Mine("no scalar of secp256k1".into()))?;
        let pubkey = hex(&signing.verifying_key().to_bytes());
        Ok(Key { signing, pubkey })
    }

    /// The x-only public key in lower-case hex.
    pub fn pubkey(&self) -> &str {
        &self.pubkey
    }

    /// The event of `kind` with `tags` and `content` at `created_at`, its
    /// id and its signature made: the JSON object that `["EVENT", ...]`
    /// carries.
    pub fn sign(&self, created_at: u64, kind: u16, tags: &Value, content: &str) -> Result<Value, Failed> {
        let id = id_of(&self.pubkey, created_at, kind, tags, content);
        let sig = self.signing.sign_prehash(&id).map_err(|_| Failed::Broken("an event could not be signed".into()))?;
        Ok(json!({
            "id": hex(&id),
            "pubkey": self.pubkey,
            "created_at": created_at,
            "kind": kind,
            "tags": tags,
            "content": content,
            "sig": hex(&sig.to_bytes()),
        }))
    }
}

/// The id of an event: SHA-256 of its serialization by NIP-01. serde_json
/// writes compact JSON, escapes the characters that NIP-01 names, and
/// writes each other character as it is.
pub fn id_of(pubkey: &str, created_at: u64, kind: u16, tags: &Value, content: &str) -> [u8; 32] {
    let serial = json!([0, pubkey, created_at, kind, tags, content]).to_string();
    Sha256::digest(serial.as_bytes()).into()
}

/// An event that a relay passed on, its id and its signature checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Checked {
    pub id: String,
    pub pubkey: String,
    pub created_at: u64,
    pub kind: u16,
    /// The name and the first value of each tag that has a value.
    pub tags: Vec<(String, String)>,
    pub content: String,
}

impl Checked {
    /// The first value of the tag `name`.
    pub fn tag(&self, name: &str) -> Option<&str> {
        self.tags.iter().find(|(n, _)| n == name).map(|(_, v)| v.as_str())
    }
}

/// `event` read and checked: each field of NIP-01 there and of its type,
/// the id the hash of the others, and the signature valid for the id by
/// the public key. `None` for each other value: a relay or a stranger
/// changed it.
pub fn checked(event: &Value) -> Option<Checked> {
    let text = |key: &str| event[key].as_str();
    let (pubkey, content) = (text("pubkey")?, text("content")?);
    let created_at = event["created_at"].as_u64()?;
    let kind = u16::try_from(event["kind"].as_u64()?).ok()?;
    let raw_tags = &event["tags"];
    let mut tags = Vec::new();
    for tag in raw_tags.as_array()? {
        let parts = tag.as_array()?;
        if parts.iter().any(|p| !p.is_string()) {
            return None;
        }
        if let (Some(name), Some(value)) = (parts.first().and_then(Value::as_str), parts.get(1).and_then(Value::as_str))
        {
            tags.push((name.to_string(), value.to_string()));
        }
    }
    let id = id_of(pubkey, created_at, kind, raw_tags, content);
    if text("id")? != hex(&id) {
        return None;
    }
    let key = VerifyingKey::from_slice(&unhex(pubkey).filter(|k| k.len() == 32)?).ok()?;
    let sig = Signature::from_slice(&unhex(text("sig")?)?).ok()?;
    key.verify_prehash(&id, &sig).ok()?;
    Some(Checked { id: hex(&id), pubkey: pubkey.to_string(), created_at, kind, tags, content: content.to_string() })
}

/// What a relay said, by NIP-01 (and NIP-42's `AUTH`).
#[derive(Debug, Clone, PartialEq)]
pub enum Said {
    /// `["EVENT", sub, event]`: an event of the subscription `sub`, not
    /// checked yet.
    Event { sub: String, event: Value },
    /// `["OK", id, accepted, message]`: the answer to an `EVENT`.
    Ok { id: String, accepted: bool, message: String },
    /// `["EOSE", sub]`: the end of the stored events of `sub`.
    Eose(String),
    /// `["CLOSED", sub, message]`: the relay ended or refused `sub`.
    Closed { sub: String, message: String },
    /// `["NOTICE", message]`: words for people.
    Notice(String),
    /// `["AUTH", challenge]`: this client does not authenticate; a relay
    /// that needs it refuses the `REQ` or the `EVENT` in its words.
    Auth,
    /// A message of a type that a later NIP may add (`COUNT`, ...).
    Other(String),
}

/// The message of a relay in `text`; `None` for text that is no JSON array
/// with a type first, or a known type with fields of the wrong types. The
/// words of a relay are on one line and cut short.
pub fn said(text: &[u8]) -> Option<Said> {
    let value: Value = serde_json::from_slice(text).ok()?;
    let all = value.as_array()?;
    let field = |n: usize| all.get(n).and_then(Value::as_str);
    let message = |n: usize| all.get(n).map_or_else(String::new, words);
    Some(match field(0)? {
        "EVENT" => Said::Event { sub: field(1)?.to_string(), event: all.get(2)?.clone() },
        "OK" => Said::Ok { id: field(1)?.to_string(), accepted: all.get(2)?.as_bool()?, message: message(3) },
        "EOSE" => Said::Eose(field(1)?.to_string()),
        "CLOSED" => Said::Closed { sub: field(1)?.to_string(), message: message(2) },
        "NOTICE" => Said::Notice(message(1)),
        "AUTH" => Said::Auth,
        other => Said::Other(words(&Value::String(other.to_string()))),
    })
}

/// Whether an `OK` false with `message` leaves the event harmless: `mute`
/// (no subscriber heard an ephemeral event: lost, as a resend repairs) or
/// `duplicate` (the relay had it).
pub fn harmless(message: &str) -> bool {
    ["mute:", "duplicate:"].iter().any(|prefix| message.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET_3: &str = "0000000000000000000000000000000000000000000000000000000000000003";
    const PUBKEY_3: &str = "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9";

    // BIP-340's test vector 0 (bip-0340/test-vectors.csv): the key 3, aux 0
    // and the message 0.
    #[test]
    fn a_signature_is_bip340s_by_its_vector() {
        let key = Key::from_secret(&unhex(SECRET_3).unwrap()).unwrap();
        assert_eq!(key.pubkey(), PUBKEY_3);
        let sig = key.signing.sign_prehash(&[0u8; 32]).unwrap();
        let want = "e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca8215\
                    25f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0";
        assert_eq!(hex(&sig.to_bytes()), want);
    }

    // Computed with Python's json.dumps (separators ",", ":", no ASCII
    // escape) and hashlib, software that this crate did not write.
    #[test]
    fn an_id_is_the_hash_of_the_serialization_of_nip01() {
        let message = r#"{"side":"0123456789","phase":"pake","body":"00ff"}"#;
        let tags = json!([["t", "pwtestg"]]);
        let id = id_of(PUBKEY_3, 1_700_000_000, 25431, &tags, message);
        assert_eq!(hex(&id), "70653f3d4264a21d583aeb8f9b0e0e50dc5492ea95ea98956d407f2cb355e1be");
        let escaped = id_of(PUBKEY_3, 1_700_000_000, 25431, &json!([]), "a\"b\\c\nd\u{e9}");
        assert_eq!(hex(&escaped), "e8c01d065e7e81e4578eca718a63b19fc91c84c673aa9c413c0ff6aab261c894");
    }

    // Signed by a BIP-340 signer in Python written from the BIP's reference
    // code (the key 3, auxiliary bytes zero), software that this crate did
    // not write; the same event is the seed `event-signed` of the fuzz
    // target `nostr_message`.
    const PYTHON_SIG: &str = "36a078b0b14139340c38acfaf2dacab76c421e81cd114401eccfe7a5f0abdb28\
                              227c1642cefdb27105b7a905e3e622ecce01a4263424b41ef7b47c11587d154b";

    #[test]
    fn an_event_of_another_signer_checks_and_this_one_signs_the_same() {
        let content = r#"{"side":"0123456789","phase":"pake","body":"00ff"}"#;
        let tags = json!([["t", "pwtestg"]]);
        let theirs = json!({
            "id": "70653f3d4264a21d583aeb8f9b0e0e50dc5492ea95ea98956d407f2cb355e1be",
            "pubkey": PUBKEY_3, "created_at": 1_700_000_000u64, "kind": 25431,
            "tags": tags, "content": content, "sig": PYTHON_SIG,
        });
        assert!(checked(&theirs).is_some(), "the event of another signer checks");
        let key = Key::from_secret(&unhex(SECRET_3).unwrap()).unwrap();
        assert_eq!(key.sign(1_700_000_000, 25431, &tags, content).unwrap(), theirs);
    }

    #[test]
    fn a_signed_event_checks_and_a_changed_one_does_not() {
        let key = Key::new().unwrap();
        let event = key.sign(1_700_000_000, 25431, &json!([["t", "pwtestg"]]), "hello").unwrap();
        let read = checked(&event).expect("a good event");
        assert_eq!((read.pubkey.as_str(), read.kind, read.tag("t")), (key.pubkey(), 25431, Some("pwtestg")));
        assert_eq!(read.content, "hello");
        for (field, value) in [
            ("content", json!("hellO")),
            ("created_at", json!(1_700_000_001u64)),
            ("tags", json!([["t", "pwtestt"]])),
            ("kind", json!(25432)),
            ("pubkey", json!(Key::new().unwrap().pubkey())),
            ("sig", json!("00".repeat(64))),
            ("id", json!("00".repeat(32))),
        ] {
            let mut changed = event.clone();
            changed[field] = value;
            assert_eq!(checked(&changed), None, "{field} changed");
        }
        let mut cut = event.clone();
        cut.as_object_mut().unwrap().remove("sig");
        assert_eq!(checked(&cut), None, "no sig");
    }

    #[test]
    fn two_keys_are_two_public_keys() {
        assert_ne!(Key::new().unwrap().pubkey(), Key::new().unwrap().pubkey());
        assert!(Key::from_secret(&[0u8; 32]).is_err(), "zero is no scalar");
        assert!(Key::from_secret(&[0xff; 32]).is_err(), "past the order");
    }

    #[test]
    fn each_message_of_a_relay_is_read() {
        let event = said(br#"["EVENT","s1",{"id":"x"}]"#).unwrap();
        assert_eq!(event, Said::Event { sub: "s1".into(), event: json!({ "id": "x" }) });
        let ok = said(br#"["OK","ab",false,"pow: difficulty 20 is needed"]"#).unwrap();
        assert_eq!(ok, Said::Ok { id: "ab".into(), accepted: false, message: "pow: difficulty 20 is needed".into() });
        assert_eq!(said(br#"["EOSE","s1"]"#), Some(Said::Eose("s1".into())));
        let closed = said(br#"["CLOSED","s1","auth-required: we\nonly serve members"]"#).unwrap();
        assert_eq!(closed, Said::Closed { sub: "s1".into(), message: "auth-required: we only serve members".into() });
        assert_eq!(said(br#"["NOTICE","slow down"]"#), Some(Said::Notice("slow down".into())));
        assert_eq!(said(br#"["AUTH","challenge"]"#), Some(Said::Auth));
        assert_eq!(said(br#"["COUNT","s1",{"count":1}]"#), Some(Said::Other("COUNT".into())));
        for bad in [&b"{}"[..], b"[]", b"[1]", br#"["OK","ab","yes"]"#, br#"["EVENT","s1"]"#, b"not json"] {
            assert_eq!(said(bad), None, "{}", String::from_utf8_lossy(bad));
        }
    }

    #[test]
    fn a_mute_or_a_duplicate_is_harmless_and_each_other_refusal_is_not() {
        assert!(harmless("mute: no one was listening to your ephemeral event"));
        assert!(harmless("duplicate: already have this event"));
        for refusal in ["pow: difficulty 26 is less than 30", "restricted: not allowed", "rate-limited: slow", ""] {
            assert!(!harmless(refusal), "{refusal}");
        }
    }
}
