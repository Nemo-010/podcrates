//! The keys of the iroh road (PodUtils/podssh@T-163): the identities of
//! `pod-identity`, one Ed25519 key for each role, kept in private files
//! (`pod_identity::file`), as iroh's secret keys. The pair's road proves the
//! same key in its channel, so a node has one identity on each road. A key is
//! shown by its fingerprint, never by its secret.

use iroh::{PublicKey, SecretKey};
use pod_core::entropy::Entropy;
use pod_core::files::Places;
use pod_identity::{self as identity, Identity, file};

pub use pod_identity::file::{CLIENT_FILE, OLD_CLIENT_FILE, Place, client_place, node_file, node_place, old_node_file};

/// A key, as iroh takes it and as the channel proves it, where it is kept,
/// and whether it was made by this call.
pub struct Key {
    pub secret: SecretKey,
    pub identity: Identity,
    /// The file; `None` for an ephemeral key.
    pub path: Option<std::path::PathBuf>,
    /// Whether the key is new: a node's ticket then changed.
    pub made: bool,
}

impl Key {
    pub fn public(&self) -> PublicKey {
        self.secret.public()
    }
}

impl std::fmt::Debug for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Key")
            .field("public", &fingerprint(&self.public()))
            .field("path", &self.path)
            .field("made", &self.made)
            .finish()
    }
}

/// The identity key that an iroh key is: the same 32 bytes of Ed25519.
pub fn identity_key(public: &PublicKey) -> identity::PublicKey {
    identity::PublicKey(*public.as_bytes())
}

/// A node's name in a destination and in the known hosts (`iroh:` and this):
/// its key in iroh's hex, so that a host key kept under the name is still
/// found. A name, not how a key is shown.
pub fn name(public: &PublicKey) -> String {
    public.to_string()
}

/// How a key is shown: its SHA256 fingerprint, as on the pair's road
/// (PodUtils/podssh@T-087). It is not secret, and an allowlist takes it, as it
/// takes the key.
pub fn fingerprint(public: &PublicKey) -> String {
    identity_key(public).fingerprint()
}

/// The key kept at `place`, made when there is none, in the `places` of the
/// caller's program (`pod_core::files::places_from`).
pub fn load(places: &Places, place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    file::load(places, place, entropy).map(as_iroh)
}

/// [`load`], with `dirs` as the cache's directories (for tests).
pub fn load_in(dirs: &[std::path::PathBuf], place: &Place, entropy: &mut dyn Entropy) -> Result<Key, String> {
    file::load_in(dirs, place, entropy).map(as_iroh)
}

fn as_iroh(key: file::Key) -> Key {
    let secret = SecretKey::from_bytes(&key.identity.seed());
    Key { secret, identity: key.identity, path: key.path, made: key.made }
}
