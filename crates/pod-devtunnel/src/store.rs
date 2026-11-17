//! The store of the user's token (T-378, part 2, step 3): one private file
//! that holds the token of a login, its scheme, the refresh token of Entra
//! ID and when the token ends. It is written whole with a durable replace
//! (`pod_core::files::replace_private`, mode 0600) and read only when it is
//! a regular file of this user that nobody else can read, as ssh reads a
//! key. The text of the file and each token in memory are cleared when they
//! go; no token goes into a line or an error text.

use std::path::{Path, PathBuf};
use std::time::Duration;

use pod_core::files::{self, Commit, Others};
use pod_core::{Class, Failure};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::failure::{Step, fail};
use crate::login::Granted;
use crate::token::{Scheme, UserToken};

/// The version of the shape of the file.
pub const SCHEMA: u32 = 1;
/// A token that ends within this is old: a caller refreshes it first.
pub const MARGIN: Duration = Duration::from_secs(300);

/// The file of the store.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TokenStore {
    path: PathBuf,
}

/// What the store holds.
pub struct Kept {
    pub token: UserToken,
    pub refresh: Option<Zeroizing<String>>,
    /// When the token ends, in milliseconds since the epoch; none when the
    /// host gave no life (a token of GitHub).
    pub ends_ms: Option<i64>,
}

impl Kept {
    /// Whether the token ends within [`MARGIN`] of `now_ms`.
    pub fn old(&self, now_ms: i64) -> bool {
        self.ends_ms.is_some_and(|end| end - now_ms <= MARGIN.as_millis() as i64)
    }
}

/// No token in a line.
impl std::fmt::Debug for Kept {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kept")
            .field("scheme", &self.token.scheme())
            .field("refresh", &self.refresh.is_some())
            .field("ends_ms", &self.ends_ms)
            .finish()
    }
}

#[derive(Serialize, Deserialize)]
struct File {
    schema: u32,
    scheme: String,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    refresh: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ends_ms: Option<i64>,
}

impl Drop for File {
    fn drop(&mut self) {
        use zeroize::Zeroize;
        self.token.zeroize();
        if let Some(refresh) = &mut self.refresh {
            refresh.zeroize();
        }
    }
}

impl TokenStore {
    /// The store in the file `path`.
    pub fn at(path: impl Into<PathBuf>) -> TokenStore {
        TokenStore { path: path.into() }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Keep what `granted` gave at `now_ms`. `Ok(Some(why))` when the file
    /// is in place but its directory was not synced.
    pub fn save(&self, granted: &Granted, now_ms: i64) -> Result<Option<String>, Failure> {
        let file = File {
            schema: SCHEMA,
            scheme: granted.token.scheme().word().to_string(),
            token: granted.token.secret().to_string(),
            refresh: granted.refresh.as_ref().map(|r| r.to_string()),
            ends_ms: granted.expires_in.map(|life| now_ms.saturating_add(life.as_millis() as i64)),
        };
        let text = Zeroizing::new(serde_json::to_string(&file).map_err(|_| self.failed("could not write the token"))?);
        if let Some(dir) = self.path.parent().filter(|d| !d.as_os_str().is_empty()) {
            files::private_dir(dir).map_err(|e| self.failed(&format!("its directory: {e}")))?;
        }
        match files::replace_private(&self.path, text.as_bytes(), 0o600, false) {
            Ok(Commit::Durable) => Ok(None),
            Ok(other) => Ok(other.unconfirmed().map(|e| e.to_string())),
            Err(e) => Err(self.failed(&format!("could not write it: {e}"))),
        }
    }

    /// What the store holds; `None` when there is no file. A file that
    /// others can read, or that is not the store's shape, is refused with
    /// the reason, never read.
    pub fn load(&self) -> Result<Option<Kept>, Failure> {
        let Some(text) = files::read_own(&self.path, Others::NoAccess).map_err(|why| self.failed(&why))? else {
            return Ok(None);
        };
        let text = Zeroizing::new(text);
        let mut file: File =
            serde_json::from_str(&text).map_err(|_| self.failed("it is not a store of a token: sign in again"))?;
        if file.schema != SCHEMA {
            return Err(self.failed(&format!("its schema is {}, not {SCHEMA}: sign in again", file.schema)));
        }
        let scheme =
            Scheme::parse(&file.scheme).ok_or_else(|| self.failed("its scheme is not one of the service's"))?;
        let token = UserToken::new(scheme, std::mem::take(&mut file.token))?;
        Ok(Some(Kept { token, refresh: file.refresh.take().map(Zeroizing::new), ends_ms: file.ends_ms }))
    }

    /// Remove the file: `false` when there was none.
    pub fn forget(&self) -> Result<bool, Failure> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(self.failed(&format!("could not remove it: {e}"))),
        }
    }

    fn failed(&self, why: &str) -> Failure {
        fail(Step::Management, Class::Config, format!("the token store {}: {why}", self.path.display()))
    }
}
