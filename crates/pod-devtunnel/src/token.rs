//! The tokens of a connection: the credential of the caller for the
//! management API (the user's token, a tunnel access token, or none), and
//! the connect token of a tunnel, which the relay takes. Each token is a
//! secret: no `Debug`, no line, no event and no error text holds it, and
//! its memory is cleared when it goes.

use std::fmt;

use pod_core::{Class, Failure};
use zeroize::Zeroizing;

use crate::failure::{Step, fail};

/// The most bytes of a token: a JWT of the service is some KiB.
pub const TOKEN_MOST: usize = 16 * 1024;

/// The scheme of the user's token in `Authorization` (the fact
/// `user-schemes` of `microsoft-devtunnel`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Scheme {
    /// A token of GitHub.
    Github,
    /// A token of Microsoft Entra ID (AAD) or of a Microsoft account.
    Aad,
    /// A plain OAuth bearer token.
    Bearer,
}

impl Scheme {
    /// Each scheme.
    pub const ALL: [Scheme; 3] = [Scheme::Github, Scheme::Aad, Scheme::Bearer];

    /// The word of the scheme in `Authorization`.
    pub fn word(self) -> &'static str {
        match self {
            Scheme::Github => "github",
            Scheme::Aad => "aad",
            Scheme::Bearer => "bearer",
        }
    }

    /// The scheme of `word`, in any case.
    pub fn parse(word: &str) -> Option<Scheme> {
        Scheme::ALL.into_iter().find(|s| s.word().eq_ignore_ascii_case(word))
    }
}

impl fmt::Display for Scheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.word())
    }
}

/// The checks of a token's text: not empty, at most [`TOKEN_MOST`] bytes,
/// and visible ASCII only, so that it cannot break a header. The failure
/// names the rule, never the text.
fn checked(class: Class, what: &str, text: String) -> Result<Zeroizing<String>, Failure> {
    let text = Zeroizing::new(text);
    let step = Step::Management;
    if text.is_empty() {
        return Err(fail(step, class, format!("the {what} is empty")));
    }
    if text.len() > TOKEN_MOST {
        return Err(fail(step, class, format!("the {what} is longer than {TOKEN_MOST} bytes")));
    }
    if !text.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(fail(step, class, format!("the {what} holds a byte that a header cannot carry")));
    }
    Ok(text)
}

/// The user's token for the management API, with its scheme. The caller
/// reads it from its own store (podssh: a private file).
#[derive(Clone)]
pub struct UserToken {
    scheme: Scheme,
    secret: Zeroizing<String>,
}

impl UserToken {
    /// The token `secret` of `scheme`. A token that is empty, too long or
    /// holds a byte that is not visible ASCII is a usage failure.
    pub fn new(scheme: Scheme, secret: impl Into<String>) -> Result<UserToken, Failure> {
        Ok(UserToken { scheme, secret: checked(Class::Usage, "user token", secret.into())? })
    }

    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The value of `Authorization`: the scheme, a space, the token.
    pub(crate) fn header(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{} {}", self.scheme.word(), self.secret.as_str()))
    }
}

impl fmt::Debug for UserToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserToken").field("scheme", &self.scheme).field("secret", &"<hidden>").finish()
    }
}

/// A tunnel access token that the owner of a tunnel gives to a user with
/// no account (`devtunnel token TUNNEL --scopes connect`, about 24 h). The
/// management API takes it with the scheme of the fact `access-scheme`; the
/// relay takes it when the answer of the API holds no connect token.
#[derive(Clone)]
pub struct AccessToken(Zeroizing<String>);

impl AccessToken {
    /// The token `secret`. A token that is empty, too long or holds a byte
    /// that is not visible ASCII is a usage failure.
    pub fn new(secret: impl Into<String>) -> Result<AccessToken, Failure> {
        Ok(AccessToken(checked(Class::Usage, "tunnel access token", secret.into())?))
    }

    /// The value of `Authorization` for the management API.
    pub(crate) fn header(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{} {}", crate::service::access_scheme(), self.0.as_str()))
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken(<hidden>)")
    }
}

/// The credential of a caller for the management API.
#[derive(Clone, Debug)]
pub enum Credential {
    /// The user's token: the tunnel of the user's account, or one that an
    /// access control entry grants to the user.
    User(UserToken),
    /// A tunnel access token with the scope `connect`.
    Access(AccessToken),
    /// No token: a tunnel with an access control entry that allows
    /// anonymous access (`devtunnel access create --anonymous`).
    Anonymous,
}

impl Credential {
    /// The form of the credential, for the text of a refusal: never a
    /// byte of the token.
    pub fn form(&self) -> &'static str {
        match self {
            Credential::User(user) => match user.scheme() {
                Scheme::Github => "a GitHub user token",
                Scheme::Aad => "an AAD user token",
                Scheme::Bearer => "a bearer user token",
            },
            Credential::Access(_) => "a tunnel access token",
            Credential::Anonymous => "no token",
        }
    }

    /// The value of `Authorization` for the management API; none for
    /// [`Credential::Anonymous`].
    pub(crate) fn header(&self) -> Option<Zeroizing<String>> {
        match self {
            Credential::User(user) => Some(user.header()),
            Credential::Access(access) => Some(access.header()),
            Credential::Anonymous => None,
        }
    }
}

impl From<UserToken> for Credential {
    fn from(user: UserToken) -> Credential {
        Credential::User(user)
    }
}

impl From<AccessToken> for Credential {
    fn from(access: AccessToken) -> Credential {
        Credential::Access(access)
    }
}

/// The connect token of a tunnel, from its connect information. The relay
/// takes it in the upgrade; a reconnect asks the management API for a
/// fresh one.
#[derive(Clone)]
pub struct ConnectToken(Zeroizing<String>);

impl ConnectToken {
    /// The token of an answer of the management API.
    pub(crate) fn new(text: String) -> Result<ConnectToken, Failure> {
        Ok(ConnectToken(checked(Class::Protocol, "connect token of the answer", text)?))
    }

    /// The caller's own tunnel access token, for the relay.
    pub(crate) fn of_access(access: &AccessToken) -> ConnectToken {
        ConnectToken(access.0.clone())
    }

    /// The value of `Authorization` for the relay: the scheme of the fact
    /// `relay-scheme`, a space, the token.
    pub(crate) fn header(&self) -> Zeroizing<String> {
        Zeroizing::new(format!("{} {}", crate::service::relay_scheme(), self.0.as_str()))
    }

    /// True when both tokens are the same, with no copy of either.
    pub fn same(&self, other: &ConnectToken) -> bool {
        self.0.as_str() == other.0.as_str()
    }
}

impl fmt::Debug for ConnectToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ConnectToken(<hidden>)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_scheme_has_the_word_of_the_vendor() {
        let words: Vec<&str> = Scheme::ALL.iter().map(|s| s.word()).collect();
        let facts: Vec<&str> = crate::service::service()
            .texts("user-schemes")
            .expect("the fact user-schemes")
            .iter()
            .map(|t| t.as_ref())
            .collect();
        assert_eq!(words, facts);
        assert_eq!(Scheme::parse("GitHub"), Some(Scheme::Github));
        assert_eq!(Scheme::parse("tunnel"), None);
    }

    #[test]
    fn a_token_that_cannot_go_in_a_header_is_refused_and_not_shown() {
        for bad in ["", "two words", "line\r\nX-Other: 1", "caf\u{e9}"] {
            let failure = UserToken::new(Scheme::Github, bad).unwrap_err();
            assert_eq!(failure.class, Class::Usage);
            if !bad.is_empty() {
                assert!(!failure.chain().contains(bad), "{}", failure.chain());
            }
        }
        assert!(UserToken::new(Scheme::Github, "x".repeat(TOKEN_MOST + 1)).is_err());
        let token = UserToken::new(Scheme::Aad, "made-up-user-token").unwrap();
        assert_eq!(token.header().as_str(), "aad made-up-user-token");
        assert!(!format!("{token:?}").contains("made-up"));
    }

    #[test]
    fn each_form_of_credential_has_its_header_and_a_name_with_no_token() {
        let access = AccessToken::new("made-up-access-token").unwrap();
        assert_eq!(access.header().as_str(), "tunnel made-up-access-token");
        assert_eq!(ConnectToken::of_access(&access).header().as_str(), "tunnel made-up-access-token");
        assert_eq!(AccessToken::new("two words").unwrap_err().class, Class::Usage);
        let user = UserToken::new(Scheme::Github, "made-up-user-token").unwrap();
        let forms = [Credential::from(user), Credential::from(access), Credential::Anonymous];
        let headers: Vec<Option<String>> = forms.iter().map(|c| c.header().map(|h| h.to_string())).collect();
        assert_eq!(
            headers,
            [Some("github made-up-user-token".into()), Some("tunnel made-up-access-token".into()), None]
        );
        let names: Vec<&str> = forms.iter().map(Credential::form).collect();
        assert_eq!(names, ["a GitHub user token", "a tunnel access token", "no token"]);
        assert!(!format!("{forms:?}").contains("made-up"), "{forms:?}");
    }
}
