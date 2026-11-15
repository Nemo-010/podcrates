//! The names of the consumer that the road says: on the wire to a server,
//! and in the words of its lines.

/// The names of the consumer. The default words are neutral;
/// [`Names::podssh`] gives podssh's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    /// The name of the program in the client's info (`ClientInfo.AppName`),
    /// by which a server may count its clients or refuse them (derper's
    /// `--disallow-app-names`), and in a line: `podssh`.
    pub app: String,
    /// The `User-Agent` of the WebSocket upgrade: `podssh/VERSION`.
    pub user_agent: String,
    /// The setting that keeps tailcat's four servers alone, as a refusal of
    /// its value and a line name it: `PODSSH_DERP_MAIN`.
    pub main: String,
}

impl Default for Names {
    fn default() -> Names {
        Names {
            app: "pod-derp".into(),
            user_agent: concat!("pod-derp/", env!("CARGO_PKG_VERSION")).into(),
            main: "the setting of the main fleet".into(),
        }
    }
}

impl Names {
    /// podssh's names, with its `User-Agent` (`podssh/VERSION`).
    pub fn podssh(user_agent: impl Into<String>) -> Names {
        Names { app: "podssh".into(), user_agent: user_agent.into(), main: "PODSSH_DERP_MAIN".into() }
    }
}
