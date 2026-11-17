//! `tokens.json`: the forward tokens that podssh's relay role mints and takes
//! (`serve::tokens` of podssh). podcrates holds no relay role yet (T-036), so
//! no code here mints or checks such a token: `kinds.rs` skips the kinds
//! `mint` and `check` with this reason, and counts them. T-856 runs them
//! when the role comes. A file holds a token's parts alone, so that no whole
//! token stands in the repository for a scan of secrets to read as live.

/// Why the vectors of `tokens.json` do not run here.
pub const WHY: &str = "the relay role mints and checks these tokens; podcrates has no relay role yet (T-036, T-856)";
