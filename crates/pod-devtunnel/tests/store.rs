//! The store of the user's token (T-378, part 2, step 3): a token of a
//! login kept in a private file, read back with its scheme, its refresh
//! token and its end, and taken by the management API of the stand-in; a
//! file that others can read is refused; no token in a line.

mod common;

use std::time::Duration;

use pod_devtunnel::login::Granted;
use pod_devtunnel::standin::Standin;
use pod_devtunnel::store::{MARGIN, TokenStore};
use pod_devtunnel::{Credential, Locator, Management, Scheme, UserToken};
use zeroize::Zeroizing;

use common::{USER_TOKEN, plan, settings, way};

fn dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("pod-devtunnel-store-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn granted(scheme: Scheme, life: Option<u64>) -> Granted {
    Granted {
        token: UserToken::new(scheme, USER_TOKEN).unwrap(),
        refresh: life.map(|_| Zeroizing::new("made-up-refresh-of-the-tests".to_string())),
        expires_in: life.map(Duration::from_secs),
    }
}

#[tokio::test]
async fn a_kept_token_is_read_back_and_the_management_api_takes_it() {
    pod_testkit::need_loopback!();
    let dir = dir("back");
    let store = TokenStore::at(dir.join("devtunnel").join("token.json"));
    assert!(store.load().unwrap().is_none(), "no file yet");
    store.save(&granted(Scheme::Github, None), 1_000).unwrap();
    let kept = store.load().unwrap().expect("the token");
    assert_eq!((kept.token.scheme(), kept.ends_ms), (Scheme::Github, None));
    assert!(!kept.old(i64::MAX), "a token with no life is never old");
    let shown = format!("{kept:?}");
    assert!(!shown.contains(USER_TOKEN), "{shown}");
    let standin = Standin::start(plan()).await.unwrap();
    let api = Management::new(way().http, &settings(&standin.base()));
    let me: Credential = kept.token.into();
    api.connect_info(&Locator::parse("standin-box").unwrap(), &me).await.expect("the kept token is the user's");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn an_entra_token_keeps_its_refresh_and_its_end() {
    let dir = dir("entra");
    let store = TokenStore::at(dir.join("token.json"));
    std::fs::create_dir_all(&dir).unwrap();
    store.save(&granted(Scheme::Aad, Some(3600)), 1_000).unwrap();
    let kept = store.load().unwrap().unwrap();
    assert_eq!((kept.token.scheme(), kept.ends_ms), (Scheme::Aad, Some(3_601_000)));
    assert_eq!(kept.refresh.as_deref().map(String::as_str), Some("made-up-refresh-of-the-tests"));
    let margin = MARGIN.as_millis() as i64;
    assert!(!kept.old(3_601_000 - margin - 1));
    assert!(kept.old(3_601_000 - margin), "old within the margin");
    assert!(store.forget().unwrap());
    assert!(!store.forget().unwrap(), "no file: no change");
    assert!(store.load().unwrap().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(unix)]
#[test]
fn the_file_is_private_and_one_that_others_can_read_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let dir = dir("modes");
    let path = dir.join("token.json");
    let store = TokenStore::at(&path);
    store.save(&granted(Scheme::Github, None), 0).unwrap();
    assert_eq!(std::fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let refused = store.load().unwrap_err();
    let words = refused.chain();
    assert!(words.contains("token store") && !words.contains(USER_TOKEN), "{words}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_file_of_another_shape_is_refused_with_no_byte_of_it_in_the_words() {
    let dir = dir("shape");
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("token.json");
    pod_core::files::replace_private(&path, b"made-up-not-a-store", 0o600, false).unwrap();
    let words = TokenStore::at(&path).load().unwrap_err().chain();
    assert!(words.contains("not a store") && !words.contains("made-up-not-a-store"), "{words}");
    let _ = std::fs::remove_dir_all(&dir);
}
