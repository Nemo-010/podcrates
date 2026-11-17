//! The writes of the management API against the stand-in (T-378, part 2;
//! GitHub #94): a new tunnel with an id of the vendor's form, its port, the
//! list of the user's tunnels, the delete; the requests that each sends;
//! and the refusals of a tunnel access token and of a refused user token.

mod common;

use pod_core::Class;
use pod_core::entropy::OsEntropy;
use pod_devtunnel::standin::Standin;
use pod_devtunnel::{Credential, Locator, Management, Step, new_id, step_of};

use common::{access, plan, settings, user, way};

fn management(base: &str) -> Management {
    Management::new(way().http, &settings(base))
}

#[tokio::test]
async fn a_tunnel_is_made_listed_given_a_port_and_deleted() {
    pod_testkit::need_loopback!();
    let standin = Standin::start(plan()).await.unwrap();
    let api = management(&standin.base());
    let me: Credential = user().into();
    let id = new_id(&mut OsEntropy).unwrap();
    let made = api.create(&me, &id, Some("my-box"), Some("usw2")).await.unwrap();
    assert_eq!((made.tunnel_id.as_str(), made.cluster_id.as_str()), (id.as_str(), "usw2"));
    assert_eq!(made.name.as_deref(), Some("my-box"));
    let locator = made.locator().unwrap();
    let port = api.add_port(&me, &locator, 8080).await.unwrap();
    assert_eq!(port.port_number, 8080);
    let list = api.list(&me).await.unwrap();
    let ids: Vec<&str> = list.iter().map(|t| t.tunnel_id.as_str()).collect();
    assert_eq!(ids, ["bcd123", id.as_str()], "the plan's tunnel, then the new one");
    assert_eq!(list[1].ports.iter().map(|p| p.port_number).collect::<Vec<_>>(), [8080]);
    api.delete(&me, &locator).await.unwrap();
    assert_eq!(api.list(&me).await.unwrap().len(), 1);
    let gone = api.delete(&me, &locator).await.unwrap_err();
    assert_eq!(gone.class, Class::NotFound, "{}", gone.chain());
    assert_eq!(
        standin.seen().writes,
        [
            format!("PUT /tunnels/{id}"),
            format!("PUT /tunnels/{id}/ports/8080"),
            "GET /tunnels".to_string(),
            format!("DELETE /tunnels/{id}"),
            "GET /tunnels".to_string(),
            format!("DELETE /tunnels/{id}"),
        ]
    );
}

/// A tunnel with no cluster goes to the global host; the list asks for
/// each cluster (`global=true`) with the version.
#[tokio::test]
async fn a_tunnel_with_no_cluster_and_the_query_of_the_list() {
    pod_testkit::need_loopback!();
    let standin = Standin::start(plan()).await.unwrap();
    let api = management(&standin.base());
    let me: Credential = user().into();
    let made = api.create(&me, "fun-pond-bbbbbbb", None, None).await.unwrap();
    assert_eq!(made.cluster_id, "usw2", "the service gives the cluster");
    assert_eq!(made.name, None);
    let list = api.list(&me).await.unwrap();
    assert_eq!(list.len(), 2);
    let again = api.create(&me, "fun-pond-bbbbbbb", None, None).await.unwrap_err();
    assert!(again.chain().contains("answered HTTP 409: Conflict: a tunnel has this id"), "{}", again.chain());
    for bad in ["Not A Label", "a/b"] {
        let refused = api.create(&me, bad, None, None).await.unwrap_err();
        assert_eq!(refused.class, Class::Usage, "{bad}");
    }
}

/// A tunnel access token manages no tunnel, and a refused user token is
/// refused: each a failure of the management step that names the form of
/// the credential, never a token.
#[tokio::test]
async fn an_access_token_and_a_refused_user_token_are_refused() {
    pod_testkit::need_loopback!();
    let standin = Standin::start(plan()).await.unwrap();
    let api = management(&standin.base());
    let by_access: Credential = access().into();
    let refused = api.list(&by_access).await.unwrap_err();
    assert_eq!(refused.class, Class::Refused);
    assert_eq!(step_of(&refused), Some(Step::Management));
    assert!(refused.chain().contains("with a tunnel access token answered HTTP 403"), "{}", refused.chain());
    standin.refuse_user();
    let refused = api.create(&user().into(), "fun-pond-bbbbbbb", None, None).await.unwrap_err();
    assert_eq!(refused.class, Class::Refused);
    assert!(!refused.chain().contains(common::USER_TOKEN), "no token in a failure");
    let missing = api.delete(&user().into(), &Locator::parse("nope.usw2").unwrap()).await.unwrap_err();
    assert_eq!(missing.class, Class::Refused, "{}", missing.chain());
}
