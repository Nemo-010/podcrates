use super::*;
use crate::net::OPEN;

fn find<'a>(c: &'a [Change], name: &str) -> Vec<&'a Change> {
    c.iter()
        .filter(|ch| match ch {
            Change::Remove(n) | Change::Set(n, _) => n == name,
        })
        .collect()
}

/// The last change of `name` wins, as the lab applies them in order.
fn last<'a>(c: &'a [Change], name: &str) -> Option<&'a Change> {
    find(c, name).last().copied()
}

#[test]
fn a_class_with_no_proxy_removes_each_variable_of_a_tool() {
    let host = [("GLOBAL_AGENT_HTTPS_PROXY", "http://host:8080"), ("CLOUDSDK_PROXY_ADDRESS", "host")];
    let c = changes(host, None);
    for v in URL_VARIABLES.iter().chain(SKIP_VARIABLES) {
        assert_eq!(last(&c, v), Some(&Change::Remove(v.to_string())), "{v}");
    }
    for v in CLOUDSDK_VARIABLES {
        assert_eq!(last(&c, v), Some(&Change::Remove(v.to_string())), "{v}");
    }
    assert!(!c.iter().any(|ch| matches!(ch, Change::Set(..))), "{c:?}");
}

#[test]
fn a_class_with_a_proxy_sets_the_url_forms_to_the_stand_in() {
    let rules = Proxy { auth: true, ..OPEN };
    let c = changes([], Some(&rules));
    let url = proxy_url(&rules);
    for v in URL_VARIABLES {
        assert_eq!(last(&c, v), Some(&Change::Set(v.to_string(), url.clone())), "{v}");
    }
    for v in SKIP_VARIABLES {
        assert_eq!(last(&c, v), Some(&Change::Remove(v.to_string())), "{v}");
    }
    assert_eq!(
        last(&c, "CLOUDSDK_PROXY_ADDRESS"),
        Some(&Change::Set("CLOUDSDK_PROXY_ADDRESS".into(), "127.0.0.1".into()))
    );
    assert_eq!(
        last(&c, "CLOUDSDK_PROXY_PORT"),
        Some(&Change::Set("CLOUDSDK_PROXY_PORT".into(), PROXY_PORT.to_string()))
    );
    assert_eq!(
        last(&c, "CLOUDSDK_PROXY_USERNAME"),
        Some(&Change::Set("CLOUDSDK_PROXY_USERNAME".into(), PROXY_USER.into()))
    );
    // A proxy with no credential leaves no user of the host.
    let c = changes([], Some(&OPEN));
    assert_eq!(last(&c, "CLOUDSDK_PROXY_USERNAME"), Some(&Change::Remove("CLOUDSDK_PROXY_USERNAME".into())));
}

#[test]
fn the_options_of_java_lose_the_options_of_a_proxy_alone() {
    let host = [
        ("JAVA_TOOL_OPTIONS", "-Xmx1g -Dhttps.proxyHost=host -Dhttps.proxyPort=8080 -Dfile.encoding=UTF-8"),
        ("JDK_JAVA_OPTIONS", "-Dhttp.proxyHost=host -Dhttp.nonProxyHosts=localhost"),
        ("OTHER", "-Dhttps.proxyHost=host"),
    ];
    let c = changes(host, None);
    assert_eq!(
        last(&c, "JAVA_TOOL_OPTIONS"),
        Some(&Change::Set("JAVA_TOOL_OPTIONS".into(), "-Xmx1g -Dfile.encoding=UTF-8".into()))
    );
    assert_eq!(last(&c, "JDK_JAVA_OPTIONS"), Some(&Change::Remove("JDK_JAVA_OPTIONS".into())));
    assert_eq!(last(&c, "OTHER"), None, "a variable of no tool of the list stays");
    assert_eq!(last(&c, "_JAVA_OPTIONS"), None, "an absent variable gets no change");
}
