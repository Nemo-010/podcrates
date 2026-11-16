use super::*;

#[test]
fn the_items_of_a_proxy_name_no_host_and_no_credential() {
    // The URL is made of parts, so that no scanner of secrets reads a
    // credential in the source.
    let url = ["http://", "made-up-user", ":", "made-up-pass", "@proxy.example:3128"].concat();
    let r = proxy_items("HTTPS_PROXY", &url);
    assert_eq!(r, "set 1; variable HTTPS_PROXY; scheme http; credential 1; port 3128");
    assert!(!r.contains("made-up") && !r.contains("example"), "{r}");
    let r = proxy_items("https_proxy", "HTTPS://[2001:db8::1]:8443/");
    assert_eq!(r, "set 1; variable https_proxy; scheme https; credential 0; port 8443");
    let r = proxy_items("ALL_PROXY", "proxy.example");
    assert_eq!(r, "set 1; variable ALL_PROXY; scheme none; credential 0; port none");
    let r = proxy_items("HTTPS_PROXY", "socks5h://[2001:db8::1]");
    assert_eq!(r, "set 1; variable HTTPS_PROXY; scheme socks5h; credential 0; port none");
}

#[test]
fn the_certificates_of_a_pem_text() {
    let pem = b"-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n\
                -----BEGIN PRIVATE KEY-----\nBBBB\n-----END PRIVATE KEY-----\n\
                -----BEGIN CERTIFICATE-----\nCCCC\n-----END CERTIFICATE-----\n";
    assert_eq!(certificates(pem), 2);
    assert_eq!(certificates(b""), 0);
}

#[test]
fn a_nameserver_line_is_the_first_word() {
    let text =
        "# nameserver 9.9.9.9\nsearch example\nnameserver 192.0.2.53\nnameserver\t2001:db8::53\noptions ndots:1\n";
    assert_eq!(nameservers(text), 2);
    assert_eq!(nameservers("options timeout:2\n"), 0);
    assert_eq!(nameservers(""), 0);
}

/// The table of a host with a default route through a gateway, and of a
/// lab with the loopback alone.
#[test]
fn a_default_route_of_ipv4_is_destination_and_mask_zero_and_up() {
    let head = "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n";
    let host = format!(
        "{head}eth0\t00000000\t010200C0\t0003\t0\t0\t0\t00000000\t0\t0\t0\n\
         eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n"
    );
    assert!(default_v4(&host));
    let subnet = format!("{head}eth0\t000200C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n");
    assert!(!default_v4(&subnet));
    let down = format!("{head}eth0\t00000000\t010200C0\t0002\t0\t0\t0\t00000000\t0\t0\t0\n");
    assert!(!default_v4(&down));
    assert!(!default_v4(head));
    assert!(!default_v4(""));
}

#[test]
fn a_default_route_of_ipv6_is_up_and_no_reject_route() {
    let zero = "00000000000000000000000000000000";
    let via =
        format!("{zero} 00 {zero} 00 fe800000000000000000000000000001 00000400 00000001 00000000 00000003 eth0\n");
    assert!(default_v6(&via));
    // The "unreachable" entry of a namespace with no default route.
    let reject = format!("{zero} 00 {zero} 00 {zero} ffffffff 00000001 00000000 00200200 lo\n");
    assert!(!default_v6(&reject));
    // An unreachable default route that is up (`ip -6 route add unreachable
    // default`): no way out.
    let unreachable = format!("{zero} 00 {zero} 00 {zero} 00000400 00000001 00000000 00200201 lo\n");
    assert!(!default_v6(&unreachable));
    let local =
        format!("00000000000000000000000000000001 80 {zero} 00 {zero} 00000000 00000002 00000000 80200001 lo\n");
    assert!(!default_v6(&local));
    assert!(!default_v6(""));
}
