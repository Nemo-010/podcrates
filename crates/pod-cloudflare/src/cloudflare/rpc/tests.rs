use super::*;

/// A fake edge on the other end of an in-memory stream. It does what the
/// edge does. It bootstraps the client and answers the bootstrap of the
/// client. It answers registerConnection with connection details.
async fn fake_edge(stream: tokio::io::DuplexStream, seen: oneshot::Sender<(u8, String, Vec<String>, bool)>) {
    let (mut read, mut write) = tokio::io::split(stream);
    let send = |b: Builder| b.to_bytes();
    // The edge asks for the bootstrap of the client (question 7).
    let mut b = Builder::new();
    let root = b.init_root(1, 1);
    b.set_u16(root, 0, MSG_BOOTSTRAP);
    let boot = b.init_struct(root, 0, 1, 1);
    b.set_u32(boot, 0, 7);
    write.write_all(&send(b)).await.unwrap();

    let mut answered_ours = false;
    let mut seen = Some(seen);
    let mut unregistered = false;
    while let Some(message) = Message::read(&mut read).await.unwrap() {
        let root = message.root().unwrap();
        match root.get_u16(0) {
            MSG_BOOTSTRAP => {
                let q = root.get_struct(0).unwrap().unwrap().get_u32(0);
                let mut b = Builder::new();
                let r = b.init_root(1, 1);
                b.set_u16(r, 0, MSG_RETURN);
                let ret = b.init_struct(r, 0, 2, 1);
                b.set_u32(ret, 0, q);
                let payload = b.init_struct(ret, 0, 0, 2);
                b.set_capability(payload, 0, 0);
                let table = b.init_struct_list(payload, 1, 1, 1, 1);
                b.set_u16(table[0], 0, CAP_SENDER_HOSTED);
                b.set_u32(table[0], 1, 42);
                write.write_all(&send(b)).await.unwrap();
            }
            MSG_RETURN => {
                // The answer of the client to question 7: one capability.
                let ret = root.get_struct(0).unwrap().unwrap();
                assert_eq!(ret.get_u32(0), 7);
                let payload = ret.get_struct(0).unwrap().unwrap();
                assert_eq!(payload.get_capability(0).unwrap(), Some(0));
                answered_ours = true;
            }
            MSG_CALL => {
                let call = root.get_struct(0).unwrap().unwrap();
                let q = call.get_u32(0);
                assert_eq!(call.get_u64(1), REGISTRATION_SERVER_ID);
                let target = call.get_struct(0).unwrap().unwrap();
                assert_eq!(target.get_u32(0), 42, "the call targets the import");
                if call.get_u16(2) == METHOD_UNREGISTER_CONNECTION {
                    unregistered = true;
                } else {
                    let params = call.get_struct(1).unwrap().unwrap().get_struct(0).unwrap().unwrap();
                    let auth = params.get_struct(0).unwrap().unwrap();
                    let client = params.get_struct(2).unwrap().unwrap().get_struct(0).unwrap().unwrap();
                    if let Some(tx) = seen.take() {
                        let _ = tx.send((
                            params.get_u8(0),
                            auth.get_text(0).unwrap(),
                            client.get_text_list(1).unwrap(),
                            answered_ours,
                        ));
                    }
                }
                let mut b = Builder::new();
                let r = b.init_root(1, 1);
                b.set_u16(r, 0, MSG_RETURN);
                let ret = b.init_struct(r, 0, 2, 1);
                b.set_u32(ret, 0, q);
                let payload = b.init_struct(ret, 0, 0, 2);
                let results = b.init_struct(payload, 0, 0, 1);
                let response = b.init_struct(results, 0, 1, 1);
                b.set_u16(response, 0, 1);
                let details = b.init_struct(response, 0, 1, 2);
                b.set_data(details, 0, Uuid::nil().as_bytes());
                b.set_text(details, 1, "test1");
                write.write_all(&send(b)).await.unwrap();
            }
            MSG_FINISH => {}
            other => panic!("unexpected message {other}"),
        }
    }
    assert!(unregistered, "podnet unregisters at shutdown");
}

#[tokio::test]
async fn registers_against_a_fake_edge() {
    let (ours, theirs) = tokio::io::duplex(1 << 16);
    let (seen_tx, seen_rx) = oneshot::channel();
    let edge = tokio::spawn(fake_edge(theirs, seen_tx));
    let (read, write) = tokio::io::split(ours);
    let auth = TunnelAuth { account_tag: "acct".into(), tunnel_secret: vec![1; 32] };
    let options = ConnectionOptions::default_for_quick_tunnel("podnet/test");
    let (details, session) = register_connection_on(read, write, &auth, Uuid::new_v4(), 2, &options).await.unwrap();
    assert_eq!(details.location, "test1");
    let (index, account, features, answered) = seen_rx.await.unwrap();
    assert_eq!(index, 2);
    assert_eq!(account, "acct");
    assert_eq!(features, ["support_datagram_v2".to_string()]);
    assert!(answered, "podnet answered the bootstrap of the edge first");
    session.shutdown_graceful(Duration::from_secs(2)).await;
    edge.await.unwrap();
}

#[test]
fn finish_stores_the_xor_of_the_default() {
    let (msg, _) = Message::parse(&finish(3, false).to_bytes()).unwrap().unwrap();
    let f = msg.root().unwrap().get_struct(0).unwrap().unwrap();
    assert_eq!(f.get_u32(0), 3);
    assert!(f.get_bool(32), "releaseResultCaps = false is stored as 1");
    let (msg, _) = Message::parse(&finish(3, true).to_bytes()).unwrap().unwrap();
    let f = msg.root().unwrap().get_struct(0).unwrap().unwrap();
    assert!(!f.get_bool(32));
}

#[test]
fn the_edge_gets_an_exception_for_its_calls() {
    let (msg, _) = Message::parse(&exception_return(9, "no").to_bytes()).unwrap().unwrap();
    let ret = msg.root().unwrap().get_struct(0).unwrap().unwrap();
    assert_eq!(ret.get_u32(0), 9);
    assert_eq!(ret.get_u16(3), RETURN_EXCEPTION);
    let e = ret.get_struct(0).unwrap().unwrap();
    assert_eq!(e.get_text(0).unwrap(), "no");
    assert_eq!(e.get_u16(2), EXCEPTION_UNIMPLEMENTED);
}
