use super::*;

#[test]
fn the_open_s_path_is_the_forward_road_s_under_the_road_s_prefix() {
    let to = |host, port, family| open_path(&Target { host, port, family }, false).unwrap();
    assert_eq!(to("github.com", 22, None), "/v1/http/open/github.com/22");
    assert_eq!(to("2001:db8::1", 22, Some(6)), "/v1/http/open/2001:db8::1/22?family=6");
    assert!(open_path(&Target { host: "a/b", port: 22, family: None }, false).is_err());
    assert!(open_path(&Target { host: "h", port: 0, family: None }, false).is_err());
    let layer = Target { host: "github.com", port: 22, family: Some(4) };
    assert_eq!(open_path(&layer, true).unwrap(), "/v1/http/open-layer/github.com/22?family=4");
}

#[tokio::test(start_paused = true)]
async fn the_tries_pause_longer_each_time_and_end_at_their_bound() {
    let mut tries = Retry::start();
    let started = Instant::now();
    tries.again("x", None).await.unwrap();
    tries.again("x", Some(Duration::from_secs(1))).await.unwrap();
    assert_eq!(started.elapsed(), Duration::from_millis(1100));
    tokio::time::sleep(RETRY_FOR).await;
    let failed = tries.again("the last error", None).await.unwrap_err();
    assert!(matches!(&failed, End::Failed(why) if why.contains("the last error")), "{failed:?}");
    tries.reset();
    assert!(tries.again("x", None).await.is_ok());
}

#[tokio::test]
async fn a_batch_takes_what_comes_at_once_and_says_the_end() {
    use tokio::io::AsyncWriteExt;
    let (mut near, mut far) = tokio::io::duplex(1024);
    near.write_all(b"abc").await.unwrap();
    near.write_all(b"def").await.unwrap();
    let mut buf = [0u8; 4];
    assert_eq!(gather(&mut far, &mut buf).await, (4, false));
    drop(near);
    let mut rest = [0u8; 8];
    assert_eq!(gather(&mut far, &mut rest).await, (2, true));
    assert_eq!(&rest[..2], b"ef");
    assert_eq!(gather(&mut far, &mut rest).await, (0, true));
}
