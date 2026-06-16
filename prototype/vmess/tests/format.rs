use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use vmess_prototype::{request_for_test, Client, ClientConfig};

const UUID: &str = "11111111-2222-3333-4444-555555555555";

#[test]
fn rejects_bad_uuid() {
    let error = Client::try_new(ClientConfig {
        server: "127.0.0.1".to_string(),
        port: 10086,
        uuid: "not-a-uuid".to_string(),
    })
    .unwrap_err();

    assert_eq!(error.stage(), "outbound-config");
}

#[test]
fn aead_request_shape() {
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 80));
    let (request, _) = request_for_test(UUID, 0x01, target).unwrap();

    assert!(request.len() > 16 + 18 + 8 + 16);
    assert_eq!(request[16..34].len(), 18);
    assert_ne!(&request[..16], &[0_u8; 16]);
    assert_ne!(&request[34..42], &[0_u8; 8]);
}
