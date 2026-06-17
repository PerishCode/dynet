use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use sha1::Sha1;
use shadowsocks_prototype::{Client, ClientConfig, Method};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

const AES_256_GCM_KEY_SIZE: usize = 32;
const AES_256_GCM_SALT_SIZE: usize = 32;
const AEAD_NONCE_SIZE: usize = 12;
const AEAD_TAG_SIZE: usize = 16;
const SUBKEY_INFO: &[u8] = b"ss-subkey";
const PASSWORD: &str = "test-password";

#[tokio::test]
async fn tcp_header_layout() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 8388));

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut salt = [0_u8; AES_256_GCM_SALT_SIZE];
        stream.read_exact(&mut salt).await.unwrap();

        let mut encrypted_length = [0_u8; 2 + AEAD_TAG_SIZE];
        stream.read_exact(&mut encrypted_length).await.unwrap();
        let mut reader = AeadReader::new(&salt);
        let length = reader.decrypt(&encrypted_length);
        assert_eq!(length, 7_u16.to_be_bytes());

        let mut encrypted_payload = vec![0_u8; 7 + AEAD_TAG_SIZE];
        stream.read_exact(&mut encrypted_payload).await.unwrap();
        let payload = reader.decrypt(&encrypted_payload);
        assert_eq!(payload, vec![1, 1, 2, 3, 4, 0x20, 0xc4]);
    });

    let downstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream.local_addr().unwrap();
    let downstream_client = TcpStream::connect(downstream_addr).await.unwrap();
    let (downstream_server, _) = downstream.accept().await.unwrap();

    let client = client(server);
    let relay_task = tokio::spawn(async move {
        let _ = client.relay_tcp(downstream_server, target).await;
    });

    server_task.await.unwrap();
    drop(downstream_client);
    relay_task.abort();
}

#[tokio::test]
async fn tcp_header_preconnected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 8388));

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut salt = [0_u8; AES_256_GCM_SALT_SIZE];
        stream.read_exact(&mut salt).await.unwrap();

        let mut encrypted_length = [0_u8; 2 + AEAD_TAG_SIZE];
        stream.read_exact(&mut encrypted_length).await.unwrap();
        let mut reader = AeadReader::new(&salt);
        let length = reader.decrypt(&encrypted_length);
        assert_eq!(length, 7_u16.to_be_bytes());

        let mut encrypted_payload = vec![0_u8; 7 + AEAD_TAG_SIZE];
        stream.read_exact(&mut encrypted_payload).await.unwrap();
        let payload = reader.decrypt(&encrypted_payload);
        assert_eq!(payload, vec![1, 1, 2, 3, 4, 0x20, 0xc4]);
    });

    let downstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream.local_addr().unwrap();
    let downstream_client = TcpStream::connect(downstream_addr).await.unwrap();
    let (downstream_server, _) = downstream.accept().await.unwrap();
    let upstream = TcpStream::connect(server).await.unwrap();

    let client = client(server);
    let relay_task = tokio::spawn(async move {
        let _ = client
            .relay_tcp_with_stream(downstream_server, upstream, target)
            .await;
    });

    server_task.await.unwrap();
    drop(downstream_client);
    relay_task.abort();
}

#[test]
fn udp_ipv4_layout() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));

    let packet = client.encode_udp_datagram(target, b"dns-query").unwrap();

    assert_eq!(packet.len(), AES_256_GCM_SALT_SIZE + 7 + 9 + AEAD_TAG_SIZE);
    let plaintext = decrypt_udp(&packet);
    assert_eq!(
        plaintext,
        vec![1, 8, 8, 8, 8, 0, 53, b'd', b'n', b's', b'-', b'q', b'u', b'e', b'r', b'y',]
    );
}

#[test]
fn udp_ipv6_layout() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let target = SocketAddr::V6(SocketAddrV6::new(
        Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111),
        443,
        0,
        0,
    ));

    let packet = client.encode_udp_datagram(target, b"body").unwrap();

    assert_eq!(packet.len(), AES_256_GCM_SALT_SIZE + 19 + 4 + AEAD_TAG_SIZE);
    let mut expected = vec![4];
    expected.extend_from_slice(&[
        0x26, 0x06, 0x47, 0x00, 0x47, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11,
        0x11,
    ]);
    expected.extend_from_slice(&[0x01, 0xbb, b'b', b'o', b'd', b'y']);
    assert_eq!(decrypt_udp(&packet), expected);
}

#[test]
fn udp_strips_target() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let target = SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::LOCALHOST, 5353, 0, 0));

    let packet = client
        .encode_udp_datagram(target, b"response-body")
        .unwrap();
    let payload = client.decode_udp_datagram(&packet).unwrap();

    assert_eq!(payload, b"response-body");
}

#[test]
fn udp_rejects_truncated() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let packet = encrypt_udp(&[1, 127, 0]);

    let error = client.decode_udp_datagram(&packet).unwrap_err();

    assert_eq!(error.stage(), "outbound-crypto");
    assert!(error.to_string().contains("truncated SOCKS address"));
}

#[test]
fn udp_rejects_short() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let packet = vec![0_u8; AES_256_GCM_SALT_SIZE + AEAD_TAG_SIZE - 1];

    let error = client.decode_udp_datagram(&packet).unwrap_err();

    assert_eq!(error.stage(), "outbound-crypto");
    assert!(error.to_string().contains("too short"));
}

fn client(server: SocketAddr) -> Client {
    Client::new(ClientConfig {
        server: server.ip().to_string(),
        port: server.port(),
        method: Method::Aes256Gcm,
        password: PASSWORD.to_string(),
    })
}

fn encrypt_udp(plaintext: &[u8]) -> Vec<u8> {
    let salt = [0x33; AES_256_GCM_SALT_SIZE];
    let cipher = udp_cipher(&salt);
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&[0_u8; AEAD_NONCE_SIZE]), plaintext)
        .unwrap();
    [salt.as_slice(), encrypted.as_slice()].concat()
}

fn decrypt_udp(packet: &[u8]) -> Vec<u8> {
    let (salt, encrypted) = packet.split_at(AES_256_GCM_SALT_SIZE);
    let cipher = udp_cipher(salt);
    cipher
        .decrypt(Nonce::from_slice(&[0_u8; AEAD_NONCE_SIZE]), encrypted)
        .unwrap()
}

fn udp_cipher(salt: &[u8]) -> Aes256Gcm {
    Aes256Gcm::new_from_slice(&derive_subkey(salt)).unwrap()
}

fn derive_subkey(salt: &[u8]) -> Vec<u8> {
    let mut subkey = vec![0_u8; AES_256_GCM_KEY_SIZE];
    Hkdf::<Sha1>::new(Some(salt), &evp_key())
        .expand(SUBKEY_INFO, &mut subkey)
        .unwrap();
    subkey
}

fn evp_key() -> Vec<u8> {
    let mut key = Vec::with_capacity(AES_256_GCM_KEY_SIZE);
    let mut previous = Vec::<u8>::new();
    while key.len() < AES_256_GCM_KEY_SIZE {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(PASSWORD.as_bytes());
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(AES_256_GCM_KEY_SIZE);
    key
}

struct AeadReader {
    cipher: Aes256Gcm,
    nonce: [u8; AEAD_NONCE_SIZE],
}

impl AeadReader {
    fn new(salt: &[u8]) -> Self {
        Self {
            cipher: Aes256Gcm::new_from_slice(&derive_subkey(salt)).unwrap(),
            nonce: [0_u8; AEAD_NONCE_SIZE],
        }
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce;
        let plaintext = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .unwrap();
        increment_nonce(&mut self.nonce);
        plaintext
    }
}

fn increment_nonce(nonce: &mut [u8; AEAD_NONCE_SIZE]) {
    for byte in nonce {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}
