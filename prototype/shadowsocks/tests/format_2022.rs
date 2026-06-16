use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    time::{SystemTime, UNIX_EPOCH},
};

use aes::{
    cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit},
    Aes128,
};
use aes_gcm::{aead::Aead, Aes128Gcm, Nonce};
use shadowsocks_prototype::{Client, ClientConfig, Method};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

const KEY: [u8; 16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
const PASSWORD: &str = "AQIDBAUGBwgJCgsMDQ4PEA==";
const SALT_SIZE: usize = 16;
const TAG_SIZE: usize = 16;
const NONCE_SIZE: usize = 12;
const CONTEXT: &str = "shadowsocks 2022 session subkey";

#[tokio::test]
async fn tcp_request_header() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 8388));

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut salt = [0_u8; SALT_SIZE];
        stream.read_exact(&mut salt).await.unwrap();
        let mut reader = AeadReader::new(&salt);

        let mut fixed_chunk = [0_u8; 11 + TAG_SIZE];
        stream.read_exact(&mut fixed_chunk).await.unwrap();
        let fixed = reader.decrypt(&fixed_chunk);
        assert_eq!(fixed[0], 0);
        assert_ne!(&fixed[1..9], &[0_u8; 8]);
        assert_eq!(u16::from_be_bytes([fixed[9], fixed[10]]), 25);

        let mut variable_chunk = vec![0_u8; 25 + TAG_SIZE];
        stream.read_exact(&mut variable_chunk).await.unwrap();
        let variable = reader.decrypt(&variable_chunk);
        assert_eq!(&variable[..7], &[1, 1, 2, 3, 4, 0x20, 0xc4]);
        assert_eq!(u16::from_be_bytes([variable[7], variable[8]]), 16);
        assert_ne!(&variable[9..], &[0_u8; 16]);
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
async fn rejects_old_tcp_response() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = listener.local_addr().unwrap();
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(1, 2, 3, 4), 8388));

    let server_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request_salt = [0_u8; SALT_SIZE];
        stream.read_exact(&mut request_salt).await.unwrap();
        read_request_headers(&mut stream, &request_salt).await;

        let response_salt = [0x44; SALT_SIZE];
        let packet = response_packet(response_salt, request_salt, 1, b"");
        stream.write_all(&packet).await.unwrap();
    });

    let downstream = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let downstream_addr = downstream.local_addr().unwrap();
    let downstream_client = TcpStream::connect(downstream_addr).await.unwrap();
    let (downstream_server, _) = downstream.accept().await.unwrap();

    let client = client(server);
    let outcome = client
        .relay_tcp(downstream_server, target)
        .await
        .unwrap_err();

    server_task.await.unwrap();
    drop(downstream_client);
    assert_eq!(outcome.stage(), "outbound-crypto");
    assert!(outcome.to_string().contains("timestamp"));
}

#[test]
fn udp_client_packet() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53));
    let mut session = client.udp_session();

    let packet = session.encode_udp_datagram(target, b"dns-query").unwrap();

    let (header, body) = decrypt_packet(&packet);
    assert_ne!(&header[..8], &[0_u8; 8]);
    assert_eq!(u64::from_be_bytes(header[8..16].try_into().unwrap()), 0);
    assert_eq!(body[0], 0);
    assert_ne!(&body[1..9], &[0_u8; 8]);
    assert_eq!(&body[9..11], &[0, 0]);
    assert_eq!(
        &body[11..],
        &[1, 8, 8, 8, 8, 0, 53, b'd', b'n', b's', b'-', b'q', b'u', b'e', b'r', b'y',]
    );

    let next = session.encode_udp_datagram(target, b"next").unwrap();
    let (next_header, _) = decrypt_packet(&next);
    assert_eq!(
        u64::from_be_bytes(next_header[8..16].try_into().unwrap()),
        1
    );
}

#[test]
fn udp_server_packet() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 53));
    let mut session = client.udp_session();
    let outbound = session.encode_udp_datagram(target, b"query").unwrap();
    let (client_header, _) = decrypt_packet(&outbound);
    let client_session_id: [u8; 8] = client_header[..8].try_into().unwrap();

    let response = encrypt_server_packet(client_session_id, target, b"answer", now(), 0);
    let payload = session.decode_udp_datagram(&response).unwrap();

    assert_eq!(payload, b"answer");
}

#[test]
fn rejects_udp_replay() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 53));
    let mut session = client.udp_session();
    let outbound = session.encode_udp_datagram(target, b"query").unwrap();
    let (client_header, _) = decrypt_packet(&outbound);
    let client_session_id: [u8; 8] = client_header[..8].try_into().unwrap();
    let response = encrypt_server_packet(client_session_id, target, b"answer", now(), 0);

    session.decode_udp_datagram(&response).unwrap();
    let error = session.decode_udp_datagram(&response).unwrap_err();

    assert_eq!(error.stage(), "outbound-crypto");
    assert!(error.to_string().contains("replay"));
}

#[test]
fn rejects_old_udp_packet() {
    let client = client(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 8388)));
    let target = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(8, 8, 4, 4), 53));
    let mut session = client.udp_session();
    let outbound = session.encode_udp_datagram(target, b"query").unwrap();
    let (client_header, _) = decrypt_packet(&outbound);
    let client_session_id: [u8; 8] = client_header[..8].try_into().unwrap();
    let response = encrypt_server_packet(client_session_id, target, b"answer", 1, 0);

    let error = session.decode_udp_datagram(&response).unwrap_err();

    assert_eq!(error.stage(), "outbound-crypto");
    assert!(error.to_string().contains("timestamp"));
}

#[test]
fn rejects_bad_psk() {
    let error = Client::try_new(ClientConfig {
        server: "127.0.0.1".to_string(),
        port: 8388,
        method: Method::Blake3Aes128Gcm2022,
        password: "not-base64".to_string(),
    })
    .unwrap_err();

    assert_eq!(error.stage(), "outbound-config");
    assert!(error.to_string().contains("base64"));
}

#[test]
fn rejects_short_psk() {
    let error = Client::try_new(ClientConfig {
        server: "127.0.0.1".to_string(),
        port: 8388,
        method: Method::Blake3Aes128Gcm2022,
        password: "AQID".to_string(),
    })
    .unwrap_err();

    assert_eq!(error.stage(), "outbound-config");
    assert!(error.to_string().contains("16 bytes"));
}

fn client(server: SocketAddr) -> Client {
    Client::new(ClientConfig {
        server: server.ip().to_string(),
        port: server.port(),
        method: Method::Blake3Aes128Gcm2022,
        password: PASSWORD.to_string(),
    })
}

fn decrypt_packet(packet: &[u8]) -> ([u8; 16], Vec<u8>) {
    let encrypted_header: &[u8; 16] = packet[..16].try_into().unwrap();
    let header = decrypt_header(encrypted_header);
    let body = udp_cipher(&header[..8])
        .decrypt(Nonce::from_slice(&header[4..]), &packet[16..])
        .unwrap();
    (header, body)
}

fn encrypt_server_packet(
    client_session_id: [u8; 8],
    target: SocketAddr,
    payload: &[u8],
    timestamp: u64,
    packet_id: u64,
) -> Vec<u8> {
    let mut header = [0_u8; 16];
    header[..8].copy_from_slice(&[9, 8, 7, 6, 5, 4, 3, 2]);
    header[8..].copy_from_slice(&packet_id.to_be_bytes());

    let mut body = Vec::new();
    body.push(1);
    body.extend_from_slice(&timestamp.to_be_bytes());
    body.extend_from_slice(&client_session_id);
    body.extend_from_slice(&0_u16.to_be_bytes());
    body.extend_from_slice(&socks_addr(target));
    body.extend_from_slice(payload);

    let encrypted_header = encrypt_header(&header);
    let encrypted_body = udp_cipher(&header[..8])
        .encrypt(Nonce::from_slice(&header[4..]), body.as_slice())
        .unwrap();
    [encrypted_header.as_slice(), encrypted_body.as_slice()].concat()
}

fn response_packet(
    response_salt: [u8; SALT_SIZE],
    request_salt: [u8; SALT_SIZE],
    timestamp: u64,
    payload: &[u8],
) -> Vec<u8> {
    let mut writer = AeadWriter::new(&response_salt);
    let mut packet = response_salt.to_vec();
    let mut header = Vec::new();
    header.push(1);
    header.extend_from_slice(&timestamp.to_be_bytes());
    header.extend_from_slice(&request_salt);
    header.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    writer.encrypt(&header, &mut packet);
    writer.encrypt(payload, &mut packet);
    packet
}

async fn read_request_headers(stream: &mut TcpStream, salt: &[u8]) {
    let mut request_reader = AeadReader::new(salt);
    let mut fixed_chunk = [0_u8; 11 + TAG_SIZE];
    stream.read_exact(&mut fixed_chunk).await.unwrap();
    let fixed = request_reader.decrypt(&fixed_chunk);
    let variable_len = u16::from_be_bytes([fixed[9], fixed[10]]) as usize;
    let mut variable_chunk = vec![0_u8; variable_len + TAG_SIZE];
    stream.read_exact(&mut variable_chunk).await.unwrap();
    request_reader.decrypt(&variable_chunk);
}

fn encrypt_header(header: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(&KEY).unwrap();
    let mut block = GenericArray::clone_from_slice(header);
    cipher.encrypt_block(&mut block);
    block.into()
}

fn decrypt_header(header: &[u8; 16]) -> [u8; 16] {
    let cipher = Aes128::new_from_slice(&KEY).unwrap();
    let mut block = GenericArray::clone_from_slice(header);
    cipher.decrypt_block(&mut block);
    block.into()
}

fn udp_cipher(session_id: &[u8]) -> Aes128Gcm {
    Aes128Gcm::new_from_slice(&session_key(session_id)).unwrap()
}

fn session_key(salt: &[u8]) -> [u8; 16] {
    let mut material = Vec::new();
    material.extend_from_slice(&KEY);
    material.extend_from_slice(salt);
    let derived = blake3::derive_key(CONTEXT, &material);
    derived[..16].try_into().unwrap()
}

fn socks_addr(target: SocketAddr) -> Vec<u8> {
    match target {
        SocketAddr::V4(address) => {
            let mut encoded = vec![1];
            encoded.extend_from_slice(&address.ip().octets());
            encoded.extend_from_slice(&address.port().to_be_bytes());
            encoded
        }
        SocketAddr::V6(_) => unreachable!("test only uses IPv4"),
    }
}

struct AeadReader {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_SIZE],
}

impl AeadReader {
    fn new(salt: &[u8]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(&session_key(salt)).unwrap(),
            nonce: [0_u8; NONCE_SIZE],
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

struct AeadWriter {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_SIZE],
}

impl AeadWriter {
    fn new(salt: &[u8]) -> Self {
        Self {
            cipher: Aes128Gcm::new_from_slice(&session_key(salt)).unwrap(),
            nonce: [0_u8; NONCE_SIZE],
        }
    }

    fn encrypt(&mut self, plaintext: &[u8], out: &mut Vec<u8>) {
        let nonce = self.nonce;
        let ciphertext = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .unwrap();
        increment_nonce(&mut self.nonce);
        out.extend_from_slice(&ciphertext);
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for byte in nonce {
        let (next, carry) = byte.overflowing_add(1);
        *byte = next;
        if !carry {
            break;
        }
    }
}
