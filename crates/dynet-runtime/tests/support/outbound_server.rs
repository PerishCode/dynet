use std::{
    io::Read,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream},
    sync::{
        mpsc::{self, Receiver},
        Arc,
    },
    thread::{self, JoinHandle},
    time::Duration,
};

use md5::{Digest, Md5};
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN},
    hkdf,
};
use rustls::{
    pki_types::{CertificateDer, PrivateKeyDer},
    ServerConfig, ServerConnection, StreamOwned,
};
use sha2::Sha224;

const TAG_LEN: usize = 16;
const KEY_LEN: usize = 16;
const SS_SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];
const TROJAN_CERT_DER: &str = concat!(
    "3082017e30820123a00302010202140b614a1682f5a99746bd96e83f7f22100d98ed55300a06082a8648",
    "ce3d04030230143112301006035504030c096c6f63616c686f7374301e170d3236303532323130343535",
    "325a170d3336303531393130343535325a30143112301006035504030c096c6f63616c686f7374305930",
    "1306072a8648ce3d020106082a8648ce3d030107034200043f3aa58c97fe3bb798ec65c6c5e9b8ea",
    "4996914d8b2e43d0d03c1635c0da467171803e6fea23a594f5578fefde7d18c9c1086a8822110",
    "224284efaf62df81703a3533051301d0603551d0e04160414a5c38eb6096f271a173f93b7abff4d",
    "baa7cb1a09301f0603551d23041830168014a5c38eb6096f271a173f93b7abff4dbaa7cb1a0930",
    "0f0603551d130101ff040530030101ff300a06082a8648ce3d0403020349003046022100a3ecc4da",
    "9044a17638bef99d824173aacc07bab4d08fa702376dac2948d37bb6022100cbebf808abf910cf",
    "d3e073cd8be80a2f2d5e2485cc3675077ff9d6dc906d3951",
);
const TROJAN_KEY_DER: &str = concat!(
    "308187020100301306072a8648ce3d020106082a8648ce3d030107046d306b02010104208ce97ea6",
    "d4c42904c3296026525614e3bf3ac8d3420758d72684b7b99965a8cda144034200043f3aa58c",
    "97fe3bb798ec65c6c5e9b8ea4996914d8b2e43d0d03c1635c0da467171803e6fea23a594f",
    "5578fefde7d18c9c1086a8822110224284efaf62df81703",
);

pub(crate) struct SsServer {
    address: SocketAddr,
    receiver: Receiver<Result<ObservedRequest, String>>,
    handle: JoinHandle<()>,
}

impl SsServer {
    pub(crate) fn spawn(password: &str) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("SS server binds localhost");
        let address = listener.local_addr().expect("SS server has local address");
        let password = password.to_string();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_one_ss(listener, &password);
            let _ = sender.send(result);
        });
        Self {
            address,
            receiver,
            handle,
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn request(self) -> Result<ObservedRequest, String> {
        let result = self
            .receiver
            .recv_timeout(Duration::from_secs(3))
            .map_err(|error| format!("timed out waiting for SS server: {error}"))?;
        self.handle
            .join()
            .map_err(|_| "SS server panicked".to_string())?;
        result
    }
}

pub(crate) struct TrojanServer {
    address: SocketAddr,
    receiver: Receiver<Result<ObservedRequest, String>>,
    handle: JoinHandle<()>,
}

impl TrojanServer {
    pub(crate) fn spawn(password: &str) -> Self {
        let listener =
            TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).expect("Trojan server binds localhost");
        let address = listener
            .local_addr()
            .expect("Trojan server has local address");
        let password = password.to_string();
        let (sender, receiver) = mpsc::channel();
        let handle = thread::spawn(move || {
            let result = serve_one_trojan(listener, &password);
            let _ = sender.send(result);
        });
        Self {
            address,
            receiver,
            handle,
        }
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn request(self) -> Result<ObservedRequest, String> {
        let result = self
            .receiver
            .recv_timeout(Duration::from_secs(3))
            .map_err(|error| format!("timed out waiting for Trojan server: {error}"))?;
        self.handle
            .join()
            .map_err(|_| "Trojan server panicked".to_string())?;
        result
    }
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) struct ObservedRequest {
    pub(crate) target: Target,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Eq, PartialEq)]
pub(crate) enum Target {
    Socket(SocketAddr),
    Domain { host: String, port: u16 },
}

impl Target {
    pub(crate) fn domain(host: &str, port: u16) -> Self {
        Self::Domain {
            host: host.to_string(),
            port,
        }
    }
}

fn serve_one_ss(listener: TcpListener, password: &str) -> Result<ObservedRequest, String> {
    let (mut stream, _) = listener
        .accept()
        .map_err(|error| format!("failed to accept SS client: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set SS read timeout: {error}"))?;
    read_request(&mut stream, password)
}

fn serve_one_trojan(listener: TcpListener, password: &str) -> Result<ObservedRequest, String> {
    let (stream, _) = listener
        .accept()
        .map_err(|error| format!("failed to accept Trojan client: {error}"))?;
    stream
        .set_read_timeout(Some(Duration::from_secs(3)))
        .map_err(|error| format!("failed to set Trojan read timeout: {error}"))?;
    let config = Arc::new(test_tls_config()?);
    let connection = ServerConnection::new(config)
        .map_err(|error| format!("failed to create Trojan test TLS server: {error}"))?;
    let mut tls = StreamOwned::new(connection, stream);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|error| format!("failed Trojan test TLS handshake: {error}"))?;
    }
    read_trojan_request(&mut tls, password)
}

fn read_request(stream: &mut TcpStream, password: &str) -> Result<ObservedRequest, String> {
    let master_key = password_key(password);
    let salt = read_exact(stream, KEY_LEN, "request salt")?;
    let session_key = session_key(&master_key, &salt)?;
    let mut opener = Cipher::new(&session_key)?;
    let payload = read_chunk(stream, &mut opener)?;
    let (target, offset) = parse_target(&payload)?;
    Ok(ObservedRequest {
        target,
        payload: payload[offset..].to_vec(),
    })
}

fn read_trojan_request(stream: &mut impl Read, password: &str) -> Result<ObservedRequest, String> {
    let prefix = read_stream_exact(stream, 59, "Trojan request prefix")?;
    let expected_hash = hex_sha224(password);
    if &prefix[..56] != expected_hash.as_bytes() {
        return Err("Trojan password hash mismatch".to_string());
    }
    if &prefix[56..58] != b"\r\n" {
        return Err("Trojan password terminator is invalid".to_string());
    }
    if prefix[58] != 1 {
        return Err(format!("unsupported Trojan command {}", prefix[58]));
    }
    let address_type = read_stream_exact(stream, 1, "Trojan target address type")?[0];
    let mut target_payload = vec![address_type];
    match address_type {
        1 => target_payload.extend(read_stream_exact(stream, 6, "Trojan IPv4 target")?),
        3 => {
            let length = read_stream_exact(stream, 1, "Trojan domain length")?[0];
            target_payload.push(length);
            target_payload.extend(read_stream_exact(
                stream,
                usize::from(length) + 2,
                "Trojan domain target",
            )?);
        }
        4 => target_payload.extend(read_stream_exact(stream, 18, "Trojan IPv6 target")?),
        other => return Err(format!("unsupported Trojan address type {other}")),
    }
    let terminator = read_stream_exact(stream, 2, "Trojan request terminator")?;
    if terminator != b"\r\n" {
        return Err("Trojan target terminator is invalid".to_string());
    }
    let (target, offset) = parse_target(&target_payload)?;
    Ok(ObservedRequest {
        target,
        payload: target_payload[offset..].to_vec(),
    })
}

fn read_chunk(stream: &mut TcpStream, opener: &mut Cipher) -> Result<Vec<u8>, String> {
    let mut encrypted_len = read_exact(stream, 2 + TAG_LEN, "request chunk length")?;
    let length = opener.open(&mut encrypted_len)?;
    if length.len() != 2 {
        return Err(format!("SS length plaintext was {} bytes", length.len()));
    }
    let payload_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let mut encrypted_payload = read_exact(stream, payload_len + TAG_LEN, "request payload")?;
    Ok(opener.open(&mut encrypted_payload)?.to_vec())
}

fn read_stream_exact(stream: &mut impl Read, len: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut output = vec![0; len];
    stream
        .read_exact(&mut output)
        .map_err(|error| format!("failed to read {label}: {error}"))?;
    Ok(output)
}

fn read_exact(stream: &mut TcpStream, len: usize, label: &str) -> Result<Vec<u8>, String> {
    let mut output = vec![0; len];
    stream
        .read_exact(&mut output)
        .map_err(|error| format!("failed to read SS {label}: {error}"))?;
    Ok(output)
}

fn parse_target(payload: &[u8]) -> Result<(Target, usize), String> {
    let Some(address_type) = payload.first().copied() else {
        return Err("SS request payload is empty".to_string());
    };
    match address_type {
        1 => parse_ipv4(payload),
        3 => parse_domain(payload),
        4 => parse_ipv6(payload),
        other => Err(format!("unsupported SS address type {other}")),
    }
}

fn parse_ipv4(payload: &[u8]) -> Result<(Target, usize), String> {
    if payload.len() < 7 {
        return Err("SS IPv4 target header is truncated".to_string());
    }
    let address = Ipv4Addr::new(payload[1], payload[2], payload[3], payload[4]);
    let port = u16::from_be_bytes([payload[5], payload[6]]);
    Ok((
        Target::Socket(SocketAddr::new(IpAddr::V4(address), port)),
        7,
    ))
}

fn parse_domain(payload: &[u8]) -> Result<(Target, usize), String> {
    let Some(host_len) = payload.get(1).copied().map(usize::from) else {
        return Err("SS domain length is missing".to_string());
    };
    let end = 2 + host_len;
    if payload.len() < end + 2 {
        return Err("SS domain header is truncated".to_string());
    }
    let host = std::str::from_utf8(&payload[2..end])
        .map_err(|error| format!("SS domain target is not UTF-8: {error}"))?
        .to_string();
    let port = u16::from_be_bytes([payload[end], payload[end + 1]]);
    Ok((Target::Domain { host, port }, end + 2))
}

fn parse_ipv6(payload: &[u8]) -> Result<(Target, usize), String> {
    if payload.len() < 19 {
        return Err("SS IPv6 target header is truncated".to_string());
    }
    let mut octets = [0_u8; 16];
    octets.copy_from_slice(&payload[1..17]);
    let port = u16::from_be_bytes([payload[17], payload[18]]);
    Ok((
        Target::Socket(SocketAddr::new(IpAddr::V6(Ipv6Addr::from(octets)), port)),
        19,
    ))
}

fn password_key(password: &str) -> Vec<u8> {
    let password = password.as_bytes();
    let mut output = Vec::new();
    let mut previous = Vec::new();
    while output.len() < KEY_LEN {
        let mut digest = Md5::new();
        if !previous.is_empty() {
            digest.update(&previous);
        }
        digest.update(password);
        previous = digest.finalize().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(KEY_LEN);
    output
}

fn hex_sha224(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn test_tls_config() -> Result<ServerConfig, String> {
    let cert = CertificateDer::from(hex_bytes(TROJAN_CERT_DER)?);
    let key = PrivateKeyDer::try_from(hex_bytes(TROJAN_KEY_DER)?)
        .map_err(|error| format!("failed to parse Trojan test key: {error}"))?;
    ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .map_err(|error| format!("failed to build Trojan test TLS config: {error}"))
}

fn hex_bytes(value: &str) -> Result<Vec<u8>, String> {
    if !value.len().is_multiple_of(2) {
        return Err("hex string has odd length".to_string());
    }
    let mut bytes = Vec::with_capacity(value.len() / 2);
    for index in (0..value.len()).step_by(2) {
        let byte = u8::from_str_radix(&value[index..index + 2], 16)
            .map_err(|error| format!("invalid hex fixture byte: {error}"))?;
        bytes.push(byte);
    }
    Ok(bytes)
}

fn session_key(master_key: &[u8], salt: &[u8]) -> Result<Vec<u8>, String> {
    let mut output = vec![0_u8; KEY_LEN];
    hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
        .extract(master_key)
        .expand(SS_SUBKEY_INFO, KeyLen(KEY_LEN))
        .map_err(|_| "failed to expand SS session key".to_string())?
        .fill(&mut output)
        .map_err(|_| "failed to fill SS session key".to_string())?;
    Ok(output)
}

struct KeyLen(usize);

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

struct Cipher {
    key: LessSafeKey,
    nonce: [u8; NONCE_LEN],
}

impl Cipher {
    fn new(key: &[u8]) -> Result<Self, String> {
        let key = UnboundKey::new(&AES_128_GCM, key)
            .map_err(|_| "failed to initialize SS AEAD key".to_string())?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: [0; NONCE_LEN],
        })
    }

    fn open<'a>(&mut self, input: &'a mut [u8]) -> Result<&'a [u8], String> {
        let nonce = self.next_nonce();
        self.key
            .open_in_place(nonce, Aad::empty(), input)
            .map(|output| &*output)
            .map_err(|_| "failed to open SS AEAD chunk".to_string())
    }

    fn next_nonce(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.nonce);
        for byte in &mut self.nonce {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
        nonce
    }
}
