use std::{
    collections::VecDeque,
    io::{self, Read, Write},
    net::SocketAddr,
    time::Duration,
};

use dynet_core::{payload_as, NetworkNode};
use md5::{Digest, Md5};
use rand::RngCore;
use ring::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_128_GCM, NONCE_LEN},
    hkdf,
};
use serde::Deserialize;

use super::{
    buffered_read::{self, BufferedRead},
    connect_tcp_socket, ProxiedTcpStream, TcpTarget,
};

const TAG_LEN: usize = 16;
const KEY_LEN_AES_128_GCM: usize = 16;
const MAX_PAYLOAD_LEN: usize = 0x3fff;
const SS_SUBKEY_INFO: &[&[u8]] = &[b"ss-subkey"];

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct ShadowsocksSpec {
    pub(super) tag: String,
    pub(super) server: String,
    pub(super) server_port: u16,
    pub(super) cipher: String,
    pub(super) password: String,
}

pub(crate) struct ShadowsocksTcpStream {
    stream: Box<dyn ShadowsocksTransport>,
    master_key: Vec<u8>,
    key_len: usize,
    opener: Option<AeadCipher>,
    sealer: AeadCipher,
    pending_salt: Vec<u8>,
    pending_header: Vec<u8>,
    encrypted_read: VecDeque<u8>,
    pending_payload_len: Option<usize>,
    plain_read: VecDeque<u8>,
    eof: bool,
}

pub(super) trait ShadowsocksTransport: Read + Write {
    #[allow(dead_code)]
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()>;
}

impl ShadowsocksTransport for std::net::TcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        std::net::TcpStream::set_read_timeout(self, timeout)
    }
}

impl ShadowsocksTransport for ProxiedTcpStream {
    fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.set_read_timeout(timeout)
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ShadowsocksPayload {
    server: String,
    #[serde(default)]
    server_ip: Option<String>,
    #[serde(default)]
    server_port: Option<u16>,
    #[serde(default)]
    port: Option<u16>,
    cipher: String,
    password: String,
}

struct AeadCipher {
    key: LessSafeKey,
    nonce: ShadowsocksNonce,
}

#[derive(Debug, Clone)]
struct ShadowsocksNonce {
    bytes: [u8; NONCE_LEN],
}

struct KeyLen(usize);

impl hkdf::KeyType for KeyLen {
    fn len(&self) -> usize {
        self.0
    }
}

pub(super) fn spec_from_node(node: &NetworkNode) -> Result<ShadowsocksSpec, String> {
    let payload = payload_as::<ShadowsocksPayload>(node)?;
    let server_port = payload.server_port.or(payload.port).ok_or_else(|| {
        format!(
            "Shadowsocks outbound `{}` requires payload.serverPort or payload.port",
            node.tag
        )
    })?;
    let server = payload
        .server_ip
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(payload.server.as_str())
        .to_string();
    Ok(ShadowsocksSpec {
        tag: node.tag.clone(),
        server,
        server_port,
        cipher: payload.cipher,
        password: payload.password,
    })
}

pub(super) fn connect_tcp(
    spec: &ShadowsocksSpec,
    destination: &TcpTarget,
    mark: u32,
) -> Result<ShadowsocksTcpStream, String> {
    let stream = connect_tcp_socket(&spec.server, spec.server_port, mark)?;
    connect_tcp_on_stream(spec, destination, Box::new(stream))
}

pub(super) fn connect_tcp_on_stream(
    spec: &ShadowsocksSpec,
    destination: &TcpTarget,
    stream: Box<dyn ShadowsocksTransport>,
) -> Result<ShadowsocksTcpStream, String> {
    let key_len = key_len(spec)?;
    let master_key = password_key(&spec.password, key_len);
    let mut salt = vec![0_u8; key_len];
    rand::thread_rng().fill_bytes(&mut salt);
    let session_key = session_key(&master_key, &salt, key_len)?;
    let wrapped = ShadowsocksTcpStream {
        stream,
        master_key,
        key_len,
        opener: None,
        sealer: AeadCipher::new(&session_key)?,
        pending_salt: salt,
        pending_header: target_header(destination)?,
        encrypted_read: VecDeque::new(),
        pending_payload_len: None,
        plain_read: VecDeque::new(),
        eof: false,
    };
    Ok(wrapped)
}

pub(super) fn server_target(spec: &ShadowsocksSpec) -> TcpTarget {
    match spec.server.parse::<std::net::IpAddr>() {
        Ok(address) => TcpTarget::Socket(SocketAddr::new(address, spec.server_port)),
        Err(_) => TcpTarget::Domain {
            host: spec.server.clone(),
            port: spec.server_port,
        },
    }
}

impl Read for ShadowsocksTcpStream {
    fn read(&mut self, output: &mut [u8]) -> std::io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.plain_read.is_empty() && !self.eof {
            self.read_next_chunk()?;
        }
        let count = output.len().min(self.plain_read.len());
        for slot in &mut output[..count] {
            *slot = self
                .plain_read
                .pop_front()
                .expect("plain_read has enough bytes");
        }
        Ok(count)
    }
}

impl Write for ShadowsocksTcpStream {
    fn write(&mut self, input: &[u8]) -> std::io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let count = if self.pending_salt.is_empty() && self.pending_header.is_empty() {
            let count = input.len().min(MAX_PAYLOAD_LEN);
            let chunk = self
                .sealed_chunk(&input[..count])
                .map_err(std::io::Error::other)?;
            self.stream.write_all(&chunk)?;
            count
        } else {
            let prefix_len = self.pending_header.len();
            let input_count = input.len().min(MAX_PAYLOAD_LEN - prefix_len);
            let mut payload = std::mem::take(&mut self.pending_header);
            payload.extend_from_slice(&input[..input_count]);
            let mut packet = std::mem::take(&mut self.pending_salt);
            packet.extend_from_slice(&self.sealed_chunk(&payload).map_err(std::io::Error::other)?);
            self.stream.write_all(&packet)?;
            input_count
        };
        Ok(count)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        if !self.pending_salt.is_empty() || !self.pending_header.is_empty() {
            let payload = std::mem::take(&mut self.pending_header);
            let mut packet = std::mem::take(&mut self.pending_salt);
            packet.extend_from_slice(&self.sealed_chunk(&payload).map_err(std::io::Error::other)?);
            self.stream.write_all(&packet)?;
        }
        self.stream.flush()
    }
}

impl ShadowsocksTcpStream {
    #[allow(dead_code)]
    pub(crate) fn set_read_timeout(&self, timeout: Option<Duration>) -> io::Result<()> {
        self.stream.set_read_timeout(timeout)
    }

    fn sealed_chunk(&mut self, payload: &[u8]) -> Result<Vec<u8>, String> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(format!("Shadowsocks chunk too large: {}", payload.len()));
        }
        let payload_len = u16::try_from(payload.len())
            .map_err(|_| format!("Shadowsocks chunk too large: {}", payload.len()))?;
        let encrypted_len = self.sealer.seal(&payload_len.to_be_bytes())?;
        let encrypted_payload = self.sealer.seal(payload)?;
        let mut output = Vec::with_capacity(encrypted_len.len() + encrypted_payload.len());
        output.extend_from_slice(&encrypted_len);
        output.extend_from_slice(&encrypted_payload);
        Ok(output)
    }

    fn read_next_chunk(&mut self) -> io::Result<()> {
        self.ensure_response_opener()?;
        if self.eof {
            return Ok(());
        }
        let payload_len = match self.pending_payload_len {
            Some(payload_len) => payload_len,
            None => match self.read_chunk_len()? {
                Some(payload_len) => payload_len,
                None => return Ok(()),
            },
        };
        if payload_len == 0 {
            self.eof = true;
            self.pending_payload_len = None;
            return Ok(());
        }
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(buffered_read::invalid_data(format!(
                "Shadowsocks chunk length is too large: {payload_len}"
            )));
        }
        let mut encrypted_payload =
            match self.read_buffered(payload_len + TAG_LEN, "Shadowsocks chunk payload")? {
                BufferedRead::Ready(bytes) => bytes,
                BufferedRead::Pending => {
                    return Err(buffered_read::pending(
                        "Shadowsocks chunk payload is not ready",
                    ));
                }
                BufferedRead::Eof => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "failed to read Shadowsocks chunk payload: unexpected EOF",
                    ))
                }
            };
        self.pending_payload_len = None;
        let plaintext = self
            .opener
            .as_mut()
            .expect("response opener initialized")
            .open(&mut encrypted_payload, "payload")
            .map_err(buffered_read::invalid_data)?;
        self.plain_read.extend(plaintext);
        Ok(())
    }

    fn read_chunk_len(&mut self) -> io::Result<Option<usize>> {
        let mut encrypted_len = match self.read_buffered(2 + TAG_LEN, "Shadowsocks chunk length")? {
            BufferedRead::Ready(bytes) => bytes,
            BufferedRead::Pending => {
                return Err(buffered_read::pending(
                    "Shadowsocks chunk length is not ready",
                ));
            }
            BufferedRead::Eof => {
                self.eof = true;
                return Ok(None);
            }
        };
        let length = self
            .opener
            .as_mut()
            .expect("response opener initialized")
            .open(&mut encrypted_len, "length")
            .map_err(buffered_read::invalid_data)?;
        if length.len() != 2 {
            return Err(buffered_read::invalid_data(format!(
                "Shadowsocks chunk length plaintext was {} bytes",
                length.len()
            )));
        }
        let payload_len = usize::from(u16::from_be_bytes([length[0], length[1]]));
        self.pending_payload_len = Some(payload_len);
        Ok(Some(payload_len))
    }

    fn ensure_response_opener(&mut self) -> io::Result<()> {
        if self.opener.is_some() {
            return Ok(());
        }
        let salt = match self.read_buffered(self.key_len, "Shadowsocks response salt")? {
            BufferedRead::Ready(bytes) => bytes,
            BufferedRead::Pending => {
                return Err(buffered_read::pending(
                    "Shadowsocks response salt is not ready",
                ));
            }
            BufferedRead::Eof => {
                self.eof = true;
                return Ok(());
            }
        };
        let session_key = session_key(&self.master_key, &salt, self.key_len)
            .map_err(buffered_read::invalid_data)?;
        self.opener = Some(AeadCipher::new(&session_key).map_err(buffered_read::invalid_data)?);
        Ok(())
    }

    fn read_buffered(&mut self, len: usize, label: &str) -> io::Result<BufferedRead> {
        buffered_read::read_exact(&mut *self.stream, &mut self.encrypted_read, len, label)
    }
}

impl AeadCipher {
    fn new(key: &[u8]) -> Result<Self, String> {
        let key = UnboundKey::new(&AES_128_GCM, key)
            .map_err(|_| "failed to initialize Shadowsocks AEAD key".to_string())?;
        Ok(Self {
            key: LessSafeKey::new(key),
            nonce: ShadowsocksNonce::default(),
        })
    }

    fn seal(&mut self, input: &[u8]) -> Result<Vec<u8>, String> {
        let mut output = input.to_vec();
        self.key
            .seal_in_place_append_tag(self.nonce.next(), Aad::empty(), &mut output)
            .map_err(|_| "failed to seal Shadowsocks AEAD chunk".to_string())?;
        Ok(output)
    }

    fn open<'a>(&mut self, input: &'a mut [u8], label: &str) -> Result<&'a [u8], String> {
        self.key
            .open_in_place(self.nonce.next(), Aad::empty(), input)
            .map(|output| &*output)
            .map_err(|_| format!("failed to open Shadowsocks AEAD {label}"))
    }
}

impl Default for ShadowsocksNonce {
    fn default() -> Self {
        Self {
            bytes: [0_u8; NONCE_LEN],
        }
    }
}

impl ShadowsocksNonce {
    fn next(&mut self) -> Nonce {
        let nonce = Nonce::assume_unique_for_key(self.bytes);
        self.increment();
        nonce
    }

    fn increment(&mut self) {
        for byte in &mut self.bytes {
            let (next, overflow) = byte.overflowing_add(1);
            *byte = next;
            if !overflow {
                break;
            }
        }
    }
}

fn key_len(spec: &ShadowsocksSpec) -> Result<usize, String> {
    match spec.cipher.trim().to_ascii_lowercase().as_str() {
        "aes-128-gcm" => Ok(KEY_LEN_AES_128_GCM),
        other => Err(format!(
            "Shadowsocks outbound `{}` has unsupported cipher `{other}`; only aes-128-gcm is supported",
            spec.tag
        )),
    }
}

fn password_key(password: &str, key_len: usize) -> Vec<u8> {
    let password = password.as_bytes();
    let mut output = Vec::new();
    let mut previous = Vec::new();
    while output.len() < key_len {
        let mut digest = Md5::new();
        if !previous.is_empty() {
            digest.update(&previous);
        }
        digest.update(password);
        previous = digest.finalize().to_vec();
        output.extend_from_slice(&previous);
    }
    output.truncate(key_len);
    output
}

fn session_key(master_key: &[u8], salt: &[u8], key_len: usize) -> Result<Vec<u8>, String> {
    let mut output = vec![0_u8; key_len];
    hkdf::Salt::new(hkdf::HKDF_SHA1_FOR_LEGACY_USE_ONLY, salt)
        .extract(master_key)
        .expand(SS_SUBKEY_INFO, KeyLen(key_len))
        .map_err(|_| "failed to expand Shadowsocks session key".to_string())?
        .fill(&mut output)
        .map_err(|_| "failed to fill Shadowsocks session key".to_string())?;
    Ok(output)
}

fn target_header(target: &TcpTarget) -> Result<Vec<u8>, String> {
    let mut output = Vec::new();
    match target {
        TcpTarget::Socket(address) => match address {
            SocketAddr::V4(address) => {
                output.push(1);
                output.extend_from_slice(&address.ip().octets());
                output.extend_from_slice(&address.port().to_be_bytes());
            }
            SocketAddr::V6(address) => {
                output.push(4);
                output.extend_from_slice(&address.ip().octets());
                output.extend_from_slice(&address.port().to_be_bytes());
            }
        },
        TcpTarget::Domain { host, port } => {
            let host = host.as_bytes();
            let host_len = u8::try_from(host.len())
                .map_err(|_| format!("Shadowsocks target host is too long: {}", host.len()))?;
            output.push(3);
            output.push(host_len);
            output.extend_from_slice(host);
            output.extend_from_slice(&port.to_be_bytes());
        }
    }
    Ok(output)
}

impl From<Box<ShadowsocksTcpStream>> for ProxiedTcpStream {
    fn from(stream: Box<ShadowsocksTcpStream>) -> Self {
        Self::Shadowsocks(stream)
    }
}
