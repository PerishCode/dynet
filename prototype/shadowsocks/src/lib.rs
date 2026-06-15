use std::{fmt, io::ErrorKind, net::SocketAddr};

use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use md5::{Digest, Md5};
use rand::{rngs::OsRng, RngCore};
use sha1::Sha1;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const AES_256_GCM_KEY_SIZE: usize = 32;
const AES_256_GCM_SALT_SIZE: usize = 32;
const AEAD_NONCE_SIZE: usize = 12;
const AEAD_TAG_SIZE: usize = 16;
const TCP_CHUNK_LIMIT: usize = 0x3fff;
const SUBKEY_INFO: &[u8] = b"ss-subkey";

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Method {
    Aes256Gcm,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    pub method: Method,
    pub password: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Client {
    server: String,
    port: u16,
    method: Method,
    key: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpRelayOutcome {
    pub upstream: SocketAddr,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Error {
    stage: &'static str,
    message: String,
}

impl Error {
    pub fn stage(&self) -> &'static str {
        self.stage
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl Client {
    pub fn new(config: ClientConfig) -> Self {
        let key = match config.method {
            Method::Aes256Gcm => evp_bytes_to_key(config.password.as_bytes()),
        };
        Self {
            server: config.server,
            port: config.port,
            method: config.method,
            key,
        }
    }

    pub fn server_endpoint(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    pub async fn relay_tcp(
        &self,
        downstream: TcpStream,
        target: SocketAddr,
    ) -> Result<TcpRelayOutcome, Error> {
        let upstream = TcpStream::connect((self.server.as_str(), self.port))
            .await
            .map_err(|error| Error {
                stage: "outbound-connect",
                message: format!(
                    "failed connecting Shadowsocks server {}: {error}",
                    self.server_endpoint()
                ),
            })?;
        let upstream_addr = upstream.peer_addr().map_err(|error| Error {
            stage: "outbound-connect",
            message: format!("failed reading Shadowsocks server address: {error}"),
        })?;
        relay_tcp_stream(
            self,
            upstream_addr,
            downstream,
            upstream,
            &socks_address(target),
        )
        .await
    }

    pub fn encode_udp_datagram(
        &self,
        target: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let target_header = socks_address(target);
        let mut plaintext = Vec::with_capacity(target_header.len() + payload.len());
        plaintext.extend_from_slice(&target_header);
        plaintext.extend_from_slice(payload);
        encrypt_udp_packet(self.method, &self.key, &plaintext)
    }

    pub fn decode_udp_datagram(&self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let plaintext = decrypt_udp_packet(self.method, &self.key, packet)?;
        let payload_offset = socks_payload_offset(&plaintext)?;
        Ok(plaintext[payload_offset..].to_vec())
    }
}

async fn relay_tcp_stream(
    client: &Client,
    upstream_addr: SocketAddr,
    downstream: TcpStream,
    upstream: TcpStream,
    target_header: &[u8],
) -> Result<TcpRelayOutcome, Error> {
    let (mut downstream_rx, mut downstream_tx) = downstream.into_split();
    let (mut upstream_rx, mut upstream_tx) = upstream.into_split();
    let (mut writer, salt) = AeadStream::new_with_random_salt(client.method, &client.key)?;
    let mut initial = salt.to_vec();
    writer.encrypt_chunk(target_header, &mut initial)?;
    upstream_tx
        .write_all(&initial)
        .await
        .map_err(|error| Error {
            stage: "outbound-write",
            message: format!("failed writing Shadowsocks TCP header to {upstream_addr}: {error}"),
        })?;

    let client_to_upstream = async {
        let mut bytes = 0_u64;
        let mut buffer = vec![0_u8; TCP_CHUNK_LIMIT];
        loop {
            let size = downstream_rx
                .read(&mut buffer)
                .await
                .map_err(|error| Error {
                    stage: "inbound-read",
                    message: format!("failed reading TCP downstream: {error}"),
                })?;
            if size == 0 {
                upstream_tx.shutdown().await.map_err(|error| Error {
                    stage: "outbound-write",
                    message: format!("failed shutting down Shadowsocks TCP writer: {error}"),
                })?;
                return Ok(bytes);
            }
            bytes += size as u64;
            let mut packet = Vec::with_capacity(size + AEAD_TAG_SIZE * 2 + 2);
            writer.encrypt_chunk(&buffer[..size], &mut packet)?;
            upstream_tx
                .write_all(&packet)
                .await
                .map_err(|error| Error {
                    stage: "outbound-write",
                    message: format!("failed writing Shadowsocks TCP chunk: {error}"),
                })?;
        }
    };

    let upstream_to_client = async {
        let mut salt = vec![0_u8; salt_size(client.method)];
        upstream_rx
            .read_exact(&mut salt)
            .await
            .map_err(|error| Error {
                stage: "outbound-read",
                message: format!("failed reading Shadowsocks TCP response salt: {error}"),
            })?;
        let mut reader = AeadStream::from_salt(client.method, &client.key, &salt)?;
        let mut bytes = 0_u64;
        loop {
            let Some(payload) = reader.decrypt_chunk(&mut upstream_rx).await? else {
                return Ok(bytes);
            };
            downstream_tx
                .write_all(&payload)
                .await
                .map_err(|error| Error {
                    stage: "inbound-write",
                    message: format!("failed writing TCP downstream: {error}"),
                })?;
            bytes += payload.len() as u64;
        }
    };

    let (client_to_upstream_bytes, upstream_to_client_bytes) =
        tokio::try_join!(client_to_upstream, upstream_to_client)?;
    Ok(TcpRelayOutcome {
        upstream: upstream_addr,
        client_to_upstream_bytes,
        upstream_to_client_bytes,
    })
}

struct AeadStream {
    cipher: Aes256Gcm,
    nonce: [u8; AEAD_NONCE_SIZE],
}

impl AeadStream {
    fn new_with_random_salt(method: Method, key: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        let mut salt = vec![0_u8; salt_size(method)];
        OsRng.fill_bytes(&mut salt);
        let stream = Self::from_salt(method, key, &salt)?;
        Ok((stream, salt))
    }

    fn from_salt(method: Method, key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        let subkey = derive_subkey(method, key, salt)?;
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&subkey).map_err(|error| Error {
                stage: "outbound-crypto",
                message: format!("failed initializing AEAD cipher: {error:?}"),
            })?,
            nonce: [0_u8; AEAD_NONCE_SIZE],
        })
    }

    fn encrypt_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        if payload.len() > TCP_CHUNK_LIMIT {
            return Err(Error {
                stage: "outbound-crypto",
                message: format!("Shadowsocks TCP chunk exceeds {TCP_CHUNK_LIMIT} bytes"),
            });
        }
        let length = (payload.len() as u16).to_be_bytes();
        let encrypted_length = self.encrypt(&length)?;
        let encrypted_payload = self.encrypt(payload)?;
        out.extend_from_slice(&encrypted_length);
        out.extend_from_slice(&encrypted_payload);
        Ok(())
    }

    async fn decrypt_chunk<R>(&mut self, reader: &mut R) -> Result<Option<Vec<u8>>, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut encrypted_length = [0_u8; 2 + AEAD_TAG_SIZE];
        match reader.read_exact(&mut encrypted_length).await {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => {
                return Err(Error {
                    stage: "outbound-read",
                    message: format!("failed reading Shadowsocks TCP length chunk: {error}"),
                });
            }
        }
        let length = self.decrypt(&encrypted_length)?;
        if length.len() != 2 {
            return Err(Error {
                stage: "outbound-crypto",
                message: "invalid Shadowsocks TCP length chunk".to_string(),
            });
        }
        let size = u16::from_be_bytes([length[0], length[1]]) as usize;
        if size > TCP_CHUNK_LIMIT {
            return Err(Error {
                stage: "outbound-crypto",
                message: "Shadowsocks TCP payload length exceeds limit".to_string(),
            });
        }
        let mut encrypted_payload = vec![0_u8; size + AEAD_TAG_SIZE];
        reader
            .read_exact(&mut encrypted_payload)
            .await
            .map_err(|error| Error {
                stage: "outbound-read",
                message: format!("failed reading Shadowsocks TCP payload chunk: {error}"),
            })?;
        self.decrypt(&encrypted_payload).map(Some)
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce;
        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|error| Error {
                stage: "outbound-crypto",
                message: format!("Shadowsocks AEAD encrypt failed: {error:?}"),
            })?;
        increment_nonce(&mut self.nonce);
        Ok(encrypted)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce;
        let decrypted = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|error| Error {
                stage: "outbound-crypto",
                message: format!("Shadowsocks AEAD decrypt failed: {error:?}"),
            })?;
        increment_nonce(&mut self.nonce);
        Ok(decrypted)
    }
}

fn encrypt_udp_packet(method: Method, key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = vec![0_u8; salt_size(method)];
    OsRng.fill_bytes(&mut salt);
    let cipher = udp_cipher(method, key, &salt)?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&[0_u8; AEAD_NONCE_SIZE]), plaintext)
        .map_err(|error| Error {
            stage: "outbound-crypto",
            message: format!("Shadowsocks UDP encrypt failed: {error:?}"),
        })?;
    let mut packet = Vec::with_capacity(salt.len() + encrypted.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

fn decrypt_udp_packet(method: Method, key: &[u8], packet: &[u8]) -> Result<Vec<u8>, Error> {
    let salt_size = salt_size(method);
    if packet.len() < salt_size + AEAD_TAG_SIZE {
        return Err(Error {
            stage: "outbound-crypto",
            message: "Shadowsocks UDP packet is too short".to_string(),
        });
    }
    let (salt, ciphertext) = packet.split_at(salt_size);
    let cipher = udp_cipher(method, key, salt)?;
    cipher
        .decrypt(Nonce::from_slice(&[0_u8; AEAD_NONCE_SIZE]), ciphertext)
        .map_err(|error| Error {
            stage: "outbound-crypto",
            message: format!("Shadowsocks UDP decrypt failed: {error:?}"),
        })
}

fn udp_cipher(method: Method, key: &[u8], salt: &[u8]) -> Result<Aes256Gcm, Error> {
    let subkey = derive_subkey(method, key, salt)?;
    Aes256Gcm::new_from_slice(&subkey).map_err(|error| Error {
        stage: "outbound-crypto",
        message: format!("failed initializing UDP AEAD cipher: {error:?}"),
    })
}

fn derive_subkey(method: Method, key: &[u8], salt: &[u8]) -> Result<Vec<u8>, Error> {
    let mut subkey = vec![0_u8; key_size(method)];
    Hkdf::<Sha1>::new(Some(salt), key)
        .expand(SUBKEY_INFO, &mut subkey)
        .map_err(|error| Error {
            stage: "outbound-crypto",
            message: format!("failed deriving Shadowsocks AEAD subkey: {error:?}"),
        })?;
    Ok(subkey)
}

fn key_size(method: Method) -> usize {
    match method {
        Method::Aes256Gcm => AES_256_GCM_KEY_SIZE,
    }
}

fn salt_size(method: Method) -> usize {
    match method {
        Method::Aes256Gcm => AES_256_GCM_SALT_SIZE,
    }
}

fn evp_bytes_to_key(password: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(AES_256_GCM_KEY_SIZE);
    let mut previous = Vec::<u8>::new();
    while key.len() < AES_256_GCM_KEY_SIZE {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(AES_256_GCM_KEY_SIZE);
    key
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

fn socks_address(target: SocketAddr) -> Vec<u8> {
    let mut address = Vec::with_capacity(1 + 16 + 2);
    match target {
        SocketAddr::V4(address_v4) => {
            address.push(1);
            address.extend_from_slice(&address_v4.ip().octets());
            address.extend_from_slice(&address_v4.port().to_be_bytes());
        }
        SocketAddr::V6(address_v6) => {
            address.push(4);
            address.extend_from_slice(&address_v6.ip().octets());
            address.extend_from_slice(&address_v6.port().to_be_bytes());
        }
    }
    address
}

fn socks_payload_offset(packet: &[u8]) -> Result<usize, Error> {
    let Some(atyp) = packet.first().copied() else {
        return Err(udp_packet_error("missing SOCKS address type"));
    };
    let offset = match atyp {
        1 => 1 + 4 + 2,
        3 => {
            let Some(length) = packet.get(1).copied() else {
                return Err(udp_packet_error("missing SOCKS domain length"));
            };
            1 + 1 + usize::from(length) + 2
        }
        4 => 1 + 16 + 2,
        _ => return Err(udp_packet_error("unsupported SOCKS address type")),
    };
    if packet.len() < offset {
        return Err(udp_packet_error("truncated SOCKS address"));
    }
    Ok(offset)
}

fn udp_packet_error(message: &str) -> Error {
    Error {
        stage: "outbound-crypto",
        message: format!("invalid Shadowsocks UDP payload: {message}"),
    }
}
