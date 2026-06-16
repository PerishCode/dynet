use std::{io::ErrorKind, net::SocketAddr};

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

use crate::{address, Error, TcpRelayOutcome};

const KEY_SIZE: usize = 32;
const SALT_SIZE: usize = 32;
const NONCE_SIZE: usize = 12;
const TAG_SIZE: usize = 16;
const TCP_CHUNK_LIMIT: usize = 0x3fff;
const SUBKEY_INFO: &[u8] = b"ss-subkey";

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Cipher {
    key: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct UdpSession {
    key: Vec<u8>,
}

impl Cipher {
    pub(crate) fn new(password: &str) -> Self {
        Self {
            key: evp_bytes_to_key(password.as_bytes()),
        }
    }

    pub(crate) fn udp_session(&self) -> UdpSession {
        UdpSession {
            key: self.key.clone(),
        }
    }

    pub(crate) async fn relay_tcp_stream(
        &self,
        upstream_addr: SocketAddr,
        downstream: TcpStream,
        upstream: TcpStream,
        target_header: &[u8],
    ) -> Result<TcpRelayOutcome, Error> {
        let (mut downstream_rx, mut downstream_tx) = downstream.into_split();
        let (mut upstream_rx, mut upstream_tx) = upstream.into_split();
        let (mut writer, salt) = AeadStream::new_with_random_salt(&self.key)?;
        let mut initial = salt.to_vec();
        writer.encrypt_chunk(target_header, &mut initial)?;
        upstream_tx.write_all(&initial).await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed writing Shadowsocks TCP header to {upstream_addr}: {error}"),
            )
        })?;

        let client_to_upstream = async {
            let mut bytes = 0_u64;
            let mut buffer = vec![0_u8; TCP_CHUNK_LIMIT];
            loop {
                let size = downstream_rx.read(&mut buffer).await.map_err(|error| {
                    Error::new(
                        "inbound-read",
                        format!("failed reading TCP downstream: {error}"),
                    )
                })?;
                if size == 0 {
                    upstream_tx.shutdown().await.map_err(|error| {
                        Error::new(
                            "outbound-write",
                            format!("failed shutting down Shadowsocks TCP writer: {error}"),
                        )
                    })?;
                    return Ok(bytes);
                }
                bytes += size as u64;
                let mut packet = Vec::with_capacity(size + TAG_SIZE * 2 + 2);
                writer.encrypt_chunk(&buffer[..size], &mut packet)?;
                upstream_tx.write_all(&packet).await.map_err(|error| {
                    Error::new(
                        "outbound-write",
                        format!("failed writing Shadowsocks TCP chunk: {error}"),
                    )
                })?;
            }
        };

        let upstream_to_client = async {
            let mut salt = vec![0_u8; SALT_SIZE];
            upstream_rx.read_exact(&mut salt).await.map_err(|error| {
                Error::new(
                    "outbound-read",
                    format!("failed reading Shadowsocks TCP response salt: {error}"),
                )
            })?;
            let mut reader = AeadStream::from_salt(&self.key, &salt)?;
            let mut bytes = 0_u64;
            loop {
                let Some(payload) = reader.decrypt_chunk(&mut upstream_rx).await? else {
                    return Ok(bytes);
                };
                downstream_tx.write_all(&payload).await.map_err(|error| {
                    Error::new(
                        "inbound-write",
                        format!("failed writing TCP downstream: {error}"),
                    )
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
}

impl UdpSession {
    pub(crate) fn encode_udp_datagram(
        &mut self,
        target: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let target_header = address::socks_address(target);
        let mut plaintext = Vec::with_capacity(target_header.len() + payload.len());
        plaintext.extend_from_slice(&target_header);
        plaintext.extend_from_slice(payload);
        encrypt_udp_packet(&self.key, &plaintext)
    }

    pub(crate) fn decode_udp_datagram(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let plaintext = decrypt_udp_packet(&self.key, packet)?;
        let payload_offset = address::socks_payload_offset(&plaintext)?;
        Ok(plaintext[payload_offset..].to_vec())
    }
}

struct AeadStream {
    cipher: Aes256Gcm,
    nonce: [u8; NONCE_SIZE],
}

impl AeadStream {
    fn new_with_random_salt(key: &[u8]) -> Result<(Self, Vec<u8>), Error> {
        let mut salt = vec![0_u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let stream = Self::from_salt(key, &salt)?;
        Ok((stream, salt))
    }

    fn from_salt(key: &[u8], salt: &[u8]) -> Result<Self, Error> {
        let subkey = derive_subkey(key, salt)?;
        Ok(Self {
            cipher: Aes256Gcm::new_from_slice(&subkey).map_err(|error| {
                Error::new(
                    "outbound-crypto",
                    format!("failed initializing AEAD cipher: {error:?}"),
                )
            })?,
            nonce: [0_u8; NONCE_SIZE],
        })
    }

    fn encrypt_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        if payload.len() > TCP_CHUNK_LIMIT {
            return Err(Error::new(
                "outbound-crypto",
                format!("Shadowsocks TCP chunk exceeds {TCP_CHUNK_LIMIT} bytes"),
            ));
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
        let mut encrypted_length = [0_u8; 2 + TAG_SIZE];
        match reader.read_exact(&mut encrypted_length).await {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => {
                return Err(Error::new(
                    "outbound-read",
                    format!("failed reading Shadowsocks TCP length chunk: {error}"),
                ));
            }
        }
        let length = self.decrypt(&encrypted_length)?;
        if length.len() != 2 {
            return Err(Error::new(
                "outbound-crypto",
                "invalid Shadowsocks TCP length chunk",
            ));
        }
        let size = u16::from_be_bytes([length[0], length[1]]) as usize;
        if size > TCP_CHUNK_LIMIT {
            return Err(Error::new(
                "outbound-crypto",
                "Shadowsocks TCP payload length exceeds limit",
            ));
        }
        let mut encrypted_payload = vec![0_u8; size + TAG_SIZE];
        reader
            .read_exact(&mut encrypted_payload)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-read",
                    format!("failed reading Shadowsocks TCP payload chunk: {error}"),
                )
            })?;
        self.decrypt(&encrypted_payload).map(Some)
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce;
        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|error| {
                Error::new(
                    "outbound-crypto",
                    format!("Shadowsocks AEAD encrypt failed: {error:?}"),
                )
            })?;
        increment_nonce(&mut self.nonce);
        Ok(encrypted)
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce;
        let decrypted = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|error| {
                Error::new(
                    "outbound-crypto",
                    format!("Shadowsocks AEAD decrypt failed: {error:?}"),
                )
            })?;
        increment_nonce(&mut self.nonce);
        Ok(decrypted)
    }
}

fn encrypt_udp_packet(key: &[u8], plaintext: &[u8]) -> Result<Vec<u8>, Error> {
    let mut salt = vec![0_u8; SALT_SIZE];
    OsRng.fill_bytes(&mut salt);
    let cipher = udp_cipher(key, &salt)?;
    let encrypted = cipher
        .encrypt(Nonce::from_slice(&[0_u8; NONCE_SIZE]), plaintext)
        .map_err(|error| {
            Error::new(
                "outbound-crypto",
                format!("Shadowsocks UDP encrypt failed: {error:?}"),
            )
        })?;
    let mut packet = Vec::with_capacity(salt.len() + encrypted.len());
    packet.extend_from_slice(&salt);
    packet.extend_from_slice(&encrypted);
    Ok(packet)
}

fn decrypt_udp_packet(key: &[u8], packet: &[u8]) -> Result<Vec<u8>, Error> {
    if packet.len() < SALT_SIZE + TAG_SIZE {
        return Err(Error::new(
            "outbound-crypto",
            "Shadowsocks UDP packet is too short",
        ));
    }
    let (salt, ciphertext) = packet.split_at(SALT_SIZE);
    let cipher = udp_cipher(key, salt)?;
    cipher
        .decrypt(Nonce::from_slice(&[0_u8; NONCE_SIZE]), ciphertext)
        .map_err(|error| {
            Error::new(
                "outbound-crypto",
                format!("Shadowsocks UDP decrypt failed: {error:?}"),
            )
        })
}

fn udp_cipher(key: &[u8], salt: &[u8]) -> Result<Aes256Gcm, Error> {
    let subkey = derive_subkey(key, salt)?;
    Aes256Gcm::new_from_slice(&subkey).map_err(|error| {
        Error::new(
            "outbound-crypto",
            format!("failed initializing UDP AEAD cipher: {error:?}"),
        )
    })
}

fn derive_subkey(key: &[u8], salt: &[u8]) -> Result<Vec<u8>, Error> {
    let mut subkey = vec![0_u8; KEY_SIZE];
    Hkdf::<Sha1>::new(Some(salt), key)
        .expand(SUBKEY_INFO, &mut subkey)
        .map_err(|error| {
            Error::new(
                "outbound-crypto",
                format!("failed deriving Shadowsocks AEAD subkey: {error:?}"),
            )
        })?;
    Ok(subkey)
}

fn evp_bytes_to_key(password: &[u8]) -> Vec<u8> {
    let mut key = Vec::with_capacity(KEY_SIZE);
    let mut previous = Vec::<u8>::new();
    while key.len() < KEY_SIZE {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(KEY_SIZE);
    key
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
