use std::{
    io::ErrorKind,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use aes_gcm::{aead::Aead, Aes128Gcm, Nonce};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::{Error, TcpRelayOutcome};

mod crypto;
mod replay;
mod udp;
use crypto::{increment_nonce, session_cipher};
pub(crate) use udp::UdpSession;

pub const SS2022_AES_128_GCM_METHOD: &str = "2022-blake3-aes-128-gcm";

pub(super) const KEY_SIZE: usize = 16;
pub(super) const SESSION_ID_SIZE: usize = 8;
pub(super) const SEPARATE_HEADER_SIZE: usize = 16;
pub(super) const NONCE_SIZE: usize = 12;
pub(super) const TAG_SIZE: usize = 16;
pub(super) const HEADER_TYPE_CLIENT_PACKET: u8 = 0;
pub(super) const HEADER_TYPE_SERVER_PACKET: u8 = 1;
pub(super) const TIMESTAMP_TOLERANCE_SECS: u64 = 30;
const SALT_SIZE: usize = 16;
const TCP_CHUNK_LIMIT: usize = 0xffff;
const REQUEST_FIXED_HEADER_SIZE: usize = 11;
const RESPONSE_FIXED_HEADER_SIZE: usize = 27;
const HEADER_TYPE_CLIENT_STREAM: u8 = 0;
const HEADER_TYPE_SERVER_STREAM: u8 = 1;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct Cipher {
    key: [u8; KEY_SIZE],
}

impl Cipher {
    pub(crate) fn new_aes_128_gcm(password: &str) -> Result<Self, Error> {
        let key = STANDARD.decode(password).map_err(|error| {
            Error::new(
                "outbound-config",
                format!("{SS2022_AES_128_GCM_METHOD} password must be base64: {error}"),
            )
        })?;
        let key: [u8; KEY_SIZE] = key.try_into().map_err(|_| {
            Error::new(
                "outbound-config",
                format!("{SS2022_AES_128_GCM_METHOD} password must decode to {KEY_SIZE} bytes"),
            )
        })?;
        Ok(Self { key })
    }

    pub(crate) fn udp_session(&self) -> UdpSession {
        UdpSession::new(self.clone())
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
        let mut salt = [0_u8; SALT_SIZE];
        OsRng.fill_bytes(&mut salt);
        let mut writer = AeadStream::from_salt(&self.key, &salt)?;
        let mut initial = salt.to_vec();
        encrypt_request_header(&mut writer, target_header, &mut initial)?;
        upstream_tx.write_all(&initial).await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed writing Shadowsocks 2022 TCP header to {upstream_addr}: {error}"),
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
                            format!("failed shutting down Shadowsocks 2022 TCP writer: {error}"),
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
                        format!("failed writing Shadowsocks 2022 TCP chunk: {error}"),
                    )
                })?;
            }
        };

        let upstream_to_client = async {
            let mut response_salt = [0_u8; SALT_SIZE];
            upstream_rx
                .read_exact(&mut response_salt)
                .await
                .map_err(|error| {
                    Error::new(
                        "outbound-read",
                        format!("failed reading Shadowsocks 2022 TCP response salt: {error}"),
                    )
                })?;
            let mut reader = AeadStream::from_salt(&self.key, &response_salt)?;
            let first_length = reader
                .decrypt_response_header(&mut upstream_rx, &salt)
                .await?;
            let bytes = read_payload_chunk(&mut reader, &mut upstream_rx, first_length).await?;
            if !bytes.is_empty() {
                downstream_tx.write_all(&bytes).await.map_err(|error| {
                    Error::new(
                        "inbound-write",
                        format!("failed writing TCP downstream: {error}"),
                    )
                })?;
            }
            let mut total = bytes.len() as u64;
            loop {
                let Some(payload) = reader.decrypt_chunk(&mut upstream_rx).await? else {
                    return Ok(total);
                };
                downstream_tx.write_all(&payload).await.map_err(|error| {
                    Error::new(
                        "inbound-write",
                        format!("failed writing TCP downstream: {error}"),
                    )
                })?;
                total += payload.len() as u64;
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

fn encrypt_request_header(
    writer: &mut AeadStream,
    target_header: &[u8],
    out: &mut Vec<u8>,
) -> Result<(), Error> {
    let mut padding = [0_u8; 16];
    OsRng.fill_bytes(&mut padding);
    let mut variable = Vec::with_capacity(target_header.len() + 2 + padding.len());
    variable.extend_from_slice(target_header);
    variable.extend_from_slice(&(padding.len() as u16).to_be_bytes());
    variable.extend_from_slice(&padding);

    let mut fixed = Vec::with_capacity(REQUEST_FIXED_HEADER_SIZE);
    fixed.push(HEADER_TYPE_CLIENT_STREAM);
    fixed.extend_from_slice(&unix_timestamp().to_be_bytes());
    fixed.extend_from_slice(&(variable.len() as u16).to_be_bytes());
    writer.encrypt(&fixed, out)?;
    writer.encrypt(&variable, out)?;
    Ok(())
}

async fn read_payload_chunk<R>(
    reader: &mut AeadStream,
    stream: &mut R,
    size: usize,
) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let mut encrypted_payload = vec![0_u8; size + TAG_SIZE];
    stream
        .read_exact(&mut encrypted_payload)
        .await
        .map_err(|error| {
            Error::new(
                "outbound-read",
                format!("failed reading Shadowsocks 2022 TCP payload chunk: {error}"),
            )
        })?;
    reader.decrypt(&encrypted_payload)
}

struct AeadStream {
    cipher: Aes128Gcm,
    nonce: [u8; NONCE_SIZE],
}

impl AeadStream {
    fn from_salt(key: &[u8; KEY_SIZE], salt: &[u8; SALT_SIZE]) -> Result<Self, Error> {
        Ok(Self {
            cipher: session_cipher(key, salt)?,
            nonce: [0_u8; NONCE_SIZE],
        })
    }

    fn encrypt_chunk(&mut self, payload: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        if payload.len() > TCP_CHUNK_LIMIT {
            return Err(Error::new(
                "outbound-crypto",
                format!("Shadowsocks 2022 TCP chunk exceeds {TCP_CHUNK_LIMIT} bytes"),
            ));
        }
        self.encrypt(&(payload.len() as u16).to_be_bytes(), out)?;
        self.encrypt(payload, out)
    }

    async fn decrypt_response_header<R>(
        &mut self,
        reader: &mut R,
        request_salt: &[u8; SALT_SIZE],
    ) -> Result<usize, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut encrypted_header = [0_u8; RESPONSE_FIXED_HEADER_SIZE + TAG_SIZE];
        reader
            .read_exact(&mut encrypted_header)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-read",
                    format!("failed reading Shadowsocks 2022 TCP response header: {error}"),
                )
            })?;
        let header = self.decrypt(&encrypted_header)?;
        if header.len() != RESPONSE_FIXED_HEADER_SIZE {
            return Err(Error::new(
                "outbound-crypto",
                "invalid Shadowsocks 2022 TCP response header length",
            ));
        }
        if header[0] != HEADER_TYPE_SERVER_STREAM {
            return Err(Error::new(
                "outbound-crypto",
                "invalid Shadowsocks 2022 TCP response header type",
            ));
        }
        validate_timestamp(
            u64::from_be_bytes(header[1..9].try_into().expect("timestamp slice")),
            "TCP response",
        )?;
        if &header[9..25] != request_salt {
            return Err(Error::new(
                "outbound-crypto",
                "invalid Shadowsocks 2022 TCP response request salt",
            ));
        }
        Ok(u16::from_be_bytes([header[25], header[26]]) as usize)
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
                    format!("failed reading Shadowsocks 2022 TCP length chunk: {error}"),
                ));
            }
        }
        let length = self.decrypt(&encrypted_length)?;
        if length.len() != 2 {
            return Err(Error::new(
                "outbound-crypto",
                "invalid Shadowsocks 2022 TCP length chunk",
            ));
        }
        let size = u16::from_be_bytes([length[0], length[1]]) as usize;
        read_payload_chunk(self, reader, size).await.map(Some)
    }

    fn encrypt(&mut self, plaintext: &[u8], out: &mut Vec<u8>) -> Result<(), Error> {
        let nonce = self.nonce;
        let encrypted = self
            .cipher
            .encrypt(Nonce::from_slice(&nonce), plaintext)
            .map_err(|error| {
                Error::new(
                    "outbound-crypto",
                    format!("Shadowsocks 2022 AEAD encrypt failed: {error:?}"),
                )
            })?;
        increment_nonce(&mut self.nonce);
        out.extend_from_slice(&encrypted);
        Ok(())
    }

    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = self.nonce;
        let decrypted = self
            .cipher
            .decrypt(Nonce::from_slice(&nonce), ciphertext)
            .map_err(|error| {
                Error::new(
                    "outbound-crypto",
                    format!("Shadowsocks 2022 AEAD decrypt failed: {error:?}"),
                )
            })?;
        increment_nonce(&mut self.nonce);
        Ok(decrypted)
    }
}

pub(super) fn unix_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

pub(super) fn validate_timestamp(timestamp: u64, context: &str) -> Result<(), Error> {
    let now = unix_timestamp();
    let delta = now.abs_diff(timestamp);
    if delta > TIMESTAMP_TOLERANCE_SECS {
        return Err(Error::new(
            "outbound-crypto",
            format!("Shadowsocks 2022 {context} timestamp outside replay window"),
        ));
    }
    Ok(())
}
