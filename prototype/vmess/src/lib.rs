use std::{fmt, io::ErrorKind, net::SocketAddr};

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
};
use uuid::Uuid;

mod protocol;

const CHUNK_LIMIT: usize = 0x3fff;
const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Client {
    server: String,
    port: u16,
    user_id: [u8; 16],
    cmd_key: [u8; 16],
}

#[derive(Debug)]
pub struct UdpReader {
    reader: VmessReader<ReadHalf<TcpStream>>,
}

#[derive(Debug)]
pub struct UdpWriter {
    writer: VmessWriter<WriteHalf<TcpStream>>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpRelayOutcome {
    pub upstream: SocketAddr,
    pub client_to_upstream_bytes: u64,
    pub upstream_to_client_bytes: u64,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct UdpRelayParts {
    pub upstream: SocketAddr,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Error {
    stage: &'static str,
    message: String,
}

#[derive(Debug)]
struct VmessWriter<W> {
    writer: W,
    key: [u8; 16],
    iv: [u8; 16],
    counter: u16,
}

#[derive(Debug)]
struct VmessReader<R> {
    reader: R,
    key: [u8; 16],
    iv: [u8; 16],
    response_auth: u8,
    header_read: bool,
    counter: u16,
}

impl Error {
    pub fn stage(&self) -> &'static str {
        self.stage
    }

    fn new(stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for Error {}

impl Client {
    pub fn try_new(config: ClientConfig) -> Result<Self, Error> {
        let uuid = Uuid::parse_str(&config.uuid).map_err(|error| {
            Error::new(
                "outbound-config",
                format!("failed parsing VMess UUID: {error}"),
            )
        })?;
        let user_id = *uuid.as_bytes();
        let cmd_key = protocol::command_key(&user_id);
        Ok(Self {
            server: config.server,
            port: config.port,
            user_id,
            cmd_key,
        })
    }

    pub fn server_endpoint(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    pub async fn relay_tcp(
        &self,
        downstream: TcpStream,
        target: SocketAddr,
    ) -> Result<TcpRelayOutcome, Error> {
        let mut upstream = self.connect().await?;
        let upstream_addr = upstream.peer_addr().map_err(|error| {
            Error::new(
                "outbound-connect",
                format!("failed reading VMess server address: {error}"),
            )
        })?;
        let context = protocol::request_context();
        upstream
            .write_all(&protocol::request(
                &self.cmd_key,
                CMD_TCP,
                target,
                &context,
            )?)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-write",
                    format!("failed writing VMess TCP request to {upstream_addr}: {error}"),
                )
            })?;

        let (downstream_rx, mut downstream_tx) = downstream.into_split();
        let (upstream_rx, upstream_tx) = io::split(upstream);
        let mut writer = VmessWriter::new(upstream_tx, context.request_key, context.request_iv);
        let mut reader = VmessReader::new(upstream_rx, &context);

        let client_to_upstream = async {
            let bytes = writer.copy_from(downstream_rx).await?;
            writer.close().await?;
            Ok(bytes)
        };
        let upstream_to_client = async {
            let mut bytes = 0_u64;
            while let Some(payload) = reader.read_chunk().await? {
                downstream_tx.write_all(&payload).await.map_err(|error| {
                    Error::new(
                        "inbound-write",
                        format!("failed writing TCP downstream: {error}"),
                    )
                })?;
                bytes += payload.len() as u64;
            }
            Ok(bytes)
        };
        let (client_to_upstream_bytes, upstream_to_client_bytes) =
            tokio::try_join!(client_to_upstream, upstream_to_client)?;
        Ok(TcpRelayOutcome {
            upstream: upstream_addr,
            client_to_upstream_bytes,
            upstream_to_client_bytes,
        })
    }

    pub async fn connect_udp(
        &self,
        target: SocketAddr,
    ) -> Result<(UdpRelayParts, UdpReader, UdpWriter), Error> {
        let mut upstream = self.connect().await?;
        let upstream_addr = upstream.peer_addr().map_err(|error| {
            Error::new(
                "outbound-connect",
                format!("failed reading VMess server address: {error}"),
            )
        })?;
        let context = protocol::request_context();
        upstream
            .write_all(&protocol::request(
                &self.cmd_key,
                CMD_UDP,
                target,
                &context,
            )?)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-write",
                    format!("failed writing VMess UDP request: {error}"),
                )
            })?;
        let (reader, writer) = io::split(upstream);
        Ok((
            UdpRelayParts {
                upstream: upstream_addr,
            },
            UdpReader {
                reader: VmessReader::new(reader, &context),
            },
            UdpWriter {
                writer: VmessWriter::new(writer, context.request_key, context.request_iv),
            },
        ))
    }

    async fn connect(&self) -> Result<TcpStream, Error> {
        TcpStream::connect((self.server.as_str(), self.port))
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-connect",
                    format!(
                        "failed connecting VMess server {}: {error}",
                        self.server_endpoint()
                    ),
                )
            })
    }
}

impl UdpWriter {
    pub async fn write_datagram(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.writer.write_chunk(payload).await
    }
}

impl UdpReader {
    pub async fn read_datagram(&mut self) -> Result<Vec<u8>, Error> {
        self.reader
            .read_chunk()
            .await?
            .ok_or_else(|| Error::new("outbound-read", "VMess UDP stream closed"))
    }
}

impl<W> VmessWriter<W>
where
    W: AsyncWriteExt + Unpin,
{
    fn new(writer: W, key: [u8; 16], iv: [u8; 16]) -> Self {
        Self {
            writer,
            key,
            iv,
            counter: 0,
        }
    }

    async fn copy_from<R>(&mut self, mut reader: R) -> Result<u64, Error>
    where
        R: AsyncRead + Unpin,
    {
        let mut bytes = 0_u64;
        let mut buffer = vec![0_u8; CHUNK_LIMIT];
        loop {
            let size = reader.read(&mut buffer).await.map_err(|error| {
                Error::new(
                    "inbound-read",
                    format!("failed reading TCP downstream: {error}"),
                )
            })?;
            if size == 0 {
                return Ok(bytes);
            }
            bytes += size as u64;
            self.write_chunk(&buffer[..size]).await?;
        }
    }

    async fn write_chunk(&mut self, payload: &[u8]) -> Result<(), Error> {
        if payload.len() > CHUNK_LIMIT {
            return Err(Error::new(
                "outbound-protocol",
                format!("VMess chunk exceeds {CHUNK_LIMIT} bytes"),
            ));
        }
        let packet = protocol::encrypt_chunk(&self.key, &self.iv, self.counter, payload)?;
        self.counter = self.counter.wrapping_add(1);
        self.writer.write_all(&packet).await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed writing VMess data chunk: {error}"),
            )
        })
    }

    async fn close(&mut self) -> Result<(), Error> {
        self.write_chunk(&[]).await?;
        self.writer.shutdown().await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed shutting down VMess writer: {error}"),
            )
        })
    }
}

impl<R> VmessReader<R>
where
    R: AsyncRead + Unpin,
{
    fn new(reader: R, context: &protocol::RequestContext) -> Self {
        let key = protocol::sha256_16(&context.request_key);
        let iv = protocol::sha256_16(&context.request_iv);
        Self {
            reader,
            key,
            iv,
            response_auth: context.response_auth,
            header_read: false,
            counter: 0,
        }
    }

    async fn read_chunk(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if !self.header_read {
            self.read_response_header().await?;
        }
        let mut length = [0_u8; 2];
        match self.reader.read_exact(&mut length).await {
            Ok(_) => {}
            Err(error) if error.kind() == ErrorKind::UnexpectedEof => return Ok(None),
            Err(error) => {
                return Err(Error::new(
                    "outbound-read",
                    format!("failed reading VMess chunk length: {error}"),
                ));
            }
        }
        let length = u16::from_be_bytes(length) as usize;
        if length == 0 {
            return Ok(None);
        }
        let mut ciphertext = vec![0_u8; length];
        self.reader
            .read_exact(&mut ciphertext)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-read",
                    format!("failed reading VMess data chunk: {error}"),
                )
            })?;
        let payload = protocol::decrypt_chunk(&self.key, &self.iv, self.counter, &ciphertext)?;
        self.counter = self.counter.wrapping_add(1);
        if payload.is_empty() {
            Ok(None)
        } else {
            Ok(Some(payload))
        }
    }

    async fn read_response_header(&mut self) -> Result<(), Error> {
        let mut encrypted_length = [0_u8; 2 + protocol::AEAD_TAG_SIZE];
        self.reader
            .read_exact(&mut encrypted_length)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-read",
                    format!("failed reading VMess response header length: {error}"),
                )
            })?;
        let length = protocol::decrypt_response_length(&self.key, &self.iv, &encrypted_length)?;
        if length.len() != 2 {
            return Err(Error::new(
                "outbound-protocol",
                "invalid VMess response header length",
            ));
        }
        let length = u16::from_be_bytes([length[0], length[1]]) as usize;
        let mut encrypted_header = vec![0_u8; length + protocol::AEAD_TAG_SIZE];
        self.reader
            .read_exact(&mut encrypted_header)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-read",
                    format!("failed reading VMess response header: {error}"),
                )
            })?;
        let header = protocol::decrypt_response_header(&self.key, &self.iv, &encrypted_header)?;
        protocol::validate_response_header(self.response_auth, &header)?;
        self.header_read = true;
        Ok(())
    }
}

pub fn request_for_test(
    uuid: &str,
    command: u8,
    target: SocketAddr,
) -> Result<(Vec<u8>, u8), Error> {
    let client = Client::try_new(ClientConfig {
        server: "127.0.0.1".to_string(),
        port: 10086,
        uuid: uuid.to_string(),
    })?;
    let context = protocol::request_context();
    let response_auth = context.response_auth;
    Ok((
        protocol::request(&client.cmd_key, command, target, &context)?,
        response_auth,
    ))
}
