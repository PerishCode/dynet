use std::{fmt, net::SocketAddr, pin::Pin, task::Poll};

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf, ReadHalf, WriteHalf},
    net::TcpStream,
};
use uuid::Uuid;

use crate::reality::{
    decode_public_key, decode_short_id, RealityClientConfig, RealityClientConnection,
};
use crate::reality_stream::{perform_reality_handshake, RealityStream};
pub use crate::vless_protocol::{
    read_udp_frame, tcp_header_for_test, udp_frame, udp_header_for_test, TargetAddress, TargetHost,
};
use crate::{crypto::CryptoConnection, vision_stream::VisionStream};

#[allow(dead_code)]
mod buf_reader;
mod crypto;
mod reality;
mod reality_stream;
#[allow(dead_code)]
mod slide_buffer;
mod sync_adapter;
mod tls_deframer;
mod tls_fuzzy_deframer;
mod tls_handshake_util;
mod tls_parse;
#[allow(dead_code)]
mod util;
mod vision_filter;
mod vision_pad;
mod vision_stream;
mod vision_unpad;
mod vless_protocol;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    pub uuid: String,
    pub server_name: String,
    pub public_key: String,
    pub short_id: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Client {
    server: String,
    port: u16,
    user_id: [u8; 16],
    server_name: String,
    public_key: [u8; 32],
    short_id: [u8; 8],
}

#[derive(Debug)]
pub struct UdpReader {
    reader: ReadHalf<RealityStream>,
    response_pending: bool,
}

#[derive(Debug)]
pub struct TcpReader {
    reader: ReadHalf<VisionStream<TcpStream>>,
}

#[derive(Debug)]
pub struct TcpWriter {
    writer: WriteHalf<VisionStream<TcpStream>>,
}

#[derive(Debug)]
pub struct TcpStreamHandle {
    stream: VisionStream<TcpStream>,
}

#[derive(Debug)]
pub struct UdpWriter {
    writer: WriteHalf<RealityStream>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct TcpRelayParts {
    pub upstream: SocketAddr,
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
                format!("failed parsing VLESS UUID: {error}"),
            )
        })?;
        if config.server_name.is_empty() {
            return Err(Error::new(
                "outbound-config",
                "VLESS Reality server_name is required",
            ));
        }
        let public_key = decode_public_key(&config.public_key).map_err(|error| {
            Error::new(
                "outbound-config",
                format!("failed decoding VLESS Reality public_key: {error}"),
            )
        })?;
        let short_id = decode_short_id(&config.short_id).map_err(|error| {
            Error::new(
                "outbound-config",
                format!("failed decoding VLESS Reality short_id: {error}"),
            )
        })?;
        Ok(Self {
            server: config.server,
            port: config.port,
            user_id: *uuid.as_bytes(),
            server_name: config.server_name,
            public_key,
            short_id,
        })
    }

    pub fn server_endpoint(&self) -> String {
        format!("{}:{}", self.server, self.port)
    }

    pub fn server_host(&self) -> &str {
        &self.server
    }

    pub fn server_port(&self) -> u16 {
        self.port
    }

    pub fn tcp_request_header(&self, target: TargetAddress) -> Result<Vec<u8>, Error> {
        vless_protocol::tcp_request_header(&self.user_id, target)
    }

    pub fn udp_request_header(&self, target: TargetAddress) -> Result<Vec<u8>, Error> {
        vless_protocol::udp_request_header(&self.user_id, target)
    }

    pub fn user_id(&self) -> [u8; 16] {
        self.user_id
    }

    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    pub fn short_id(&self) -> [u8; 8] {
        self.short_id
    }

    pub async fn connect_tcp(
        &self,
        target: SocketAddr,
    ) -> Result<(TcpRelayParts, TcpReader, TcpWriter), Error> {
        let (parts, stream) = self.connect_tcp_stream(target).await?;
        let (reader, writer) = io::split(stream.stream);
        Ok((parts, TcpReader { reader }, TcpWriter { writer }))
    }

    pub async fn connect_tcp_stream(
        &self,
        target: SocketAddr,
    ) -> Result<(TcpRelayParts, TcpStreamHandle), Error> {
        self.connect_tcp_with_stream(target, self.dial_tcp_server().await?)
            .await
    }

    pub async fn connect_tcp_with_stream(
        &self,
        target: SocketAddr,
        tcp: TcpStream,
    ) -> Result<(TcpRelayParts, TcpStreamHandle), Error> {
        let (upstream, mut stream) = self.connect_reality_with_stream(tcp).await?;
        stream
            .write_all(&self.tcp_request_header(TargetAddress::socket(target))?)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-write",
                    format!("failed writing VLESS TCP request: {error}"),
                )
            })?;
        stream.flush().await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed flushing VLESS TCP request: {error}"),
            )
        })?;
        let (tcp, session) = stream.into_inner();
        let stream = VisionStream::new_client(
            tcp,
            CryptoConnection::new_reality_client(session),
            self.user_id,
        );
        Ok((TcpRelayParts { upstream }, TcpStreamHandle { stream }))
    }

    pub async fn connect_udp(
        &self,
        target: SocketAddr,
    ) -> Result<(UdpRelayParts, UdpReader, UdpWriter), Error> {
        let (upstream, mut stream) = self.connect_reality().await?;
        stream
            .write_all(&self.udp_request_header(TargetAddress::socket(target))?)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-write",
                    format!("failed writing VLESS UDP request: {error}"),
                )
            })?;
        stream.flush().await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed flushing VLESS UDP request: {error}"),
            )
        })?;
        let (reader, writer) = io::split(stream);
        Ok((
            UdpRelayParts { upstream },
            UdpReader {
                reader,
                response_pending: true,
            },
            UdpWriter { writer },
        ))
    }

    async fn dial_tcp_server(&self) -> Result<TcpStream, Error> {
        let tcp = TcpStream::connect((self.server.as_str(), self.port))
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-connect",
                    format!(
                        "failed connecting VLESS Reality server {}: {error}",
                        self.server_endpoint()
                    ),
                )
            })?;
        Ok(tcp)
    }

    async fn connect_reality(&self) -> Result<(SocketAddr, RealityStream), Error> {
        self.connect_reality_with_stream(self.dial_tcp_server().await?)
            .await
    }

    async fn connect_reality_with_stream(
        &self,
        mut tcp: TcpStream,
    ) -> Result<(SocketAddr, RealityStream), Error> {
        let upstream = tcp.peer_addr().map_err(|error| {
            Error::new(
                "outbound-connect",
                format!("failed reading VLESS Reality server address: {error}"),
            )
        })?;
        let mut session = RealityClientConnection::new(RealityClientConfig {
            public_key: self.public_key,
            short_id: self.short_id,
            server_name: self.server_name.clone(),
            cipher_suites: Vec::new(),
        })
        .map_err(|error| {
            Error::new(
                "outbound-tls",
                format!("failed creating VLESS Reality client connection: {error}"),
            )
        })?;
        perform_reality_handshake(&mut session, &mut tcp)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-tls",
                    format!("failed establishing VLESS Reality connection: {error}"),
                )
            })?;
        Ok((upstream, RealityStream::new(tcp, session)))
    }
}

impl AsyncRead for TcpStreamHandle {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for TcpStreamHandle {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

impl TcpWriter {
    pub async fn write_all(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.writer.write_all(payload).await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed writing VLESS TCP payload: {error}"),
            )
        })?;
        self.writer.flush().await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed flushing VLESS TCP payload: {error}"),
            )
        })
    }

    pub async fn shutdown(&mut self) -> Result<(), Error> {
        self.writer.shutdown().await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed shutting down VLESS TCP stream: {error}"),
            )
        })
    }
}

impl TcpReader {
    pub async fn read(&mut self, output: &mut [u8]) -> Result<usize, Error> {
        self.reader.read(output).await.map_err(|error| {
            Error::new(
                "outbound-read",
                format!("failed reading VLESS TCP payload: {error}"),
            )
        })
    }
}

impl UdpWriter {
    pub async fn write_datagram(&mut self, payload: &[u8]) -> Result<(), Error> {
        self.writer
            .write_all(&udp_frame(payload)?)
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-write",
                    format!("failed writing VLESS UDP frame: {error}"),
                )
            })?;
        self.writer.flush().await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed flushing VLESS UDP frame: {error}"),
            )
        })
    }
}

impl UdpReader {
    pub async fn read_datagram(&mut self) -> Result<Vec<u8>, Error> {
        if self.response_pending {
            vless_protocol::read_vless_response_header(&mut self.reader).await?;
            self.response_pending = false;
        }
        read_udp_frame(&mut self.reader).await
    }
}
