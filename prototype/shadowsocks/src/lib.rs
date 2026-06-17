use std::{fmt, net::SocketAddr};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};

mod address;
mod aead2017;
mod aead2022;

pub use aead2022::SS2022_AES_128_GCM_METHOD;

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum Method {
    Aes256Gcm,
    Blake3Aes128Gcm2022,
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
    protocol: Protocol,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum Protocol {
    Aead2017(aead2017::Cipher),
    Aead2022(aead2022::Cipher),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct UdpSession {
    protocol: UdpProtocol,
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum UdpProtocol {
    Aead2017(aead2017::UdpSession),
    Aead2022(aead2022::UdpSession),
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

    pub(crate) fn new(stage: &'static str, message: impl Into<String>) -> Self {
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
    pub fn new(config: ClientConfig) -> Self {
        Self::try_new(config).expect("valid Shadowsocks client config")
    }

    pub fn try_new(config: ClientConfig) -> Result<Self, Error> {
        let protocol = match config.method {
            Method::Aes256Gcm => Protocol::Aead2017(aead2017::Cipher::new(&config.password)),
            Method::Blake3Aes128Gcm2022 => {
                Protocol::Aead2022(aead2022::Cipher::new_aes_128_gcm(&config.password)?)
            }
        };
        Ok(Self {
            server: config.server,
            port: config.port,
            protocol,
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

    pub fn udp_session(&self) -> UdpSession {
        let protocol = match &self.protocol {
            Protocol::Aead2017(cipher) => UdpProtocol::Aead2017(cipher.udp_session()),
            Protocol::Aead2022(cipher) => UdpProtocol::Aead2022(cipher.udp_session()),
        };
        UdpSession { protocol }
    }

    pub async fn relay_tcp(
        &self,
        downstream: TcpStream,
        target: SocketAddr,
    ) -> Result<TcpRelayOutcome, Error> {
        let upstream = TcpStream::connect((self.server.as_str(), self.port))
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-connect",
                    format!(
                        "failed connecting Shadowsocks server {}: {error}",
                        self.server_endpoint()
                    ),
                )
            })?;
        self.relay_tcp_with_stream(downstream, upstream, target)
            .await
    }

    pub async fn relay_tcp_with_stream(
        &self,
        downstream: TcpStream,
        upstream: TcpStream,
        target: SocketAddr,
    ) -> Result<TcpRelayOutcome, Error> {
        let upstream_addr = upstream.peer_addr().map_err(|error| {
            Error::new(
                "outbound-connect",
                format!("failed reading Shadowsocks server address: {error}"),
            )
        })?;
        self.relay_tcp_with_io(downstream, upstream_addr, upstream, target)
            .await
    }

    pub async fn relay_tcp_with_io<D, U>(
        &self,
        downstream: D,
        upstream_addr: SocketAddr,
        upstream: U,
        target: SocketAddr,
    ) -> Result<TcpRelayOutcome, Error>
    where
        D: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let target_header = address::socks_address(target);
        match &self.protocol {
            Protocol::Aead2017(cipher) => {
                cipher
                    .relay_tcp_stream(upstream_addr, downstream, upstream, &target_header)
                    .await
            }
            Protocol::Aead2022(cipher) => {
                cipher
                    .relay_tcp_stream(upstream_addr, downstream, upstream, &target_header)
                    .await
            }
        }
    }

    pub fn encode_udp_datagram(
        &self,
        target: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        self.udp_session().encode_udp_datagram(target, payload)
    }

    pub fn decode_udp_datagram(&self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        self.udp_session().decode_udp_datagram(packet)
    }
}

impl UdpSession {
    pub fn encode_udp_datagram(
        &mut self,
        target: SocketAddr,
        payload: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match &mut self.protocol {
            UdpProtocol::Aead2017(session) => session.encode_udp_datagram(target, payload),
            UdpProtocol::Aead2022(session) => session.encode_udp_datagram(target, payload),
        }
    }

    pub fn decode_udp_datagram(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        match &mut self.protocol {
            UdpProtocol::Aead2017(session) => session.decode_udp_datagram(packet),
            UdpProtocol::Aead2022(session) => session.decode_udp_datagram(packet),
        }
    }
}
