use std::{fmt, net::SocketAddr};

use native_tls::TlsConnector as NativeTlsConnector;
use sha2::{Digest, Sha224};
use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadHalf, WriteHalf},
    net::TcpStream,
};
use tokio_native_tls::{TlsConnector, TlsStream};

const CRLF: &[u8; 2] = b"\r\n";
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ClientConfig {
    pub server: String,
    pub port: u16,
    pub password: String,
    pub sni: Option<String>,
    pub skip_cert_verify: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Client {
    server: String,
    port: u16,
    password_hash: String,
    sni: Option<String>,
    skip_cert_verify: bool,
}

#[derive(Debug)]
pub struct UdpReader<R = ReadHalf<TlsStream<TcpStream>>> {
    reader: R,
}

#[derive(Debug)]
pub struct UdpWriter<W = WriteHalf<TlsStream<TcpStream>>> {
    writer: W,
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
    pub fn new(config: ClientConfig) -> Self {
        Self {
            server: config.server,
            port: config.port,
            password_hash: password_hash(&config.password),
            sni: config.sni,
            skip_cert_verify: config.skip_cert_verify,
        }
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

    pub async fn relay_tcp(
        &self,
        downstream: TcpStream,
        target: SocketAddr,
    ) -> Result<TcpRelayOutcome, Error> {
        let (upstream_addr, mut upstream) = self.connect_tls().await?;
        self.relay_tcp_with_tls(downstream, target, upstream_addr, &mut upstream)
            .await
    }

    pub async fn relay_tcp_with_stream(
        &self,
        downstream: TcpStream,
        target: SocketAddr,
        tcp: TcpStream,
    ) -> Result<TcpRelayOutcome, Error> {
        let (upstream_addr, mut upstream) = self.connect_tls_with_stream(tcp).await?;
        self.relay_tcp_with_tls(downstream, target, upstream_addr, &mut upstream)
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
        let mut upstream = self.connect_tls_with_io(upstream).await?;
        self.relay_tcp_with_tls(downstream, target, upstream_addr, &mut upstream)
            .await
    }

    async fn relay_tcp_with_tls<D, U>(
        &self,
        downstream: D,
        target: SocketAddr,
        upstream_addr: SocketAddr,
        upstream: &mut TlsStream<U>,
    ) -> Result<TcpRelayOutcome, Error>
    where
        D: AsyncRead + AsyncWrite + Unpin,
        U: AsyncRead + AsyncWrite + Unpin,
    {
        upstream
            .write_all(&request_header(&self.password_hash, CMD_CONNECT, target))
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-write",
                    format!("failed writing Trojan TCP request to {upstream_addr}: {error}"),
                )
            })?;

        let mut downstream = downstream;
        let (client_to_upstream, upstream_to_client) =
            io::copy_bidirectional(&mut downstream, &mut *upstream)
                .await
                .map_err(|error| {
                    Error::new("relay", format!("Trojan TCP relay failed: {error}"))
                })?;
        Ok(TcpRelayOutcome {
            upstream: upstream_addr,
            client_to_upstream_bytes: client_to_upstream,
            upstream_to_client_bytes: upstream_to_client,
        })
    }

    pub async fn connect_udp(
        &self,
        target: SocketAddr,
    ) -> Result<(UdpRelayParts, UdpReader, UdpWriter), Error> {
        let (upstream_addr, mut upstream) = self.connect_tls().await?;
        self.connect_udp_with_tls(upstream_addr, &mut upstream, target)
            .await?;
        let (reader, writer) = io::split(upstream);
        Ok((
            UdpRelayParts {
                upstream: upstream_addr,
            },
            UdpReader { reader },
            UdpWriter { writer },
        ))
    }

    pub async fn connect_udp_with_io<IO>(
        &self,
        upstream_addr: SocketAddr,
        upstream: IO,
        target: SocketAddr,
    ) -> Result<
        (
            UdpRelayParts,
            UdpReader<ReadHalf<TlsStream<IO>>>,
            UdpWriter<WriteHalf<TlsStream<IO>>>,
        ),
        Error,
    >
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        let mut upstream = self.connect_tls_with_io(upstream).await?;
        self.connect_udp_with_tls(upstream_addr, &mut upstream, target)
            .await?;
        let (reader, writer) = io::split(upstream);
        Ok((
            UdpRelayParts {
                upstream: upstream_addr,
            },
            UdpReader { reader },
            UdpWriter { writer },
        ))
    }

    async fn connect_udp_with_tls<IO>(
        &self,
        upstream_addr: SocketAddr,
        upstream: &mut TlsStream<IO>,
        target: SocketAddr,
    ) -> Result<(), Error>
    where
        IO: AsyncRead + AsyncWrite + Unpin,
    {
        upstream
            .write_all(&request_header(
                &self.password_hash,
                CMD_UDP_ASSOCIATE,
                target,
            ))
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-write",
                    format!("failed writing Trojan UDP associate request: {error}"),
                )
            })?;
        let _ = upstream_addr;
        Ok(())
    }

    async fn connect_tls(&self) -> Result<(SocketAddr, TlsStream<TcpStream>), Error> {
        let tcp = TcpStream::connect((self.server.as_str(), self.port))
            .await
            .map_err(|error| {
                Error::new(
                    "outbound-connect",
                    format!(
                        "failed connecting Trojan server {}: {error}",
                        self.server_endpoint()
                    ),
                )
            })?;
        self.connect_tls_with_stream(tcp).await
    }

    async fn connect_tls_with_stream(
        &self,
        tcp: TcpStream,
    ) -> Result<(SocketAddr, TlsStream<TcpStream>), Error> {
        let upstream_addr = tcp.peer_addr().map_err(|error| {
            Error::new(
                "outbound-connect",
                format!("failed reading Trojan server address: {error}"),
            )
        })?;
        self.connect_tls_with_io(tcp)
            .await
            .map(|stream| (upstream_addr, stream))
    }

    async fn connect_tls_with_io<U>(&self, io: U) -> Result<TlsStream<U>, Error>
    where
        U: AsyncRead + AsyncWrite + Unpin,
    {
        let connector = tls_connector(self.skip_cert_verify)?;
        let sni = self.sni.as_deref().unwrap_or(&self.server);
        connector.connect(sni, io).await.map_err(|error| {
            Error::new(
                "outbound-tls",
                format!("failed establishing Trojan TLS connection: {error}"),
            )
        })
    }
}

impl<W> UdpWriter<W>
where
    W: AsyncWrite + Unpin,
{
    pub async fn write_datagram(
        &mut self,
        target: SocketAddr,
        payload: &[u8],
    ) -> Result<(), Error> {
        let packet = udp_packet(target, payload)?;
        self.writer.write_all(&packet).await.map_err(|error| {
            Error::new(
                "outbound-write",
                format!("failed writing Trojan UDP packet: {error}"),
            )
        })
    }
}

impl<R> UdpReader<R>
where
    R: AsyncRead + Unpin,
{
    pub async fn read_datagram(&mut self) -> Result<Vec<u8>, Error> {
        read_udp_packet(&mut self.reader).await
    }
}

pub fn request_header_for_test(password: &str, cmd: u8, target: SocketAddr) -> Vec<u8> {
    request_header(&password_hash(password), cmd, target)
}

pub fn udp_packet_for_test(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, Error> {
    udp_packet(target, payload)
}

pub async fn read_udp_for_test<R>(reader: &mut R) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    read_udp_packet(reader).await
}

fn tls_connector(skip_cert_verify: bool) -> Result<TlsConnector, Error> {
    let mut builder = NativeTlsConnector::builder();
    if skip_cert_verify {
        builder.danger_accept_invalid_certs(true);
    }
    builder.build().map(TlsConnector::from).map_err(|error| {
        Error::new(
            "outbound-tls",
            format!("failed building Trojan TLS connector: {error}"),
        )
    })
}

fn password_hash(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut output, "{byte:02x}").expect("hex write cannot fail");
    }
    output
}

fn request_header(password_hash: &str, cmd: u8, target: SocketAddr) -> Vec<u8> {
    let mut header = Vec::with_capacity(password_hash.len() + 2 + 1 + 1 + 16 + 2 + 2);
    header.extend_from_slice(password_hash.as_bytes());
    header.extend_from_slice(CRLF);
    header.push(cmd);
    write_address(target, &mut header);
    header.extend_from_slice(CRLF);
    header
}

fn udp_packet(target: SocketAddr, payload: &[u8]) -> Result<Vec<u8>, Error> {
    let length = u16::try_from(payload.len()).map_err(|_| {
        Error::new(
            "outbound-protocol",
            "Trojan UDP payload exceeds 65535 bytes",
        )
    })?;
    let mut packet = Vec::with_capacity(1 + 16 + 2 + 2 + 2 + payload.len());
    write_address(target, &mut packet);
    packet.extend_from_slice(&length.to_be_bytes());
    packet.extend_from_slice(CRLF);
    packet.extend_from_slice(payload);
    Ok(packet)
}

async fn read_udp_packet<R>(reader: &mut R) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    read_address(reader).await?;
    let mut length = [0_u8; 2];
    reader.read_exact(&mut length).await.map_err(read_error)?;
    let length = u16::from_be_bytes(length) as usize;
    let mut crlf = [0_u8; 2];
    reader.read_exact(&mut crlf).await.map_err(read_error)?;
    if crlf != *CRLF {
        return Err(Error::new(
            "outbound-protocol",
            "invalid Trojan UDP packet delimiter",
        ));
    }
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await.map_err(read_error)?;
    Ok(payload)
}

async fn read_address<R>(reader: &mut R) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
{
    let mut atyp = [0_u8; 1];
    reader.read_exact(&mut atyp).await.map_err(read_error)?;
    match atyp[0] {
        0x01 => {
            let mut rest = [0_u8; 4 + 2];
            reader.read_exact(&mut rest).await.map_err(read_error)?;
        }
        0x03 => {
            let mut length = [0_u8; 1];
            reader.read_exact(&mut length).await.map_err(read_error)?;
            let mut rest = vec![0_u8; usize::from(length[0]) + 2];
            reader.read_exact(&mut rest).await.map_err(read_error)?;
        }
        0x04 => {
            let mut rest = [0_u8; 16 + 2];
            reader.read_exact(&mut rest).await.map_err(read_error)?;
        }
        _ => {
            return Err(Error::new(
                "outbound-protocol",
                "unsupported Trojan UDP address type",
            ));
        }
    }
    Ok(())
}

fn write_address(target: SocketAddr, output: &mut Vec<u8>) {
    match target {
        SocketAddr::V4(address) => {
            output.push(0x01);
            output.extend_from_slice(&address.ip().octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            output.push(0x04);
            output.extend_from_slice(&address.ip().octets());
            output.extend_from_slice(&address.port().to_be_bytes());
        }
    }
}

fn read_error(error: std::io::Error) -> Error {
    Error::new(
        "outbound-read",
        format!("failed reading Trojan UDP packet: {error}"),
    )
}
