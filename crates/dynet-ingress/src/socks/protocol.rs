use std::net::SocketAddr;

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

const SOCKS_VERSION: u8 = 5;
const SOCKS_NO_AUTH: u8 = 0;
const SOCKS_NO_ACCEPTABLE_METHODS: u8 = 0xff;
const SOCKS_ATYP_IPV4: u8 = 1;
const SOCKS_ATYP_DOMAIN: u8 = 3;
const SOCKS_ATYP_IPV6: u8 = 4;

pub(super) const SOCKS_CMD_CONNECT: u8 = 1;
pub(super) const SOCKS_CMD_BIND: u8 = 2;
pub(super) const SOCKS_CMD_UDP_ASSOCIATE: u8 = 3;
pub(super) const SOCKS_REPLY_SUCCEEDED: u8 = 0;
pub(super) const SOCKS_REPLY_COMMAND_NOT_SUPPORTED: u8 = 7;

pub(super) async fn negotiate_no_auth(client: &mut TcpStream) -> Result<(), SocksError> {
    let mut header = [0_u8; 2];
    client.read_exact(&mut header).await.map_err(|error| {
        SocksError::with_source("socks-handshake", "failed reading greeting", error)
    })?;
    if header[0] != SOCKS_VERSION {
        return Err(SocksError::new(
            "socks-handshake",
            "unsupported SOCKS version",
        ));
    }
    let mut methods = vec![0_u8; header[1] as usize];
    client.read_exact(&mut methods).await.map_err(|error| {
        SocksError::with_source("socks-handshake", "failed reading methods", error)
    })?;
    let method = if methods.contains(&SOCKS_NO_AUTH) {
        SOCKS_NO_AUTH
    } else {
        SOCKS_NO_ACCEPTABLE_METHODS
    };
    client
        .write_all(&[SOCKS_VERSION, method])
        .await
        .map_err(|error| {
            SocksError::with_source("socks-handshake", "failed writing method selection", error)
        })?;
    if method == SOCKS_NO_ACCEPTABLE_METHODS {
        return Err(SocksError::new(
            "socks-handshake",
            "SOCKS5 no-auth method is not offered",
        ));
    }
    Ok(())
}

pub(super) async fn read_request(client: &mut TcpStream) -> Result<SocksRequest, SocksError> {
    let mut header = [0_u8; 4];
    client.read_exact(&mut header).await.map_err(|error| {
        SocksError::with_source("socks-request", "failed reading request header", error)
    })?;
    if header[0] != SOCKS_VERSION {
        return Err(SocksError::new(
            "socks-request",
            "unsupported SOCKS version",
        ));
    }
    if header[2] != 0 {
        return Err(SocksError::new(
            "socks-request",
            "SOCKS5 reserved byte must be zero",
        ));
    }
    Ok(SocksRequest {
        command: header[1],
        destination: read_destination(client, header[3]).await?,
    })
}

pub(super) async fn write_reply(
    client: &mut TcpStream,
    reply: u8,
    bind: SocketAddr,
) -> Result<(), SocksError> {
    let mut response = Vec::with_capacity(22);
    response.extend_from_slice(&[SOCKS_VERSION, reply, 0]);
    match bind {
        SocketAddr::V4(address) => {
            response.push(SOCKS_ATYP_IPV4);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            response.push(SOCKS_ATYP_IPV6);
            response.extend_from_slice(&address.ip().octets());
            response.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    client.write_all(&response).await.map_err(|error| {
        SocksError::with_source("socks-reply", "failed writing SOCKS5 reply", error)
    })
}

pub(super) fn parse_udp_packet(packet: &[u8]) -> Result<SocksUdpPacket, SocksError> {
    if packet.len() < 4 {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP packet is too short",
        ));
    }
    if packet[0] != 0 || packet[1] != 0 {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP reserved bytes must be zero",
        ));
    }
    if packet[2] != 0 {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP fragmentation is not supported",
        ));
    }
    let (destination, offset) = parse_udp_destination(packet, 3)?;
    Ok(SocksUdpPacket {
        destination,
        payload: packet[offset..].to_vec(),
    })
}

async fn read_destination(
    client: &mut TcpStream,
    atyp: u8,
) -> Result<SocksDestination, SocksError> {
    match atyp {
        SOCKS_ATYP_IPV4 => read_ipv4_destination(client).await,
        SOCKS_ATYP_IPV6 => read_ipv6_destination(client).await,
        SOCKS_ATYP_DOMAIN => read_domain_destination(client).await,
        _ => Err(SocksError::new(
            "socks-request",
            "unsupported SOCKS5 address type",
        )),
    }
}

async fn read_ipv4_destination(client: &mut TcpStream) -> Result<SocksDestination, SocksError> {
    let mut address = [0_u8; 4];
    client.read_exact(&mut address).await.map_err(|error| {
        SocksError::with_source("socks-request", "failed reading IPv4 target", error)
    })?;
    Ok(SocksDestination::Socket(SocketAddr::from((
        address,
        read_port(client).await?,
    ))))
}

async fn read_ipv6_destination(client: &mut TcpStream) -> Result<SocksDestination, SocksError> {
    let mut address = [0_u8; 16];
    client.read_exact(&mut address).await.map_err(|error| {
        SocksError::with_source("socks-request", "failed reading IPv6 target", error)
    })?;
    Ok(SocksDestination::Socket(SocketAddr::from((
        address,
        read_port(client).await?,
    ))))
}

async fn read_domain_destination(client: &mut TcpStream) -> Result<SocksDestination, SocksError> {
    let mut length = [0_u8; 1];
    client.read_exact(&mut length).await.map_err(|error| {
        SocksError::with_source("socks-request", "failed reading domain length", error)
    })?;
    let mut domain = vec![0_u8; length[0] as usize];
    client.read_exact(&mut domain).await.map_err(|error| {
        SocksError::with_source("socks-request", "failed reading domain target", error)
    })?;
    let domain = String::from_utf8(domain).map_err(|error| {
        SocksError::new(
            "socks-request",
            format!("domain target is not UTF-8: {error}"),
        )
    })?;
    Ok(SocksDestination::Domain {
        domain,
        port: read_port(client).await?,
    })
}

async fn read_port(client: &mut TcpStream) -> Result<u16, SocksError> {
    let mut port = [0_u8; 2];
    client.read_exact(&mut port).await.map_err(|error| {
        SocksError::with_source("socks-request", "failed reading target port", error)
    })?;
    Ok(u16::from_be_bytes(port))
}

fn parse_udp_destination(
    packet: &[u8],
    offset: usize,
) -> Result<(SocksDestination, usize), SocksError> {
    let Some(atyp) = packet.get(offset).copied() else {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP address type is missing",
        ));
    };
    let cursor = offset + 1;
    match atyp {
        SOCKS_ATYP_IPV4 => parse_udp_ipv4(packet, cursor),
        SOCKS_ATYP_IPV6 => parse_udp_ipv6(packet, cursor),
        SOCKS_ATYP_DOMAIN => parse_udp_domain(packet, cursor),
        _ => Err(SocksError::new(
            "socks-udp-read",
            "unsupported SOCKS5 UDP address type",
        )),
    }
}

fn parse_udp_ipv4(packet: &[u8], cursor: usize) -> Result<(SocksDestination, usize), SocksError> {
    if packet.len() < cursor + 6 {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP IPv4 target is truncated",
        ));
    }
    let address = [
        packet[cursor],
        packet[cursor + 1],
        packet[cursor + 2],
        packet[cursor + 3],
    ];
    let port = u16::from_be_bytes([packet[cursor + 4], packet[cursor + 5]]);
    Ok((
        SocksDestination::Socket(SocketAddr::from((address, port))),
        cursor + 6,
    ))
}

fn parse_udp_ipv6(packet: &[u8], cursor: usize) -> Result<(SocksDestination, usize), SocksError> {
    if packet.len() < cursor + 18 {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP IPv6 target is truncated",
        ));
    }
    let mut address = [0_u8; 16];
    address.copy_from_slice(&packet[cursor..cursor + 16]);
    let port = u16::from_be_bytes([packet[cursor + 16], packet[cursor + 17]]);
    Ok((
        SocksDestination::Socket(SocketAddr::from((address, port))),
        cursor + 18,
    ))
}

fn parse_udp_domain(packet: &[u8], cursor: usize) -> Result<(SocksDestination, usize), SocksError> {
    let Some(length) = packet.get(cursor).copied() else {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP domain length is missing",
        ));
    };
    let domain_start = cursor + 1;
    let domain_end = domain_start + length as usize;
    if packet.len() < domain_end + 2 {
        return Err(SocksError::new(
            "socks-udp-read",
            "SOCKS5 UDP domain target is truncated",
        ));
    }
    let domain = String::from_utf8(packet[domain_start..domain_end].to_vec()).map_err(|error| {
        SocksError::new(
            "socks-udp-read",
            format!("SOCKS5 UDP domain is not UTF-8: {error}"),
        )
    })?;
    let port = u16::from_be_bytes([packet[domain_end], packet[domain_end + 1]]);
    Ok((SocksDestination::Domain { domain, port }, domain_end + 2))
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct SocksRequest {
    pub(super) command: u8,
    pub(super) destination: SocksDestination,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) enum SocksDestination {
    Socket(SocketAddr),
    Domain { domain: String, port: u16 },
}

impl SocksDestination {
    pub(super) fn domain(&self) -> Option<&str> {
        match self {
            Self::Socket(_) => None,
            Self::Domain { domain, .. } => Some(domain),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct SocksUdpPacket {
    pub(super) destination: SocksDestination,
    pub(super) payload: Vec<u8>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub(super) struct SocksError {
    pub(super) stage: &'static str,
    pub(super) message: String,
}

impl SocksError {
    pub(super) fn new(stage: &'static str, message: impl Into<String>) -> Self {
        Self {
            stage,
            message: message.into(),
        }
    }

    pub(super) fn with_source(
        stage: &'static str,
        message: &'static str,
        error: impl std::fmt::Display,
    ) -> Self {
        Self::new(stage, format!("{message}: {error}"))
    }
}
