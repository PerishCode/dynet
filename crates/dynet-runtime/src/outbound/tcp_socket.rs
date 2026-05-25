use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};

use crate::settings::OutboundTcpSettings;
use crate::socket;

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum TcpTarget {
    Socket(SocketAddr),
    Domain { host: String, port: u16 },
}

impl std::fmt::Display for TcpTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Socket(address) => write!(formatter, "{address}"),
            Self::Domain { host, port } => write!(formatter, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for TcpTarget {
    fn from(value: SocketAddr) -> Self {
        Self::Socket(value)
    }
}

pub(super) fn connect_direct_target(
    target: &TcpTarget,
    mark: u32,
    settings: OutboundTcpSettings,
) -> Result<TcpStream, String> {
    let stream = match target {
        TcpTarget::Socket(address) => {
            socket::connect_marked_tcp(address, mark, settings.connect_timeout())
                .map_err(|error| format!("failed to connect TCP target {target}: {error}"))?
        }
        TcpTarget::Domain { host, port } => connect_host_port(
            host,
            *port,
            mark,
            None,
            &format!("TCP target {target}"),
            settings,
        )?,
    };
    socket::set_socket_mark(&stream, mark)?;
    stream
        .set_read_timeout(Some(settings.read_write_timeout()))
        .map_err(|error| format!("failed to set TCP target read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(settings.read_write_timeout()))
        .map_err(|error| format!("failed to set TCP target write timeout: {error}"))?;
    Ok(stream)
}

pub(crate) fn connect_tcp_socket(
    address: &str,
    port: u16,
    mark: u32,
    settings: OutboundTcpSettings,
) -> Result<TcpStream, String> {
    connect_tcp_socket_bound(address, port, mark, None, settings)
}

pub(crate) fn connect_tcp_socket_bound(
    address: &str,
    port: u16,
    mark: u32,
    interface_name: Option<&str>,
    settings: OutboundTcpSettings,
) -> Result<TcpStream, String> {
    let stream = match address.parse::<IpAddr>() {
        Ok(ip) => {
            let socket = SocketAddr::new(ip, port);
            connect_socket_address(&socket, mark, interface_name, "outbound server", settings)?
        }
        Err(_) => connect_host_port(
            address,
            port,
            mark,
            interface_name,
            "outbound server",
            settings,
        )?,
    };
    stream
        .set_read_timeout(Some(settings.read_write_timeout()))
        .map_err(|error| format!("failed to set outbound read timeout: {error}"))?;
    stream
        .set_write_timeout(Some(settings.read_write_timeout()))
        .map_err(|error| format!("failed to set outbound write timeout: {error}"))?;
    Ok(stream)
}

fn connect_host_port(
    host: &str,
    port: u16,
    mark: u32,
    interface_name: Option<&str>,
    context: &str,
    settings: OutboundTcpSettings,
) -> Result<TcpStream, String> {
    let addresses = (host, port)
        .to_socket_addrs()
        .map_err(|error| format!("failed to resolve {context} {host}:{port}: {error}"))?;
    let mut last_error = None;
    for address in addresses {
        match connect_socket_address(&address, mark, interface_name, context, settings) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(format!(
        "failed to connect {context} {host}:{port}: {}",
        last_error.unwrap_or_else(|| "no socket addresses resolved".to_string())
    ))
}

fn connect_socket_address(
    address: &SocketAddr,
    mark: u32,
    interface_name: Option<&str>,
    context: &str,
    settings: OutboundTcpSettings,
) -> Result<TcpStream, String> {
    let stream = match interface_name {
        Some(interface_name) => {
            socket::connect_bound_tcp(address, mark, interface_name, settings.connect_timeout())
                .map_err(|error| format!("failed to connect {context} {address}: {error}"))?
        }
        None => socket::connect_marked_tcp(address, mark, settings.connect_timeout())
            .map_err(|error| format!("failed to connect {context} {address}: {error}"))?,
    };
    Ok(stream)
}
