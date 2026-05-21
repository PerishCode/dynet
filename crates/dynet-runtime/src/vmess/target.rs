use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) enum VmessTarget {
    Ip(SocketAddr),
    Domain { host: String, port: u16 },
}

impl std::fmt::Display for VmessTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Ip(address) => write!(formatter, "{address}"),
            Self::Domain { host, port } => write!(formatter, "{host}:{port}"),
        }
    }
}

impl From<SocketAddr> for VmessTarget {
    fn from(value: SocketAddr) -> Self {
        Self::Ip(value)
    }
}

pub(super) fn write_destination(
    header: &mut [u8],
    destination: &VmessTarget,
) -> Result<usize, String> {
    match destination {
        VmessTarget::Ip(destination) => write_ip_destination(header, *destination),
        VmessTarget::Domain { host, port } => write_domain_destination(header, host, *port),
    }
}

fn write_ip_destination(header: &mut [u8], destination: SocketAddr) -> Result<usize, String> {
    header[38..40].copy_from_slice(&destination.port().to_be_bytes());
    match destination.ip() {
        IpAddr::V4(address) => {
            header[40] = 1;
            header[41..45].copy_from_slice(&address.octets());
            Ok(45)
        }
        IpAddr::V6(address) => {
            header[40] = 3;
            header[41..57].copy_from_slice(&address.octets());
            Ok(57)
        }
    }
}

fn write_domain_destination(header: &mut [u8], host: &str, port: u16) -> Result<usize, String> {
    let host = host.trim();
    if host.is_empty() {
        return Err("VMess destination domain must not be empty".to_string());
    }
    let bytes = host.as_bytes();
    let len = u8::try_from(bytes.len()).map_err(|_| {
        format!(
            "VMess destination domain is too long: {} bytes",
            bytes.len()
        )
    })?;
    header[38..40].copy_from_slice(&port.to_be_bytes());
    header[40] = 2;
    header[41] = len;
    let end = 42 + usize::from(len);
    header[42..end].copy_from_slice(bytes);
    Ok(end)
}
