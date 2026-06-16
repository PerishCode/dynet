use std::net::SocketAddr;

use crate::Error;

pub(crate) fn socks_address(target: SocketAddr) -> Vec<u8> {
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

pub(crate) fn socks_payload_offset(packet: &[u8]) -> Result<usize, Error> {
    let Some(atyp) = packet.first().copied() else {
        return Err(packet_error("missing SOCKS address type"));
    };
    let offset = match atyp {
        1 => 1 + 4 + 2,
        3 => {
            let Some(length) = packet.get(1).copied() else {
                return Err(packet_error("missing SOCKS domain length"));
            };
            1 + 1 + usize::from(length) + 2
        }
        4 => 1 + 16 + 2,
        _ => return Err(packet_error("unsupported SOCKS address type")),
    };
    if packet.len() < offset {
        return Err(packet_error("truncated SOCKS address"));
    }
    Ok(offset)
}

pub(crate) fn packet_error(message: &str) -> Error {
    Error::new(
        "outbound-crypto",
        format!("invalid Shadowsocks UDP payload: {message}"),
    )
}
