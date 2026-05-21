use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use smoltcp::{
    socket::udp,
    wire::{IpAddress, IpEndpoint},
};

pub(crate) fn send_response(
    socket: &mut udp::Socket<'_>,
    client: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> Result<usize, String> {
    let metadata = udp::UdpMetadata {
        endpoint: socket_to_endpoint(client)?,
        local_address: Some(socket_ip_to_ipaddress(target.ip())?),
        meta: Default::default(),
    };
    socket
        .send_slice(payload, metadata)
        .map_err(|error| format!("failed to write TUN UDP payload: {error}"))?;
    Ok(payload.len())
}

pub(crate) fn metadata_to_sockets(
    local_port: u16,
    metadata: udp::UdpMetadata,
) -> Result<(SocketAddr, SocketAddr), String> {
    let client = endpoint_to_socket(metadata.endpoint)?;
    let Some(local_address) = metadata.local_address else {
        return Err("TUN UDP packet did not include a destination IP".to_string());
    };
    let target =
        ipaddress_to_ipaddr(local_address).map(|address| SocketAddr::new(address, local_port))?;
    Ok((client, target))
}

pub(crate) fn metadata_is_ipv6(metadata: udp::UdpMetadata) -> bool {
    endpoint_is_ipv6(metadata.endpoint)
        || metadata
            .local_address
            .is_some_and(|address| matches!(address, IpAddress::Ipv6(_)))
}

fn endpoint_to_socket(endpoint: IpEndpoint) -> Result<SocketAddr, String> {
    match endpoint.addr {
        IpAddress::Ipv4(address) => Ok(SocketAddr::new(
            IpAddr::V4(Ipv4Addr::from(address.octets())),
            endpoint.port,
        )),
        #[allow(unreachable_patterns)]
        other => Err(format!(
            "experimental UDP forwarding currently supports IPv4 socket endpoints only, got {other:?}"
        )),
    }
}

fn endpoint_is_ipv6(endpoint: IpEndpoint) -> bool {
    matches!(endpoint.addr, IpAddress::Ipv6(_))
}

fn ipaddress_to_ipaddr(address: IpAddress) -> Result<IpAddr, String> {
    match address {
        IpAddress::Ipv4(address) => Ok(IpAddr::V4(Ipv4Addr::from(address.octets()))),
        IpAddress::Ipv6(address) => Ok(IpAddr::V6(std::net::Ipv6Addr::from(address.octets()))),
        #[allow(unreachable_patterns)]
        other => Err(format!("unsupported IP address in UDP metadata: {other:?}")),
    }
}

fn socket_ip_to_ipaddress(address: IpAddr) -> Result<IpAddress, String> {
    match address {
        IpAddr::V4(address) => Ok(IpAddress::Ipv4(address.octets().into())),
        IpAddr::V6(address) => Ok(IpAddress::Ipv6(address.octets().into())),
    }
}

fn socket_to_endpoint(address: SocketAddr) -> Result<IpEndpoint, String> {
    Ok(IpEndpoint::new(
        socket_ip_to_ipaddress(address.ip())?,
        address.port(),
    ))
}
