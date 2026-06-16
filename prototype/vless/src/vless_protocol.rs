use std::net::{IpAddr, SocketAddr};

use tokio::io::{AsyncRead, AsyncReadExt};
use uuid::Uuid;

use crate::Error;

const VERSION: u8 = 0;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const ADDRESS_IPV4: u8 = 0x01;
const ADDRESS_DOMAIN: u8 = 0x02;
const ADDRESS_IPV6: u8 = 0x03;
const VISION_FLOW: &str = "xtls-rprx-vision";
const UDP_FRAME_LIMIT: usize = u16::MAX as usize;

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TargetAddress {
    host: TargetHost,
    port: u16,
}

impl TargetAddress {
    pub fn new(host: TargetHost, port: u16) -> Self {
        Self { host, port }
    }

    pub fn socket(address: SocketAddr) -> Self {
        Self {
            host: TargetHost::Ip(address.ip()),
            port: address.port(),
        }
    }
}

pub(crate) fn tcp_request_header(
    user_id: &[u8; 16],
    target: TargetAddress,
) -> Result<Vec<u8>, Error> {
    request_header(user_id, COMMAND_TCP, &vision_flow_addon_data(), target)
}

pub(crate) fn udp_request_header(
    user_id: &[u8; 16],
    target: TargetAddress,
) -> Result<Vec<u8>, Error> {
    request_header(user_id, COMMAND_UDP, &[], target)
}

pub fn tcp_header_for_test(uuid: &str, target: TargetAddress) -> Result<Vec<u8>, Error> {
    tcp_request_header(&parse_uuid(uuid)?, target)
}

pub fn udp_header_for_test(uuid: &str, target: TargetAddress) -> Result<Vec<u8>, Error> {
    udp_request_header(&parse_uuid(uuid)?, target)
}

pub fn udp_frame(payload: &[u8]) -> Result<Vec<u8>, Error> {
    if payload.len() > UDP_FRAME_LIMIT {
        return Err(Error::new(
            "outbound-protocol",
            "VLESS UDP payload exceeds 65535 bytes",
        ));
    }
    let mut frame = Vec::with_capacity(2 + payload.len());
    frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    frame.extend_from_slice(payload);
    Ok(frame)
}

pub async fn read_udp_frame<R>(reader: &mut R) -> Result<Vec<u8>, Error>
where
    R: AsyncRead + Unpin,
{
    let length = reader.read_u16().await.map_err(|error| {
        Error::new(
            "outbound-read",
            format!("failed reading VLESS UDP payload length: {error}"),
        )
    })? as usize;
    let mut payload = vec![0_u8; length];
    reader.read_exact(&mut payload).await.map_err(|error| {
        Error::new(
            "outbound-read",
            format!("failed reading VLESS UDP payload: {error}"),
        )
    })?;
    Ok(payload)
}

pub(crate) async fn read_vless_response_header<R>(reader: &mut R) -> Result<(), Error>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; 2];
    reader.read_exact(&mut header).await.map_err(|error| {
        Error::new(
            "outbound-read",
            format!("failed reading VLESS response header: {error}"),
        )
    })?;
    if header[0] != VERSION {
        return Err(Error::new(
            "outbound-protocol",
            format!("invalid VLESS response version: {}", header[0]),
        ));
    }
    let addon_length = usize::from(header[1]);
    if addon_length > 0 {
        let mut addon = vec![0_u8; addon_length];
        reader.read_exact(&mut addon).await.map_err(|error| {
            Error::new(
                "outbound-read",
                format!("failed reading VLESS response addon: {error}"),
            )
        })?;
    }
    Ok(())
}

fn request_header(
    user_id: &[u8; 16],
    command: u8,
    addon_data: &[u8],
    target: TargetAddress,
) -> Result<Vec<u8>, Error> {
    let mut header = Vec::with_capacity(1 + user_id.len() + 1 + addon_data.len() + 1 + 2 + 1 + 16);
    header.push(VERSION);
    header.extend_from_slice(user_id);
    let addon_len = u8::try_from(addon_data.len())
        .map_err(|_| Error::new("outbound-protocol", "VLESS addon data exceeds 255 bytes"))?;
    header.push(addon_len);
    header.extend_from_slice(addon_data);
    header.push(command);
    write_target(&target, &mut header)?;
    Ok(header)
}

fn write_target(target: &TargetAddress, output: &mut Vec<u8>) -> Result<(), Error> {
    output.extend_from_slice(&target.port.to_be_bytes());
    match &target.host {
        TargetHost::Ip(IpAddr::V4(address)) => {
            output.push(ADDRESS_IPV4);
            output.extend_from_slice(&address.octets());
        }
        TargetHost::Ip(IpAddr::V6(address)) => {
            output.push(ADDRESS_IPV6);
            output.extend_from_slice(&address.octets());
        }
        TargetHost::Domain(domain) => {
            let length = u8::try_from(domain.len()).map_err(|_| {
                Error::new("outbound-protocol", "VLESS domain target exceeds 255 bytes")
            })?;
            output.push(ADDRESS_DOMAIN);
            output.push(length);
            output.extend_from_slice(domain.as_bytes());
        }
    }
    Ok(())
}

fn vision_flow_addon_data() -> Vec<u8> {
    encode_flow_addon(VISION_FLOW)
}

fn encode_flow_addon(flow: &str) -> Vec<u8> {
    let flow_bytes = flow.as_bytes();
    let mut addon = Vec::with_capacity(2 + flow_bytes.len());
    addon.push(0x0a);
    addon.push(flow_bytes.len() as u8);
    addon.extend_from_slice(flow_bytes);
    addon
}

fn parse_uuid(value: &str) -> Result<[u8; 16], Error> {
    Uuid::parse_str(value)
        .map(|uuid| *uuid.as_bytes())
        .map_err(|error| {
            Error::new(
                "outbound-config",
                format!("failed parsing VLESS UUID: {error}"),
            )
        })
}
