use std::{
    fs::File,
    io::{ErrorKind, Read},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    },
    thread,
    time::Duration,
};

use tracing::debug;

use crate::{RuntimeCounters, RuntimeEvent, RuntimeEventKind};

#[cfg(target_os = "linux")]
mod event_context;
#[cfg(target_os = "linux")]
mod ipv6_guard;
#[cfg(target_os = "linux")]
mod outbound_events;
#[cfg(target_os = "linux")]
pub(crate) mod tcp_forward;
#[cfg(target_os = "linux")]
mod udp_downstream;
#[cfg(target_os = "linux")]
pub(crate) mod udp_forward;
#[cfg(target_os = "linux")]
mod udp_packet;
#[cfg(target_os = "linux")]
mod user_rule;

#[cfg(not(target_os = "linux"))]
pub(crate) mod tcp_forward {
    use std::sync::{atomic::AtomicBool, Arc};

    use crate::{RuntimeCounters, RuntimeSettings};

    use super::TunDevice;

    pub(crate) fn run(
        _tun: TunDevice,
        _settings: RuntimeSettings,
        _counters: Arc<RuntimeCounters>,
        _stop: Arc<AtomicBool>,
    ) -> Result<(), String> {
        Err("experimental TUN forwarding is only implemented on linux".to_string())
    }
}

pub(crate) struct TunDevice {
    file: File,
}

impl TunDevice {
    #[cfg(target_os = "linux")]
    pub(crate) fn open(name: &str) -> Result<Self, String> {
        use std::os::fd::AsRawFd;

        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open("/dev/net/tun")
            .map_err(|error| format!("failed to open /dev/net/tun: {error}"))?;
        let mut request = IfReq::new(name)?;
        let result = unsafe { libc::ioctl(file.as_raw_fd(), libc::TUNSETIFF, &mut request) };
        if result != 0 {
            return Err(format!(
                "failed to attach tun {name}: {}",
                std::io::Error::last_os_error()
            ));
        }
        set_nonblocking(&file)?;
        Ok(Self { file })
    }

    #[cfg(not(target_os = "linux"))]
    pub(crate) fn open(_name: &str) -> Result<Self, String> {
        Err("dynet runtime TUN is only implemented on linux".to_string())
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn into_raw_fd(self) -> std::os::fd::RawFd {
        use std::os::fd::IntoRawFd;

        self.file.into_raw_fd()
    }
}

pub(crate) fn read_packets(
    mut tun: TunDevice,
    counters: Arc<RuntimeCounters>,
    stop: Arc<AtomicBool>,
) -> Result<(), String> {
    let mut buffer = [0_u8; 4096];
    while !stop.load(Ordering::SeqCst) {
        match tun.file.read(&mut buffer) {
            Ok(0) => thread::sleep(Duration::from_millis(50)),
            Ok(size) => handle_packet(&buffer[..size], size, &counters)?,
            Err(error) if error.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) if error.kind() == ErrorKind::Interrupted => {}
            Err(error) => return Err(format!("failed reading tun: {error}")),
        }
    }
    Ok(())
}

fn handle_packet(packet: &[u8], size: usize, counters: &RuntimeCounters) -> Result<(), String> {
    counters.tun_packets.fetch_add(1, Ordering::SeqCst);
    if let Some(summary) = PacketSummary::parse(packet) {
        if summary.version == 6 {
            emit_ipv6_denied(&summary, counters)?;
        }
        debug!(
            version = summary.version,
            protocol = %summary.protocol,
            source = %summary.source,
            destination = %summary.destination,
            destination_port = ?summary.destination_port,
            bytes = size,
            "tun.packet"
        );
    } else {
        debug!(bytes = size, "tun.packet.unparsed");
    }
    Ok(())
}

fn emit_ipv6_denied(summary: &PacketSummary, counters: &RuntimeCounters) -> Result<(), String> {
    counters.ipv6_packets_denied.fetch_add(1, Ordering::SeqCst);
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::IpPacketDenied)
            .field("ipVersion", 6)
            .field("protocol", summary.protocol)
            .field("source", summary.source)
            .field("destination", summary.destination)
            .field(
                "destinationPort",
                summary
                    .destination_port
                    .map(|port| port.to_string())
                    .unwrap_or_else(|| "<none>".to_string()),
            )
            .field("reason", "ipv6 forwarding is not implemented; fail closed"),
    )
}

struct PacketSummary {
    version: u8,
    protocol: &'static str,
    source: IpAddr,
    destination: IpAddr,
    destination_port: Option<u16>,
}

impl PacketSummary {
    fn parse(packet: &[u8]) -> Option<Self> {
        let version = packet.first()? >> 4;
        match version {
            4 => Self::parse_ipv4(packet),
            6 => Self::parse_ipv6(packet),
            _ => None,
        }
    }

    fn parse_ipv4(packet: &[u8]) -> Option<Self> {
        if packet.len() < 20 {
            return None;
        }
        let ihl = usize::from(packet[0] & 0x0f) * 4;
        if ihl < 20 || packet.len() < ihl {
            return None;
        }
        let protocol_number = packet[9];
        let source = IpAddr::V4(Ipv4Addr::new(
            packet[12], packet[13], packet[14], packet[15],
        ));
        let destination = IpAddr::V4(Ipv4Addr::new(
            packet[16], packet[17], packet[18], packet[19],
        ));
        Some(Self {
            version: 4,
            protocol: protocol_label(protocol_number),
            source,
            destination,
            destination_port: transport_destination_port(protocol_number, &packet[ihl..]),
        })
    }

    fn parse_ipv6(packet: &[u8]) -> Option<Self> {
        if packet.len() < 40 {
            return None;
        }
        let protocol_number = packet[6];
        let source_bytes: [u8; 16] = packet[8..24].try_into().ok()?;
        let destination_bytes: [u8; 16] = packet[24..40].try_into().ok()?;
        let source = IpAddr::V6(Ipv6Addr::from(source_bytes));
        let destination = IpAddr::V6(Ipv6Addr::from(destination_bytes));
        Some(Self {
            version: 6,
            protocol: protocol_label(protocol_number),
            source,
            destination,
            destination_port: transport_destination_port(protocol_number, &packet[40..]),
        })
    }
}

fn protocol_label(protocol: u8) -> &'static str {
    match protocol {
        1 => "icmp",
        6 => "tcp",
        17 => "udp",
        58 => "icmpv6",
        _ => "other",
    }
}

fn transport_destination_port(protocol: u8, payload: &[u8]) -> Option<u16> {
    if !matches!(protocol, 6 | 17) || payload.len() < 4 {
        return None;
    }
    Some(u16::from_be_bytes([payload[2], payload[3]]))
}

#[cfg(target_os = "linux")]
#[repr(C)]
struct IfReq {
    name: [u8; libc::IFNAMSIZ],
    flags: libc::c_short,
    padding: [u8; 24],
}

#[cfg(target_os = "linux")]
impl IfReq {
    fn new(name: &str) -> Result<Self, String> {
        let bytes = name.as_bytes();
        if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ {
            return Err(format!("tun name must be 1..{} bytes", libc::IFNAMSIZ - 1));
        }
        let mut request = Self {
            name: [0; libc::IFNAMSIZ],
            flags: (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short,
            padding: [0; 24],
        };
        request.name[..bytes.len()].copy_from_slice(bytes);
        Ok(request)
    }
}

#[cfg(target_os = "linux")]
fn set_nonblocking(file: &File) -> Result<(), String> {
    use std::os::fd::AsRawFd;

    let flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    if flags < 0 {
        return Err(format!(
            "failed to read tun fd flags: {}",
            std::io::Error::last_os_error()
        ));
    }
    let result = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETFL, flags | libc::O_NONBLOCK) };
    if result == 0 {
        Ok(())
    } else {
        Err(format!(
            "failed to set tun fd nonblocking: {}",
            std::io::Error::last_os_error()
        ))
    }
}
