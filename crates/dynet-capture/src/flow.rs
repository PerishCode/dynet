use std::net::{IpAddr, SocketAddr};

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CaptureBackendInfo {
    pub name: &'static str,
    pub platform: CapturePlatform,
    pub takeover: TakeoverKind,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CapturePlatform {
    Linux,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TakeoverKind {
    FullDnsUdpTcp,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CapturedFlow {
    pub flow_id: u64,
    pub peer: Option<IpAddr>,
    pub target: CapturedTarget,
    pub transport: CapturedTransport,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CapturedTarget {
    pub address: SocketAddr,
    pub domain: Option<String>,
    pub source: TargetCaptureSource,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum TargetCaptureSource {
    PacketDestination,
    ObservedDns,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CapturedTransport {
    DnsUdp,
    DnsTcp,
    Tcp,
    Udp,
}

impl CapturedTarget {
    pub fn packet_destination(address: SocketAddr) -> Self {
        Self {
            address,
            domain: None,
            source: TargetCaptureSource::PacketDestination,
        }
    }

    pub fn observed_dns(address: SocketAddr, domain: impl Into<String>) -> Self {
        Self {
            address,
            domain: Some(domain.into()),
            source: TargetCaptureSource::ObservedDns,
        }
    }
}
