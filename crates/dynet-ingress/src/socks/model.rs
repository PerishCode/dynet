use std::{net::SocketAddr, sync::Arc, time::Duration};

use dynet_runtime::{RuntimeState, SelectionDecision, TargetContext};
use tokio::{net::UdpSocket, sync::mpsc};

use super::protocol::SocksDestination;

pub(super) struct SocksUdpLoop<O> {
    pub downstream: Arc<UdpSocket>,
    pub egress: O,
    pub runtime: RuntimeState,
    pub config: crate::Socks5IngressConfig,
    pub peer: SocketAddr,
    pub session_id: u64,
    pub completion: mpsc::Receiver<()>,
}

pub(super) struct SocksUdpTask<O> {
    pub udp_peer: SocketAddr,
    pub target: SocketAddr,
    pub target_context: TargetContext,
    pub response_target: SocketAddr,
    pub destination: SocksDestination,
    pub downstream: Arc<UdpSocket>,
    pub downstream_rx: mpsc::Receiver<Vec<u8>>,
    pub complete_tx: mpsc::Sender<(SocketAddr, SocketAddr)>,
    pub session_id: u64,
    pub decision: SelectionDecision,
    pub runtime: RuntimeState,
    pub egress: O,
    pub idle_timeout: Duration,
}

#[derive(Debug, Clone)]
pub(super) struct UdpAssociationSender {
    pub node_protocol: &'static str,
    pub decision: SelectionDecision,
    pub target_context: TargetContext,
    pub tx: mpsc::Sender<Vec<u8>>,
}
