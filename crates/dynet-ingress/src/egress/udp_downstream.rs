use std::{net::SocketAddr, sync::Arc};

use tokio::{net::UdpSocket, sync::mpsc};

#[derive(Debug, Clone)]
pub(crate) enum UdpDownstream {
    Raw(Arc<UdpSocket>),
    Channel(mpsc::Sender<Vec<u8>>),
    Socks5 {
        socket: Arc<UdpSocket>,
        response_target: SocketAddr,
    },
}

impl UdpDownstream {
    pub(crate) async fn send_to_peer(
        &self,
        payload: &[u8],
        peer: SocketAddr,
    ) -> Result<usize, std::io::Error> {
        match self {
            Self::Raw(socket) => socket.send_to(payload, peer).await,
            Self::Channel(tx) => tx
                .send(payload.to_vec())
                .await
                .map(|_| payload.len())
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::BrokenPipe,
                        "UDP downstream response channel is closed",
                    )
                }),
            Self::Socks5 {
                socket,
                response_target,
            } => {
                let packet = socks5_udp_packet(*response_target, payload);
                socket.send_to(&packet, peer).await
            }
        }
    }

    pub(crate) fn payload_len(&self, payload: &[u8]) -> usize {
        payload.len()
    }
}

fn socks5_udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(4 + 18 + payload.len());
    packet.extend_from_slice(&[0, 0, 0]);
    match target {
        SocketAddr::V4(address) => {
            packet.push(1);
            packet.extend_from_slice(&address.ip().octets());
            packet.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            packet.push(4);
            packet.extend_from_slice(&address.ip().octets());
            packet.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    packet
}
