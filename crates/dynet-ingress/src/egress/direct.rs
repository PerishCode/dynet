use std::{net::SocketAddr, time::Duration};

use tokio::{
    io::{self, AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    time,
};

use crate::DATAGRAM_LIMIT;

use super::{
    count_downstream, relay_udp_response, DirectEgress, EgressError, EgressNode, TcpDialConnection,
    TcpDialTarget, TcpDialer, TcpRelayOutcome, TcpRelaySession, UdpRelayAssociation,
    UdpRelayOutcome, DIRECT_EGRESS,
};

impl EgressNode for DirectEgress {
    fn tag(&self) -> &'static str {
        DIRECT_EGRESS
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        self.handle_tcp_with_dialer(session, self).await
    }

    async fn handle_udp(
        &self,
        mut association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
        let upstream_socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0)))
            .await
            .map_err(|error| {
                EgressError::new(
                    "egress-bind",
                    None,
                    format!("failed to bind UDP egress socket: {error}"),
                )
            })?;
        upstream_socket
            .connect(association.target)
            .await
            .map_err(|error| {
                EgressError::new(
                    "egress-connect",
                    Some(association.target),
                    format!(
                        "failed connecting UDP target {}: {error}",
                        association.target
                    ),
                )
            })?;
        let mut buffer = vec![0_u8; DATAGRAM_LIMIT];
        loop {
            let step = time::timeout(
                association.idle_timeout,
                udp_step(
                    &mut association.downstream_rx,
                    &upstream_socket,
                    &mut buffer,
                ),
            )
            .await;
            match step {
                Ok(UdpStep::Downstream(payload)) => {
                    upstream_socket.send(&payload).await.map_err(|error| {
                        EgressError::new(
                            "egress-write",
                            Some(association.target),
                            format!("failed sending UDP target datagram: {error}"),
                        )
                    })?;
                }
                Ok(UdpStep::Upstream(size)) => {
                    relay_udp_response(
                        &association,
                        self.tag(),
                        association.target,
                        &buffer[..size],
                        &[],
                    )
                    .await?;
                }
                Ok(UdpStep::Closed) => {
                    return Ok(UdpRelayOutcome {
                        upstream: association.target,
                        close_reason: "inbound-closed",
                    });
                }
                Err(_) => {
                    return Ok(UdpRelayOutcome {
                        upstream: association.target,
                        close_reason: "idle-timeout",
                    });
                }
            }
        }
    }
}

impl DirectEgress {
    pub(super) async fn handle_tcp_with_dialer<D>(
        &self,
        session: TcpRelaySession,
        dialer: &D,
    ) -> Result<TcpRelayOutcome, EgressError>
    where
        D: TcpDialer,
    {
        let mut upstream = dialer
            .dial_tcp(TcpDialTarget::Socket(session.target))
            .await?
            .into_io();
        let (mut downstream, byte_counts) = count_downstream(session.downstream);
        let (client_to_upstream, upstream_to_client, close_reason) =
            if let Some(idle_timeout) = session.idle_timeout {
                copy_bidirectional_until_idle(&mut downstream, &mut upstream, idle_timeout).await
            } else {
                io::copy_bidirectional(&mut downstream, &mut upstream)
                    .await
                    .map(|(client_to_upstream, upstream_to_client)| {
                        (client_to_upstream, upstream_to_client, "normal")
                    })
            }
            .map_err(|error| {
                EgressError::new(
                    "relay",
                    Some(session.target),
                    format!("TCP relay failed: {error}"),
                )
                .with_plaintext_bytes(byte_counts)
            })?;
        Ok(TcpRelayOutcome {
            upstream: session.target,
            client_to_upstream_bytes: client_to_upstream,
            upstream_to_client_bytes: upstream_to_client,
            close_reason,
        })
    }
}

async fn copy_bidirectional_until_idle<D, U>(
    downstream: &mut D,
    upstream: &mut U,
    idle_timeout: Duration,
) -> io::Result<(u64, u64, &'static str)>
where
    D: AsyncRead + AsyncWrite + Unpin,
    U: AsyncRead + AsyncWrite + Unpin,
{
    let mut downstream_buffer = [0_u8; 16 * 1024];
    let mut upstream_buffer = [0_u8; 16 * 1024];
    let mut client_to_upstream = 0_u64;
    let mut upstream_to_client = 0_u64;
    let mut client_closed = false;
    let mut upstream_closed = false;

    loop {
        if client_closed && upstream_closed {
            return Ok((client_to_upstream, upstream_to_client, "normal"));
        }
        if upstream_closed && upstream_to_client > 0 {
            return Ok((client_to_upstream, upstream_to_client, "normal"));
        }

        let idle = time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            read = downstream.read(&mut downstream_buffer), if !client_closed => {
                let len = read?;
                if len == 0 {
                    client_closed = true;
                    upstream.shutdown().await?;
                } else {
                    upstream.write_all(&downstream_buffer[..len]).await?;
                    client_to_upstream += len as u64;
                }
            }
            read = upstream.read(&mut upstream_buffer), if !upstream_closed => {
                let len = read?;
                if len == 0 {
                    upstream_closed = true;
                } else {
                    downstream.write_all(&upstream_buffer[..len]).await?;
                    upstream_to_client += len as u64;
                }
            }
            _ = &mut idle => {
                return Ok((client_to_upstream, upstream_to_client, "idle-timeout"));
            }
        }
    }
}

impl TcpDialer for DirectEgress {
    async fn dial_tcp(&self, target: TcpDialTarget) -> Result<TcpDialConnection, EgressError> {
        let upstream = target.upstream();
        let label = target.label();
        let stream = target.connect().await.map_err(|error| {
            EgressError::new(
                "egress-connect",
                upstream,
                format!("failed dialing TCP target {label}: {error}"),
            )
        })?;
        let upstream = stream.peer_addr().map_err(|error| {
            EgressError::new(
                "egress-connect",
                upstream,
                format!("failed reading TCP target address {label}: {error}"),
            )
        })?;
        Ok(TcpDialConnection::TcpStream { stream, upstream })
    }
}

impl TcpDialTarget {
    pub(crate) async fn resolve_socket(&self) -> Result<SocketAddr, EgressError> {
        match self {
            Self::Socket(address) => Ok(*address),
            Self::Host { host, port } => {
                let label = self.label();
                let mut addresses = tokio::net::lookup_host((host.as_str(), *port))
                    .await
                    .map_err(|error| {
                        EgressError::new(
                            "egress-resolve",
                            None,
                            format!("failed resolving TCP target {label}: {error}"),
                        )
                    })?;
                addresses.next().ok_or_else(|| {
                    EgressError::new(
                        "egress-resolve",
                        None,
                        format!("TCP target {label} resolved no addresses"),
                    )
                })
            }
        }
    }

    pub(crate) fn host(host: impl Into<String>, port: u16) -> Self {
        Self::Host {
            host: host.into(),
            port,
        }
    }

    fn upstream(&self) -> Option<SocketAddr> {
        match self {
            Self::Socket(address) => Some(*address),
            Self::Host { .. } => None,
        }
    }

    fn label(&self) -> String {
        match self {
            Self::Socket(address) => address.to_string(),
            Self::Host { host, port } => format!("{host}:{port}"),
        }
    }

    async fn connect(self) -> Result<TcpStream, std::io::Error> {
        match self {
            Self::Socket(address) => TcpStream::connect(address).await,
            Self::Host { host, port } => TcpStream::connect((host.as_str(), port)).await,
        }
    }
}

pub(crate) enum UdpStep {
    Downstream(Vec<u8>),
    Upstream(usize),
    Closed,
}

pub(crate) async fn udp_step(
    downstream_rx: &mut mpsc::Receiver<Vec<u8>>,
    upstream_socket: &UdpSocket,
    buffer: &mut [u8],
) -> UdpStep {
    tokio::select! {
        payload = downstream_rx.recv() => match payload {
            Some(payload) => UdpStep::Downstream(payload),
            None => UdpStep::Closed,
        },
        result = upstream_socket.recv(buffer) => match result {
            Ok(size) => UdpStep::Upstream(size),
            Err(_) => UdpStep::Closed,
        },
    }
}
