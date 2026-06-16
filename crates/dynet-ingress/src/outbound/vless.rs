use std::net::SocketAddr;

use tokio::{io, sync::mpsc, time};

use vless_prototype::{
    Client as VlessClient, ClientConfig as VlessClientConfig, UdpReader as VlessUdpReader,
};

use crate::{
    outbound::{
        Outbound, OutboundError, TcpOutboundOutcome, TcpOutboundSession, UdpOutboundAssociation,
        UdpOutboundOutcome,
    },
    session_fields, IngressEventKind, VlessConfig,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VlessOutbound {
    client: VlessClient,
}

impl VlessOutbound {
    pub(crate) fn new(config: VlessConfig) -> Result<Self, String> {
        Ok(Self {
            client: VlessClient::try_new(VlessClientConfig {
                server: config.server,
                port: config.port,
                uuid: config.uuid,
                server_name: config.server_name,
                public_key: config.public_key,
                short_id: config.short_id,
            })
            .map_err(|error| error.to_string())?,
        })
    }

    fn tag(&self) -> &'static str {
        "vless"
    }
}

impl Outbound for VlessOutbound {
    fn tag(&self) -> &'static str {
        self.tag()
    }

    async fn handle_tcp(
        &self,
        mut session: TcpOutboundSession,
    ) -> Result<TcpOutboundOutcome, OutboundError> {
        let (parts, mut upstream) = self
            .client
            .connect_tcp_stream(session.target)
            .await
            .map_err(|error| vless_error(error, None))?;
        let (client_to_upstream, upstream_to_client) =
            io::copy_bidirectional(&mut session.downstream, &mut upstream)
                .await
                .map_err(|error| OutboundError {
                    stage: "relay",
                    upstream: Some(parts.upstream),
                    message: format!("VLESS TCP relay failed: {error}"),
                })?;
        Ok(TcpOutboundOutcome {
            upstream: parts.upstream,
            client_to_upstream_bytes: client_to_upstream,
            upstream_to_client_bytes: upstream_to_client,
            close_reason: "normal",
        })
    }

    async fn handle_udp(
        &self,
        mut association: UdpOutboundAssociation,
    ) -> Result<UdpOutboundOutcome, OutboundError> {
        let (parts, mut reader, mut writer) = self
            .client
            .connect_udp(association.target)
            .await
            .map_err(|error| vless_error(error, None))?;
        loop {
            let step = time::timeout(
                association.idle_timeout,
                vless_udp_step(&mut association.downstream_rx, &mut reader),
            )
            .await;
            match step {
                Ok(VlessUdpStep::Downstream(payload)) => {
                    writer
                        .write_datagram(&payload)
                        .await
                        .map_err(|error| vless_error(error, Some(parts.upstream)))?;
                }
                Ok(VlessUdpStep::Upstream(payload)) => {
                    association
                        .downstream
                        .send_to(&payload, association.peer)
                        .await
                        .map_err(|error| OutboundError {
                            stage: "inbound-write",
                            upstream: Some(parts.upstream),
                            message: format!("failed sending UDP downstream datagram: {error}"),
                        })?;
                    let mut fields = session_fields(
                        association.session_id,
                        association.inbound,
                        self.tag(),
                        association.peer,
                        association.target,
                        parts.upstream,
                    );
                    fields.push(("direction", "upstream-to-client".to_string()));
                    fields.push(("bytes", payload.len().to_string()));
                    association
                        .events
                        .record(IngressEventKind::UdpDatagram, fields);
                }
                Ok(VlessUdpStep::Closed) => {
                    return Ok(UdpOutboundOutcome {
                        upstream: parts.upstream,
                        close_reason: "inbound-closed",
                    });
                }
                Ok(VlessUdpStep::ReadError(error)) => {
                    return Err(vless_error(error, Some(parts.upstream)));
                }
                Err(_) => {
                    return Ok(UdpOutboundOutcome {
                        upstream: parts.upstream,
                        close_reason: "idle-timeout",
                    });
                }
            }
        }
    }
}

fn vless_error(error: vless_prototype::Error, upstream: Option<SocketAddr>) -> OutboundError {
    OutboundError {
        stage: error.stage(),
        upstream,
        message: error.to_string(),
    }
}

enum VlessUdpStep {
    Downstream(Vec<u8>),
    Upstream(Vec<u8>),
    Closed,
    ReadError(vless_prototype::Error),
}

async fn vless_udp_step(
    downstream_rx: &mut mpsc::Receiver<Vec<u8>>,
    reader: &mut VlessUdpReader,
) -> VlessUdpStep {
    tokio::select! {
        payload = downstream_rx.recv() => match payload {
            Some(payload) => VlessUdpStep::Downstream(payload),
            None => VlessUdpStep::Closed,
        },
        result = reader.read_datagram() => match result {
            Ok(payload) => VlessUdpStep::Upstream(payload),
            Err(error) => VlessUdpStep::ReadError(error),
        },
    }
}
