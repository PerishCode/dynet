use std::net::SocketAddr;

use tokio::{io, sync::mpsc, time};

use vless_prototype::{
    Client as VlessClient, ClientConfig as VlessClientConfig, UdpReader as VlessUdpReader,
};

use crate::{
    egress::{
        DirectEgress, EgressError, EgressNode, TcpDialTarget, TcpDialer, TcpRelayOutcome,
        TcpRelaySession, UdpRelayAssociation, UdpRelayOutcome,
    },
    push_decision_fields, session_fields, IngressEventKind, VlessConfig,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VlessEgress {
    client: VlessClient,
}

impl VlessEgress {
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

    pub(super) async fn handle_tcp_via_dialer<D>(
        &self,
        mut session: TcpRelaySession,
        dialer: &D,
    ) -> Result<TcpRelayOutcome, EgressError>
    where
        D: TcpDialer,
    {
        let upstream = dialer
            .dial_tcp(TcpDialTarget::host(
                self.client.server_host(),
                self.client.server_port(),
            ))
            .await?;
        let (parts, mut upstream) = self
            .client
            .connect_tcp_with_stream(session.target, upstream)
            .await
            .map_err(|error| vless_error(error, None))?;
        let (client_to_upstream, upstream_to_client) =
            io::copy_bidirectional(&mut session.downstream, &mut upstream)
                .await
                .map_err(|error| EgressError {
                    stage: "relay",
                    upstream: Some(parts.upstream),
                    message: format!("VLESS TCP relay failed: {error}"),
                })?;
        Ok(TcpRelayOutcome {
            upstream: parts.upstream,
            client_to_upstream_bytes: client_to_upstream,
            upstream_to_client_bytes: upstream_to_client,
            close_reason: "normal",
        })
    }
}

impl EgressNode for VlessEgress {
    fn tag(&self) -> &'static str {
        self.tag()
    }

    async fn handle_tcp(&self, session: TcpRelaySession) -> Result<TcpRelayOutcome, EgressError> {
        self.handle_tcp_via_dialer(session, &DirectEgress).await
    }

    async fn handle_udp(
        &self,
        mut association: UdpRelayAssociation,
    ) -> Result<UdpRelayOutcome, EgressError> {
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
                        .send_to_peer(&payload, association.peer)
                        .await
                        .map_err(|error| EgressError {
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
                    push_decision_fields(&mut fields, &association.decision);
                    fields.push(("direction", "upstream-to-client".to_string()));
                    fields.push((
                        "bytes",
                        association.downstream.payload_len(&payload).to_string(),
                    ));
                    association
                        .runtime
                        .events()
                        .record(IngressEventKind::UdpDatagram, fields);
                }
                Ok(VlessUdpStep::Closed) => {
                    return Ok(UdpRelayOutcome {
                        upstream: parts.upstream,
                        close_reason: "inbound-closed",
                    });
                }
                Ok(VlessUdpStep::ReadError(error)) => {
                    return Err(vless_error(error, Some(parts.upstream)));
                }
                Err(_) => {
                    return Ok(UdpRelayOutcome {
                        upstream: parts.upstream,
                        close_reason: "idle-timeout",
                    });
                }
            }
        }
    }
}

fn vless_error(error: vless_prototype::Error, upstream: Option<SocketAddr>) -> EgressError {
    EgressError {
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
