use std::net::SocketAddr;

use tokio::{sync::mpsc, time};

use vmess_prototype::{
    Client as VmessClient, ClientConfig as VmessClientConfig, UdpReader as VmessUdpReader,
};

use crate::{
    egress::{
        DirectEgress, EgressError, EgressNode, TcpDialTarget, TcpDialer, TcpRelayOutcome,
        TcpRelaySession, UdpRelayAssociation, UdpRelayOutcome,
    },
    push_decision_fields, session_fields, IngressEventKind, VmessConfig,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct VmessEgress {
    client: VmessClient,
}

impl VmessEgress {
    pub(crate) fn new(config: VmessConfig) -> Result<Self, String> {
        Ok(Self {
            client: VmessClient::try_new(VmessClientConfig {
                server: config.server,
                port: config.port,
                uuid: config.uuid,
            })
            .map_err(|error| error.to_string())?,
        })
    }

    fn tag(&self) -> &'static str {
        "vmess"
    }

    pub(super) async fn handle_tcp_via_dialer<D>(
        &self,
        session: TcpRelaySession,
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
        let outcome = self
            .client
            .relay_tcp_with_stream(session.downstream, session.target, upstream)
            .await
            .map_err(|error| vmess_error(error, None))?;
        Ok(TcpRelayOutcome {
            upstream: outcome.upstream,
            client_to_upstream_bytes: outcome.client_to_upstream_bytes,
            upstream_to_client_bytes: outcome.upstream_to_client_bytes,
            close_reason: "normal",
        })
    }
}

impl EgressNode for VmessEgress {
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
            .map_err(|error| vmess_error(error, None))?;
        loop {
            let step = time::timeout(
                association.idle_timeout,
                vmess_udp_step(&mut association.downstream_rx, &mut reader),
            )
            .await;
            match step {
                Ok(VmessUdpStep::Downstream(payload)) => {
                    writer
                        .write_datagram(&payload)
                        .await
                        .map_err(|error| vmess_error(error, Some(parts.upstream)))?;
                }
                Ok(VmessUdpStep::Upstream(payload)) => {
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
                Ok(VmessUdpStep::Closed) => {
                    return Ok(UdpRelayOutcome {
                        upstream: parts.upstream,
                        close_reason: "inbound-closed",
                    });
                }
                Ok(VmessUdpStep::ReadError(error)) => {
                    return Err(vmess_error(error, Some(parts.upstream)));
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

fn vmess_error(error: vmess_prototype::Error, upstream: Option<SocketAddr>) -> EgressError {
    EgressError {
        stage: error.stage(),
        upstream,
        message: error.to_string(),
    }
}

enum VmessUdpStep {
    Downstream(Vec<u8>),
    Upstream(Vec<u8>),
    Closed,
    ReadError(vmess_prototype::Error),
}

async fn vmess_udp_step(
    downstream_rx: &mut mpsc::Receiver<Vec<u8>>,
    reader: &mut VmessUdpReader,
) -> VmessUdpStep {
    tokio::select! {
        payload = downstream_rx.recv() => match payload {
            Some(payload) => VmessUdpStep::Downstream(payload),
            None => VmessUdpStep::Closed,
        },
        result = reader.read_datagram() => match result {
            Ok(payload) => VmessUdpStep::Upstream(payload),
            Err(error) => VmessUdpStep::ReadError(error),
        },
    }
}
