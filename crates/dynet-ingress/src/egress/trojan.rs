use std::net::SocketAddr;

use tokio::{sync::mpsc, time};

use trojan_prototype::{
    Client as TrojanClient, ClientConfig as TrojanClientConfig, UdpReader as TrojanUdpReader,
};

use crate::{
    egress::{
        DirectEgress, EgressError, EgressNode, TcpDialTarget, TcpDialer, TcpRelayOutcome,
        TcpRelaySession, UdpRelayAssociation, UdpRelayOutcome,
    },
    push_decision_fields, session_fields, IngressEventKind, TrojanConfig,
};

#[derive(Debug, Clone, Eq, PartialEq)]
pub(crate) struct TrojanEgress {
    client: TrojanClient,
}

impl TrojanEgress {
    pub(super) fn new(config: TrojanConfig) -> Self {
        Self {
            client: TrojanClient::new(TrojanClientConfig {
                server: config.server,
                port: config.port,
                password: config.password,
                sni: config.sni,
                skip_cert_verify: config.skip_cert_verify,
            }),
        }
    }

    fn tag(&self) -> &'static str {
        "trojan"
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
            .await?
            .into_tcp_stream(self.tag())?;
        let outcome = self
            .client
            .relay_tcp_with_stream(session.downstream, session.target, upstream)
            .await
            .map_err(|error| trojan_error(error, None))?;
        Ok(TcpRelayOutcome {
            upstream: outcome.upstream,
            client_to_upstream_bytes: outcome.client_to_upstream_bytes,
            upstream_to_client_bytes: outcome.upstream_to_client_bytes,
            close_reason: "normal",
        })
    }
}

impl EgressNode for TrojanEgress {
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
            .map_err(|error| trojan_error(error, None))?;
        loop {
            let step = time::timeout(
                association.idle_timeout,
                trojan_udp_step(&mut association.downstream_rx, &mut reader),
            )
            .await;
            match step {
                Ok(TrojanUdpStep::Downstream(payload)) => {
                    writer
                        .write_datagram(association.target, &payload)
                        .await
                        .map_err(|error| trojan_error(error, Some(parts.upstream)))?;
                }
                Ok(TrojanUdpStep::Upstream(payload)) => {
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
                Ok(TrojanUdpStep::Closed) => {
                    return Ok(UdpRelayOutcome {
                        upstream: parts.upstream,
                        close_reason: "inbound-closed",
                    });
                }
                Ok(TrojanUdpStep::ReadError(error)) => {
                    return Err(trojan_error(error, Some(parts.upstream)));
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

fn trojan_error(error: trojan_prototype::Error, upstream: Option<SocketAddr>) -> EgressError {
    EgressError {
        stage: error.stage(),
        upstream,
        message: error.to_string(),
    }
}

enum TrojanUdpStep {
    Downstream(Vec<u8>),
    Upstream(Vec<u8>),
    Closed,
    ReadError(trojan_prototype::Error),
}

async fn trojan_udp_step(
    downstream_rx: &mut mpsc::Receiver<Vec<u8>>,
    reader: &mut TrojanUdpReader,
) -> TrojanUdpStep {
    tokio::select! {
        payload = downstream_rx.recv() => match payload {
            Some(payload) => TrojanUdpStep::Downstream(payload),
            None => TrojanUdpStep::Closed,
        },
        result = reader.read_datagram() => match result {
            Ok(payload) => TrojanUdpStep::Upstream(payload),
            Err(error) => TrojanUdpStep::ReadError(error),
        },
    }
}
