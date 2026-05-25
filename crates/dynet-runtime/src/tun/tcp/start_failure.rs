use std::net::SocketAddr;

pub(in crate::tun) struct SessionStartFailure {
    pub(in crate::tun) error: String,
    pub(in crate::tun) session: Option<usize>,
    pub(in crate::tun) target: Option<SocketAddr>,
    pub(in crate::tun) client: Option<SocketAddr>,
    pub(in crate::tun) outbound: Option<String>,
    pub(in crate::tun) stage: Option<SessionStartFailureStage>,
}

impl SessionStartFailure {
    pub(in crate::tun) fn unattributed(error: impl Into<String>) -> Self {
        Self {
            error: error.into(),
            session: None,
            target: None,
            client: None,
            outbound: None,
            stage: None,
        }
    }

    pub(in crate::tun) fn session_scoped(
        error: impl Into<String>,
        session: usize,
        target: SocketAddr,
        client: SocketAddr,
    ) -> Self {
        Self {
            error: error.into(),
            session: Some(session),
            target: Some(target),
            client: Some(client),
            outbound: None,
            stage: None,
        }
    }

    pub(in crate::tun) fn outbound_scoped(
        error: impl Into<String>,
        session: usize,
        target: SocketAddr,
        client: SocketAddr,
        outbound: impl Into<String>,
    ) -> Self {
        Self {
            error: error.into(),
            session: Some(session),
            target: Some(target),
            client: Some(client),
            outbound: Some(outbound.into()),
            stage: None,
        }
    }

    pub(in crate::tun) fn with_stage(mut self, stage: Option<SessionStartFailureStage>) -> Self {
        self.stage = stage;
        self
    }
}

#[derive(Clone)]
pub(in crate::tun) struct SessionStartFailureStage {
    pub(in crate::tun) stage: String,
    pub(in crate::tun) outbound: String,
    pub(in crate::tun) kind: String,
    pub(in crate::tun) error_type: String,
    pub(in crate::tun) error_disposition: String,
}
