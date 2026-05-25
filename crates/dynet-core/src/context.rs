use std::net::IpAddr;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundContext {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbound: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transport: Option<Transport>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_domain: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_ip: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub destination_port: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quality_scope: Option<QualityScope>,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Transport {
    Tcp,
    Udp,
    Dns,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum QualityScope {
    PlanCandidate,
    DialerBound,
}

impl QualityScope {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::PlanCandidate => "plan-candidate",
            Self::DialerBound => "dialer-bound",
        }
    }
}

impl InboundContext {
    pub fn any() -> Self {
        Self::default()
    }

    pub fn from_inbound(tag: impl Into<String>) -> Self {
        Self {
            inbound: Some(tag.into()),
            transport: None,
            destination_domain: None,
            destination_ip: None,
            destination_port: None,
            quality_scope: None,
        }
    }

    pub fn with_transport(mut self, transport: Transport) -> Self {
        self.transport = Some(transport);
        self
    }

    pub fn with_destination_domain(mut self, domain: impl Into<String>) -> Self {
        self.destination_domain = Some(domain.into());
        self
    }

    pub fn with_destination_ip(mut self, address: IpAddr) -> Self {
        self.destination_ip = Some(address);
        self
    }

    pub fn with_destination_port(mut self, port: u16) -> Self {
        self.destination_port = Some(port);
        self
    }

    pub fn with_quality_scope(mut self, scope: QualityScope) -> Self {
        self.quality_scope = Some(scope);
        self
    }
}
