use super::{ForwardNode, NodeId};

impl ForwardNode {
    pub fn new(id: impl Into<String>, tag: impl Into<String>, enabled: bool) -> Self {
        let id = NodeId::new(id);
        let fingerprint = format!("node-id:{}", id.as_str());
        Self {
            id,
            tag: tag.into(),
            enabled,
            fingerprint,
            supports_ipv6: true,
        }
    }

    pub fn with_fingerprint(
        id: impl Into<String>,
        tag: impl Into<String>,
        enabled: bool,
        fingerprint: impl Into<String>,
    ) -> Self {
        Self {
            id: NodeId::new(id),
            tag: tag.into(),
            enabled,
            fingerprint: fingerprint.into(),
            supports_ipv6: true,
        }
    }

    pub fn with_capabilities(mut self, supports_ipv6: bool) -> Self {
        self.supports_ipv6 = supports_ipv6;
        self
    }
}
