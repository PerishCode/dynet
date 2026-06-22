use dynet_runtime::{DnsHttpsEndpoint, DnsUpstream, DnsUpstreamId, DnsUpstreamTransport};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct FileDnsUpstreamConfig {
    id: String,
    #[serde(rename = "type")]
    kind: String,
    address: String,
    host: Option<String>,
    path: Option<String>,
    enabled: Option<bool>,
    priority: Option<u32>,
}

impl FileDnsUpstreamConfig {
    pub(super) fn load(self) -> Result<DnsUpstream, String> {
        let id = super::non_empty("forwarding.dns_upstreams[].id", self.id.clone())?;
        let address = self.address.parse().map_err(|error| {
            format!("forwarding.dns_upstreams {id:?} address must be a socket address: {error}")
        })?;
        let transport = match self.kind.as_str() {
            "udp" => {
                if self.host.is_some() || self.path.is_some() {
                    return Err(format!(
                        "forwarding.dns_upstreams {id:?} host/path require type = \"https\""
                    ));
                }
                DnsUpstreamTransport::Udp
            }
            "https" | "doh" => self.load_https_transport(&id)?,
            _ => {
                return Err(format!(
                    "forwarding.dns_upstreams {id:?} type {:?} is unsupported",
                    self.kind
                ));
            }
        };
        Ok(DnsUpstream {
            id: DnsUpstreamId::new(id),
            address,
            transport,
            enabled: self.enabled.unwrap_or(true),
            priority: self.priority.unwrap_or(0),
        })
    }

    fn load_https_transport(&self, id: &str) -> Result<DnsUpstreamTransport, String> {
        let host = super::non_empty(
            "forwarding.dns_upstreams[].host",
            self.host
                .clone()
                .ok_or_else(|| format!("forwarding.dns_upstreams {id:?} host is required"))?,
        )?;
        let path = self
            .path
            .clone()
            .unwrap_or_else(|| "/dns-query".to_string());
        if !path.starts_with('/') {
            return Err(format!(
                "forwarding.dns_upstreams {id:?} path must start with '/'"
            ));
        }
        Ok(DnsUpstreamTransport::Https(DnsHttpsEndpoint { host, path }))
    }
}
