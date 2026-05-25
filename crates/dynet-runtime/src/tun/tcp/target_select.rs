use std::net::SocketAddr;

use dynet_core::{node_capabilities, NetworkNode};

use crate::{outbound::TcpTarget, RuntimeEvent};

pub(crate) struct SelectedTcpTarget {
    pub(crate) target: TcpTarget,
    identity_domain: Option<String>,
    source: &'static str,
}

pub(crate) fn select(
    socket_target: SocketAddr,
    domains: &[String],
    decision_domain: Option<&str>,
    outbound: &NetworkNode,
) -> SelectedTcpTarget {
    let identity_domain = preferred_domain(domains, decision_domain);
    if should_use_domain(outbound) {
        if let Some(domain) = identity_domain.clone() {
            return SelectedTcpTarget {
                target: TcpTarget::Domain {
                    host: domain,
                    port: socket_target.port(),
                },
                identity_domain,
                source: domain_source(decision_domain),
            };
        }
    }
    SelectedTcpTarget {
        target: TcpTarget::Socket(socket_target),
        identity_domain,
        source: socket_source(outbound),
    }
}

pub(crate) fn annotate(mut event: RuntimeEvent, selected: &SelectedTcpTarget) -> RuntimeEvent {
    event = event
        .field("connectTarget", &selected.target)
        .field("targetAddressSource", selected.source);
    if let Some(domain) = &selected.identity_domain {
        event = event.field("identityDomain", domain);
    }
    event
}

fn preferred_domain(domains: &[String], decision_domain: Option<&str>) -> Option<String> {
    decision_domain
        .and_then(clean_domain)
        .or_else(|| domains.iter().find_map(|domain| clean_domain(domain)))
}

fn clean_domain(value: &str) -> Option<String> {
    let domain = value.trim().trim_end_matches('.').to_ascii_lowercase();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn should_use_domain(outbound: &NetworkNode) -> bool {
    outbound.kind != "direct"
        && node_capabilities(outbound)
            .iter()
            .any(|capability| capability == "domain-target")
}

fn domain_source(decision_domain: Option<&str>) -> &'static str {
    if decision_domain.and_then(clean_domain).is_some() {
        "dns-reverse-rule-domain"
    } else {
        "dns-reverse-domain"
    }
}

fn socket_source(outbound: &NetworkNode) -> &'static str {
    if outbound.kind == "direct" {
        "socket-ip-direct-preserved"
    } else {
        "socket-ip"
    }
}
