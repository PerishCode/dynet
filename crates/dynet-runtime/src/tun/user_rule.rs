use std::net::SocketAddr;

use dynet_core::{evaluate_rules, InboundContext, Transport, UserRuleDecision};

pub(super) fn select(
    policy: &crate::RuntimePolicy,
    transport: Transport,
    target: SocketAddr,
    domains: &[String],
) -> Option<(InboundContext, Option<String>, UserRuleDecision)> {
    let base = InboundContext::from_inbound("tun-in")
        .with_transport(transport)
        .with_destination_ip(target.ip())
        .with_destination_port(target.port());
    if let Some(decision) = evaluate_rules(&policy.state, &base) {
        return Some((base, None, decision));
    }
    for domain in domains {
        let context = base.clone().with_destination_domain(domain.clone());
        if let Some(decision) = evaluate_rules(&policy.state, &context) {
            return Some((context, Some(domain.clone()), decision));
        }
    }
    None
}
