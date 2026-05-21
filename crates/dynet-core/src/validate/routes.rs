use std::collections::BTreeMap;

use crate::{
    capability::transport_capabilities, node_supports_transport, normalize_domain,
    ConfigDiagnostic, DynetConfig, NetworkNode, RouteAction, RouteRule, Transport,
};

use super::{deny, node_index, validate_ip_cidr};

pub(super) fn validate_routes(config: &DynetConfig, diagnostics: &mut Vec<ConfigDiagnostic>) {
    let inbounds = node_index(&config.inbounds);
    let outbounds = node_index(&config.outbounds);

    for (index, route) in config.routes.iter().enumerate() {
        validate_matchers(index, route, diagnostics);
        let route_outbounds = validate_action(index, route, &outbounds, diagnostics);
        let inbound = route.inbound.as_deref().and_then(|inbound| {
            required_node(
                &inbounds,
                inbound,
                format!("routes[{index}].inbound"),
                "inbound",
                diagnostics,
            )
        });
        if let Some(inbound) = inbound {
            for outbound in route_outbounds {
                validate_transport(index, route.transport, inbound, outbound, diagnostics);
            }
        }
    }
}

fn validate_matchers(index: usize, route: &RouteRule, diagnostics: &mut Vec<ConfigDiagnostic>) {
    validate_domain_field(index, "domain", route.domain.as_deref(), diagnostics);
    validate_domain_field(
        index,
        "domainSuffix",
        route.domain_suffix.as_deref(),
        diagnostics,
    );
    if matches!(route.domain_keyword.as_deref(), Some(value) if value.trim().is_empty()) {
        diagnostics.push(deny(
            format!("routes[{index}].domainKeyword"),
            "route domain keyword must not be empty",
        ));
    }
    if let Some(ip_cidr) = &route.ip_cidr {
        validate_ip_cidr(
            format!("routes[{index}].ipCidr"),
            "route ipCidr",
            ip_cidr,
            diagnostics,
        );
    }
}

fn validate_domain_field(
    index: usize,
    field: &'static str,
    value: Option<&str>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    match value {
        Some(value) if normalize_domain(value).is_none() => diagnostics.push(deny(
            format!("routes[{index}].{field}"),
            format!("route {field} must not be empty"),
        )),
        _ => {}
    }
}

fn validate_action<'a>(
    index: usize,
    route: &RouteRule,
    outbounds: &'a BTreeMap<&str, &'a NetworkNode>,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Vec<&'a NetworkNode> {
    if route.action == Some(RouteAction::Reject) {
        if route.outbound.is_some() {
            diagnostics.push(deny(
                format!("routes[{index}]"),
                "route action reject must not also set outbound",
            ));
        }
        return Vec::new();
    }

    if let Some(outbound) = route.outbound.as_deref() {
        return required_node(
            outbounds,
            outbound,
            format!("routes[{index}].outbound"),
            "outbound",
            diagnostics,
        )
        .into_iter()
        .collect();
    }

    diagnostics.push(deny(
        format!("routes[{index}]"),
        "route must set outbound or action reject",
    ));
    Vec::new()
}

fn required_node<'a>(
    nodes: &'a BTreeMap<&str, &'a NetworkNode>,
    tag: &str,
    path: String,
    role: &str,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) -> Option<&'a NetworkNode> {
    if tag.trim().is_empty() {
        diagnostics.push(deny(path, format!("route {role} must not be empty")));
        return None;
    }
    match nodes.get(tag) {
        Some(node) => Some(*node),
        None => {
            diagnostics.push(deny(
                path,
                format!("route references unknown {role} `{tag}`"),
            ));
            None
        }
    }
}

fn validate_transport(
    index: usize,
    route_transport: Option<Transport>,
    inbound: &NetworkNode,
    outbound: &NetworkNode,
    diagnostics: &mut Vec<ConfigDiagnostic>,
) {
    if let Some(transport) = route_transport {
        if !node_supports_transport(inbound, transport) {
            diagnostics.push(deny(
                format!("routes[{index}].transport"),
                format!(
                    "route transport `{}` is not supported by inbound `{}`",
                    transport_label(transport),
                    inbound.tag
                ),
            ));
        }
        if !node_supports_transport(outbound, transport) {
            diagnostics.push(deny(
                format!("routes[{index}].transport"),
                format!(
                    "route transport `{}` is not supported by outbound `{}`",
                    transport_label(transport),
                    outbound.tag
                ),
            ));
        }
        return;
    }

    let inbound_transport = transport_capabilities(inbound);
    let outbound_transport = transport_capabilities(outbound);
    if inbound_transport.is_empty() || outbound_transport.is_empty() {
        return;
    }
    if inbound_transport.is_disjoint(&outbound_transport) {
        diagnostics.push(deny(
            format!("routes[{index}]"),
            format!(
                "route maps inbound `{}` to outbound `{}` with no shared tcp/udp capability",
                inbound.tag, outbound.tag
            ),
        ));
    }
}

fn transport_label(transport: Transport) -> &'static str {
    match transport {
        Transport::Tcp => "tcp",
        Transport::Udp => "udp",
        Transport::Dns => "dns",
    }
}
