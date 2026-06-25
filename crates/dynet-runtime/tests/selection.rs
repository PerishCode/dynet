use std::net::SocketAddr;

use dynet_runtime::{
    InboundKind, IngressEventKind, RuntimeState, SchedulerPolicy, SelectionContext,
    SelectionReason, SelectionTerminal, TargetContext,
};

#[test]
fn selects_default_node() {
    let runtime = RuntimeState::single_node("ss");
    let decision = runtime
        .select(selection_context(1))
        .expect("selection succeeds");

    assert_eq!(decision.node_id.as_str(), "default-node");
    assert_eq!(decision.group_id.as_str(), "default");
    assert_eq!(decision.matched_rule_id, None);
    assert_eq!(decision.reason, SelectionReason::SingleNode);
    assert_eq!(decision.scheduler, SchedulerPolicy::SingleFirstEnabled);
    assert_eq!(decision.candidate_count, 1);
    assert_eq!(decision.trace.len(), 1);
    assert_eq!(decision.trace[0].group_id.as_str(), "default");
    assert_eq!(decision.trace[0].node_id.as_str(), "default-node");
    assert_eq!(decision.trace[0].next.label(), "direct");
    assert_eq!(decision.terminal, SelectionTerminal::DirectAuditOutlet);
    assert_eq!(decision.decision_id, 1);
    let shadows = runtime.matrix().shadow_decisions();
    assert_eq!(shadows.len(), 1);
    assert_eq!(shadows[0].decision_id, 1);
    assert_eq!(shadows[0].session_id, 1);
    assert_eq!(shadows[0].actual_node_id, "default-node");
    assert_eq!(
        shadows[0].shadow_top_node_id.as_deref(),
        Some("default-node")
    );
    assert!(!shadows[0].shadow_differs_from_actual);
    assert_eq!(shadows[0].candidates.len(), 1);
    assert_eq!(
        shadows[0].candidates[0].reason,
        "stats-balanced-shadow:no-history"
    );
    assert_eq!(runtime.nodes().snapshot()[0].tag, "ss");
    assert_eq!(runtime.groups().snapshot()[0].id.as_str(), "default");
    assert_eq!(
        runtime.groups().member_snapshot()[0].node_id.as_str(),
        "default-node"
    );
    assert_eq!(runtime.dns_upstreams().snapshot().len(), 2);
}

#[test]
fn increments_decision_id() {
    let runtime = RuntimeState::default();
    let first = runtime
        .select(selection_context(1))
        .expect("first selection");
    let second = runtime
        .select(selection_context(2))
        .expect("second selection");

    assert_eq!(first.decision_id, 1);
    assert_eq!(second.decision_id, 2);
}

#[test]
fn shadow_scoring_uses_stats() {
    let runtime = RuntimeState::default();
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("selectionGroups", "default".to_string()),
            ("selectionNodes", "default-node".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("clientToUpstreamBytes", "31".to_string()),
            ("upstreamToClientBytes", "37".to_string()),
            ("closeReason", "eof".to_string()),
        ],
    );

    let stats = runtime.matrix_node_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].group_id, "default");
    assert_eq!(stats[0].node_id, "default-node");
    assert_eq!(stats[0].node_fingerprint, "node-id:default-node");
    assert_eq!(stats[0].session_count, 1);
    assert_eq!(stats[0].success_count, 1);

    runtime
        .select(selection_context(2))
        .expect("selection succeeds");
    let shadow = runtime.matrix().shadow_decisions();
    assert_eq!(shadow[0].shadow_reason, "stats-balanced-shadow");
    assert_eq!(
        shadow[0].candidates[0].reason,
        "stats-balanced-shadow:sessions=1,errors=0,effectiveErrors=0,active=0,latencyMs=none"
    );
}

#[test]
fn target_stats_group_local() {
    let runtime = RuntimeState::default();
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "GitHub.com".to_string()),
            ("targetIp", "140.82.112.4".to_string()),
            ("selectionGroups", "default".to_string()),
            ("selectionNodes", "default-node".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("clientToUpstreamBytes", "31".to_string()),
            ("upstreamToClientBytes", "37".to_string()),
            ("closeReason", "eof".to_string()),
        ],
    );

    let stats = runtime.matrix_target_node_stats();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].group_id, "default");
    assert_eq!(stats[0].node_id, "default-node");
    assert_eq!(stats[0].node_fingerprint, "node-id:default-node");
    assert_eq!(stats[0].target_scope, "domain");
    assert_eq!(stats[0].target_value, "github.com");
    assert_eq!(stats[0].session_count, 1);

    runtime
        .select(SelectionContext {
            session_id: 2,
            inbound: InboundKind::Tcp,
            target: TargetContext::external_context(
                "140.82.112.4:443".parse().expect("socket address"),
                Some("github.com".to_string()),
            ),
        })
        .expect("selection succeeds");
    let shadow = runtime.matrix().shadow_decisions();
    assert_eq!(
        shadow[0].candidates[0].reason,
        "stats-balanced-shadow:target=domain:github.com,sessions=1,errors=0,effectiveErrors=0,active=0,latencyMs=none"
    );
}

fn selection_context(session_id: u64) -> SelectionContext {
    SelectionContext {
        session_id,
        inbound: InboundKind::Tcp,
        target: TargetContext::fixed_upstream(SocketAddr::from(([127, 0, 0, 1], 80))),
    }
}
