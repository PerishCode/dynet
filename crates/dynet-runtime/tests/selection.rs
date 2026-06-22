use std::{net::SocketAddr, path::PathBuf};

use dynet_runtime::{
    ForwardGroup, ForwardNode, GroupId, GroupMember, GroupThresholds, InboundKind,
    IngressEventKind, NextRef, NodeId, RouteMatcher, RouteRule, RuleId, RuntimeSeed, RuntimeState,
    RuntimeStore, SchedulerPolicy, SelectionContext, SelectionReason, SelectionTerminal,
    TargetContext,
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

#[tokio::test]
async fn github_cools_failed_target() {
    let runtime = runtime_from_seed(github_seed()).await;
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "github.com".to_string()),
            ("targetIp", "140.82.112.4".to_string()),
            ("selectionGroups", "GitHub".to_string()),
            ("selectionNodes", "airport-primary".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpError,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("errorStage", "dial".to_string()),
            ("error", "provider eof".to_string()),
        ],
    );

    let decision = runtime
        .select(SelectionContext {
            session_id: 2,
            inbound: InboundKind::Tcp,
            target: TargetContext::external_context(
                "140.82.112.4:443".parse().expect("socket address"),
                Some("github.com".to_string()),
            ),
        })
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-backup");
}

#[tokio::test]
async fn github_ignores_client_abort() {
    let runtime = runtime_from_seed(github_seed()).await;
    record_github_error(&runtime, "airport-primary", "client-aborted", 4096);

    let stats = runtime.matrix_target_node_stats();
    assert_eq!(stats[0].error_count, 1);
    assert_eq!(stats[0].effective_error_count, 0);
    assert_eq!(stats[0].effective_error_rate_ppm, 0);

    let decision = runtime
        .select(github_context(2))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-primary");
}

#[tokio::test]
async fn github_softens_interrupted_response() {
    let runtime = runtime_from_seed(github_seed()).await;
    record_github_error(&runtime, "airport-primary", "response-interrupted", 4096);

    let stats = runtime.matrix_target_node_stats();
    assert_eq!(stats[0].error_count, 1);
    assert_eq!(stats[0].effective_error_count, 1);
    assert_eq!(stats[0].effective_error_rate_ppm, 250_000);

    let decision = runtime
        .select(github_context(2))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-primary");
}

#[tokio::test]
async fn github_keeps_active_target() {
    let runtime = runtime_from_seed(github_seed()).await;
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "github.com".to_string()),
            ("targetIp", "140.82.112.4".to_string()),
            ("selectionGroups", "GitHub".to_string()),
            ("selectionNodes", "airport-primary".to_string()),
        ],
    );

    let decision = runtime
        .select(SelectionContext {
            session_id: 2,
            inbound: InboundKind::Tcp,
            target: TargetContext::external_context(
                "140.82.112.4:443".parse().expect("socket address"),
                Some("github.com".to_string()),
            ),
        })
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-primary");
}

fn record_github_error(
    runtime: &RuntimeState,
    node_id: &'static str,
    error_class: &'static str,
    upstream_to_client_bytes: u64,
) {
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "github.com".to_string()),
            ("targetIp", "140.82.112.4".to_string()),
            ("selectionGroups", "GitHub".to_string()),
            ("selectionNodes", node_id.to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpError,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("errorClass", error_class.to_string()),
            ("error", "synthetic browser outcome".to_string()),
            (
                "upstreamToClientBytes",
                upstream_to_client_bytes.to_string(),
            ),
        ],
    );
}

fn github_context(session_id: u64) -> SelectionContext {
    SelectionContext {
        session_id,
        inbound: InboundKind::Tcp,
        target: TargetContext::external_context(
            "140.82.112.4:443".parse().expect("socket address"),
            Some("github.com".to_string()),
        ),
    }
}

#[tokio::test]
async fn github_respects_active_cap() {
    let mut seed = github_seed();
    seed.groups[0].thresholds.max_active_sessions = Some(1);
    let runtime = runtime_from_seed(seed).await;
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "github.com".to_string()),
            ("targetIp", "140.82.112.4".to_string()),
            ("selectionGroups", "GitHub".to_string()),
            ("selectionNodes", "airport-primary".to_string()),
        ],
    );

    let decision = runtime
        .select(SelectionContext {
            session_id: 2,
            inbound: InboundKind::Tcp,
            target: TargetContext::external_context(
                "140.82.112.4:443".parse().expect("socket address"),
                Some("github.com".to_string()),
            ),
        })
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-backup");
}

#[tokio::test]
async fn private_stays_first_enabled() {
    let runtime = runtime_from_seed(private_seed()).await;
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "openai.com".to_string()),
            ("targetIp", "104.18.33.45".to_string()),
            ("selectionGroups", "Private".to_string()),
            ("selectionNodes", "private-primary".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpError,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("errorStage", "dial".to_string()),
            ("error", "provider eof".to_string()),
        ],
    );

    let decision = runtime
        .select(SelectionContext {
            session_id: 2,
            inbound: InboundKind::Tcp,
            target: TargetContext::external_context(
                "104.18.33.45:443".parse().expect("socket address"),
                Some("openai.com".to_string()),
            ),
        })
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "Private");
    assert_eq!(decision.node_id.as_str(), "private-primary");
}

fn selection_context(session_id: u64) -> SelectionContext {
    SelectionContext {
        session_id,
        inbound: InboundKind::Tcp,
        target: TargetContext::fixed_upstream(SocketAddr::from(([127, 0, 0, 1], 80))),
    }
}

async fn runtime_from_seed(seed: RuntimeSeed) -> RuntimeState {
    let directory = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = directory.path().join("runtime.sqlite");
    let store = RuntimeStore::open(&path).await.expect("store opens");
    RuntimeState::from_store_seed(store, seed)
        .await
        .expect("runtime from seed")
}

fn github_seed() -> RuntimeSeed {
    RuntimeSeed {
        nodes: vec![
            ForwardNode::new("airport-primary", "ss", true),
            ForwardNode::new("airport-backup", "ss", true),
        ],
        default_group_id: GroupId::new("GitHub"),
        groups: vec![ForwardGroup {
            id: GroupId::new("GitHub"),
            enabled: true,
            scheduler: SchedulerPolicy::SingleFirstEnabled,
            thresholds: GroupThresholds::default(),
            next: NextRef::direct_audit_outlet(),
        }],
        group_members: vec![
            GroupMember {
                group_id: GroupId::new("GitHub"),
                node_id: NodeId::new("airport-primary"),
                enabled: true,
                priority: 0,
            },
            GroupMember {
                group_id: GroupId::new("GitHub"),
                node_id: NodeId::new("airport-backup"),
                enabled: true,
                priority: 1,
            },
        ],
        route_rules: vec![RouteRule {
            id: RuleId::new("github"),
            priority: 100,
            enabled: true,
            matcher: RouteMatcher::DomainExact("github.com".to_string()),
            group_id: GroupId::new("GitHub"),
        }],
        dns_upstreams: RuntimeSeed::single_node("direct").dns_upstreams,
        dns_policy: RuntimeSeed::single_node("direct").dns_policy,
    }
}

fn private_seed() -> RuntimeSeed {
    RuntimeSeed {
        nodes: vec![
            ForwardNode::new("private-primary", "ss", true),
            ForwardNode::new("private-backup", "ss", true),
        ],
        default_group_id: GroupId::new("Private"),
        groups: vec![ForwardGroup {
            id: GroupId::new("Private"),
            enabled: true,
            scheduler: SchedulerPolicy::SingleFirstEnabled,
            thresholds: GroupThresholds::default(),
            next: NextRef::direct_audit_outlet(),
        }],
        group_members: vec![
            GroupMember {
                group_id: GroupId::new("Private"),
                node_id: NodeId::new("private-primary"),
                enabled: true,
                priority: 0,
            },
            GroupMember {
                group_id: GroupId::new("Private"),
                node_id: NodeId::new("private-backup"),
                enabled: true,
                priority: 1,
            },
        ],
        route_rules: Vec::new(),
        dns_upstreams: RuntimeSeed::single_node("direct").dns_upstreams,
        dns_policy: RuntimeSeed::single_node("direct").dns_policy,
    }
}
