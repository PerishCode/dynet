use std::path::PathBuf;

use dynet_runtime::{
    ForwardGroup, ForwardNode, GroupId, GroupMember, GroupThresholds, InboundKind,
    IngressEventKind, NextRef, NodeId, RouteMatcher, RouteRule, RuleId, RuntimeSeed, RuntimeState,
    RuntimeStore, SchedulerPolicy, SelectionContext, TargetContext,
};

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
        .select(github_context(2))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-backup");
}

#[tokio::test]
async fn github_ignores_client_abort() {
    let runtime = runtime_from_seed(github_seed()).await;
    record_github_error(&runtime, "airport-primary", "client-aborted", 4096);
    record_target_success(
        &runtime,
        RecordedTarget {
            session_id: "2",
            decision_id: "2",
            node_id: "airport-backup",
            target_domain: "github.com",
            target_ip: "140.82.112.4",
        },
    );

    let stats = runtime.matrix_target_node_stats();
    let primary = stats
        .iter()
        .find(|stats| stats.node_id == "airport-primary")
        .expect("primary stats");
    assert_eq!(primary.error_count, 1);
    assert_eq!(primary.effective_error_count, 0);
    assert_eq!(primary.effective_error_rate_ppm, 0);

    let decision = runtime
        .select(github_context(3))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-primary");
}

#[tokio::test]
async fn github_softens_interrupted_response() {
    let runtime = runtime_from_seed(github_seed()).await;
    record_github_error(&runtime, "airport-primary", "response-interrupted", 4096);
    record_target_success(
        &runtime,
        RecordedTarget {
            session_id: "2",
            decision_id: "2",
            node_id: "airport-backup",
            target_domain: "github.com",
            target_ip: "140.82.112.4",
        },
    );

    let stats = runtime.matrix_target_node_stats();
    let primary = stats
        .iter()
        .find(|stats| stats.node_id == "airport-primary")
        .expect("primary stats");
    assert_eq!(primary.error_count, 1);
    assert_eq!(primary.effective_error_count, 1);
    assert_eq!(primary.effective_error_rate_ppm, 250_000);

    let decision = runtime
        .select(github_context(3))
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
    record_target_success(
        &runtime,
        RecordedTarget {
            session_id: "2",
            decision_id: "2",
            node_id: "airport-backup",
            target_domain: "github.com",
            target_ip: "140.82.112.4",
        },
    );

    let decision = runtime
        .select(github_context(3))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-primary");
}

#[tokio::test]
async fn github_probe_unknown() {
    let runtime = runtime_from_seed(github_seed()).await;
    record_target_success(
        &runtime,
        RecordedTarget {
            session_id: "1",
            decision_id: "1",
            node_id: "airport-primary",
            target_domain: "github.com",
            target_ip: "140.82.112.4",
        },
    );

    let decision = runtime
        .select(github_context(2))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-backup");
}

#[tokio::test]
async fn github_cools_node() {
    let runtime = runtime_from_seed(github_seed()).await;
    record_target_error(
        &runtime,
        RecordedTarget {
            session_id: "1",
            decision_id: "1",
            node_id: "airport-primary",
            target_domain: "avatars.githubusercontent.com",
            target_ip: "185.199.108.133",
        },
        "connect-failed",
        0,
    );

    let decision = runtime
        .select(github_context(2))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-backup");
}

#[tokio::test]
async fn github_node_beats_target() {
    let runtime = runtime_from_seed(github_seed()).await;
    record_target_success(
        &runtime,
        RecordedTarget {
            session_id: "1",
            decision_id: "1",
            node_id: "airport-primary",
            target_domain: "github.com",
            target_ip: "140.82.112.4",
        },
    );
    record_target_error(
        &runtime,
        RecordedTarget {
            session_id: "2",
            decision_id: "2",
            node_id: "airport-primary",
            target_domain: "avatars.githubusercontent.com",
            target_ip: "185.199.108.133",
        },
        "connect-failed",
        0,
    );

    let decision = runtime
        .select(github_context(3))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-backup");
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
        .select(github_context(2))
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "GitHub");
    assert_eq!(decision.node_id.as_str(), "airport-backup");
}

fn record_github_error(
    runtime: &RuntimeState,
    node_id: &'static str,
    error_class: &'static str,
    upstream_to_client_bytes: u64,
) {
    record_target_error(
        runtime,
        RecordedTarget {
            session_id: "1",
            decision_id: "1",
            node_id,
            target_domain: "github.com",
            target_ip: "140.82.112.4",
        },
        error_class,
        upstream_to_client_bytes,
    );
}

#[derive(Clone, Copy)]
struct RecordedTarget {
    session_id: &'static str,
    decision_id: &'static str,
    node_id: &'static str,
    target_domain: &'static str,
    target_ip: &'static str,
}

fn record_target_success(runtime: &RuntimeState, target: RecordedTarget) {
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", target.session_id.to_string()),
            ("decisionId", target.decision_id.to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", target.target_domain.to_string()),
            ("targetIp", target.target_ip.to_string()),
            ("selectionGroups", "GitHub".to_string()),
            ("selectionNodes", target.node_id.to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", target.session_id.to_string()),
            ("decisionId", target.decision_id.to_string()),
            ("inbound", "tcp".to_string()),
            ("clientToUpstreamBytes", "31".to_string()),
            ("upstreamToClientBytes", "37".to_string()),
            ("closeReason", "eof".to_string()),
        ],
    );
}

fn record_target_error(
    runtime: &RuntimeState,
    target: RecordedTarget,
    error_class: &'static str,
    upstream_to_client_bytes: u64,
) {
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", target.session_id.to_string()),
            ("decisionId", target.decision_id.to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", target.target_domain.to_string()),
            ("targetIp", target.target_ip.to_string()),
            ("selectionGroups", "GitHub".to_string()),
            ("selectionNodes", target.node_id.to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpError,
        [
            ("sessionId", target.session_id.to_string()),
            ("decisionId", target.decision_id.to_string()),
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
