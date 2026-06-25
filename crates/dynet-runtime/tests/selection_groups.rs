use std::path::PathBuf;

use dynet_runtime::{
    ForwardGroup, ForwardNode, GroupId, GroupMember, GroupThresholds, InboundKind,
    IngressEventKind, NextRef, NodeId, RuntimeSeed, RuntimeState, RuntimeStore, SchedulerPolicy,
    SelectionContext, TargetContext,
};

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

#[tokio::test]
async fn tunnel_cools_failed_upstream() {
    let runtime = runtime_from_seed(tunnel_seed()).await;
    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("targetDomain", "cloudflare-dns.com".to_string()),
            ("targetIp", "104.16.248.249".to_string()),
            ("selectionGroups", "Tunnel".to_string()),
            ("selectionNodes", "tunnel-primary".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpError,
        [
            ("sessionId", "1".to_string()),
            ("decisionId", "1".to_string()),
            ("inbound", "tcp".to_string()),
            ("errorClass", "connect-failed".to_string()),
            ("error", "synthetic tunnel upstream failure".to_string()),
        ],
    );

    let decision = runtime
        .select(SelectionContext {
            session_id: 2,
            inbound: InboundKind::Tcp,
            target: TargetContext::external_context(
                "104.16.248.249:443".parse().expect("socket address"),
                Some("cloudflare-dns.com".to_string()),
            ),
        })
        .expect("selection succeeds");

    assert_eq!(decision.group_id.as_str(), "Tunnel");
    assert_eq!(decision.node_id.as_str(), "tunnel-backup");
}

async fn runtime_from_seed(seed: RuntimeSeed) -> RuntimeState {
    let directory = tempfile::tempdir().expect("tempdir");
    let path: PathBuf = directory.path().join("runtime.sqlite");
    let store = RuntimeStore::open(&path).await.expect("store opens");
    RuntimeState::from_store_seed(store, seed)
        .await
        .expect("runtime from seed")
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

fn tunnel_seed() -> RuntimeSeed {
    RuntimeSeed {
        nodes: vec![
            ForwardNode::new("tunnel-primary", "ss", true),
            ForwardNode::new("tunnel-backup", "ss", true),
            ForwardNode::new("private-outlet", "ss", true),
        ],
        default_group_id: GroupId::new("Tunnel"),
        groups: vec![
            ForwardGroup {
                id: GroupId::new("Tunnel"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                thresholds: GroupThresholds::default(),
                next: NextRef::named("Private"),
            },
            ForwardGroup {
                id: GroupId::new("Private"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                thresholds: GroupThresholds::default(),
                next: NextRef::direct_audit_outlet(),
            },
        ],
        group_members: vec![
            GroupMember {
                group_id: GroupId::new("Tunnel"),
                node_id: NodeId::new("tunnel-primary"),
                enabled: true,
                priority: 0,
            },
            GroupMember {
                group_id: GroupId::new("Tunnel"),
                node_id: NodeId::new("tunnel-backup"),
                enabled: true,
                priority: 1,
            },
            GroupMember {
                group_id: GroupId::new("Private"),
                node_id: NodeId::new("private-outlet"),
                enabled: true,
                priority: 0,
            },
        ],
        route_rules: Vec::new(),
        dns_upstreams: RuntimeSeed::single_node("direct").dns_upstreams,
        dns_policy: RuntimeSeed::single_node("direct").dns_policy,
    }
}
