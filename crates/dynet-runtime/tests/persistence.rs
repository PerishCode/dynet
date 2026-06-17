use std::{net::SocketAddr, path::PathBuf, time::Duration};

use dynet_runtime::{
    ForwardGroup, ForwardNode, GroupId, GroupMember, InboundKind, IngressEventKind, NextRef,
    NodeId, RuntimeSeed, RuntimeState, RuntimeStore, SchedulerPolicy, SelectionContext,
    TargetContext,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, SqlitePool,
};
use tempfile::TempDir;
use tokio::time;

#[tokio::test]
async fn seeds_default_bootstrap() {
    let fixture = StoreFixture::open().await;

    let runtime =
        RuntimeState::from_store_seed(fixture.store.clone(), RuntimeSeed::single_node("ss"))
            .await
            .expect("runtime state");

    assert_eq!(fixture.count_rows("runtime_nodes").await, 1);
    assert_eq!(fixture.count_rows("runtime_forward_groups").await, 1);
    assert_eq!(fixture.count_rows("runtime_group_members").await, 1);
    assert_eq!(fixture.count_rows("runtime_dns_upstreams").await, 2);
    assert_eq!(fixture.count_rows("runtime_route_rules").await, 0);
    let nodes = runtime.nodes().snapshot();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id.as_str(), "default-node");
    assert_eq!(nodes[0].tag, "ss");
    assert_eq!(runtime.groups().snapshot()[0].id.as_str(), "default");
    assert_eq!(runtime.groups().snapshot()[0].next.label(), "direct");
    assert_eq!(
        runtime.groups().member_snapshot()[0].node_id.as_str(),
        "default-node"
    );
    assert_eq!(runtime.dns_upstreams().snapshot().len(), 2);
    assert_eq!(runtime.dns_policy().timeout, Duration::from_secs(2));
    assert_eq!(runtime.dns_policy().strategy.as_str(), "parallel");
}

#[tokio::test]
async fn hydrates_existing_bootstrap() {
    let fixture = StoreFixture::open().await;
    fixture.insert_complete_bootstrap("persisted").await;

    let runtime = RuntimeState::from_store_seed(
        fixture.store.clone(),
        RuntimeSeed::single_node("config-changed"),
    )
    .await
    .expect("runtime state");

    assert_eq!(fixture.count_rows("runtime_nodes").await, 1);
    let nodes = runtime.nodes().snapshot();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].tag, "persisted");
}

#[tokio::test]
async fn restart_keeps_store_node() {
    let fixture = StoreFixture::open().await;
    RuntimeState::from_store_seed(
        fixture.store.clone(),
        RuntimeSeed::single_node("first-config"),
    )
    .await
    .expect("initial runtime state");

    let runtime = RuntimeState::from_store_seed(
        fixture.store.clone(),
        RuntimeSeed::single_node("changed-config"),
    )
    .await
    .expect("restarted runtime state");

    assert_eq!(fixture.count_rows("runtime_nodes").await, 1);
    let nodes = runtime.nodes().snapshot();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].tag, "first-config");
}

#[tokio::test]
async fn rejects_partial_old_shape() {
    let fixture = StoreFixture::open().await;
    fixture.insert_node_only("partial").await;

    let error =
        RuntimeState::from_store_seed(fixture.store.clone(), RuntimeSeed::single_node("config"))
            .await
            .expect_err("partial bootstrap rejected");

    assert!(
        error.to_string().contains("bootstrap is invalid"),
        "unexpected error: {error}"
    );
}

#[tokio::test]
async fn persists_observations() {
    let fixture = StoreFixture::open().await;
    let runtime =
        RuntimeState::from_store_seed(fixture.store.clone(), RuntimeSeed::single_node("direct"))
            .await
            .expect("runtime state");

    runtime.events().record(
        IngressEventKind::TcpAccept,
        [("sessionId", "1".to_string())],
    );
    runtime
        .select(selection_context(1))
        .expect("selection succeeds");

    fixture.wait_for_count("runtime_events", 1).await;
    fixture.wait_for_count("selection_decisions", 1).await;
    let decision = fixture.selection_decision().await;
    assert_eq!(decision.group_id, "default");
    assert_eq!(decision.node_id, "default-node");
    assert_eq!(decision.next, "direct");
    assert_eq!(decision.reason, "single-node");
    assert_eq!(decision.scheduler, "single-first-enabled");
    assert_eq!(decision.candidate_count, 1);
    assert_eq!(runtime.persistence_stats().dropped_observations, 0);
    assert_eq!(runtime.persistence_stats().sink_errors, 0);
}

#[tokio::test]
async fn seeds_group_next_graph() {
    let fixture = StoreFixture::open().await;

    let runtime = RuntimeState::from_store_seed(fixture.store.clone(), tunnel_seed())
        .await
        .expect("runtime state");

    let groups = runtime.groups().snapshot();
    let tunnel = groups
        .iter()
        .find(|group| group.id.as_str() == "Tunnel")
        .expect("Tunnel group");
    let private = groups
        .iter()
        .find(|group| group.id.as_str() == "Private")
        .expect("Private group");
    assert_eq!(tunnel.next.label(), "Private");
    assert_eq!(private.next.label(), "direct");

    let row = sqlx::query("select next from runtime_forward_groups where id = 'Tunnel'")
        .fetch_one(&fixture.inspector)
        .await
        .expect("stored Tunnel group");
    assert_eq!(row.get::<String, _>("next"), "Private");

    let decision = runtime
        .select(selection_context(1))
        .expect("graph selection succeeds");
    assert_eq!(decision.group_id.as_str(), "Tunnel");
    assert_eq!(decision.node_id.as_str(), "airport-us-01");
    assert_eq!(decision.next.label(), "Private");
    assert_eq!(decision.trace.len(), 2);
    assert_eq!(decision.trace[0].label(), "Tunnel:airport-us-01->Private");
    assert_eq!(
        decision.trace[1].label(),
        "Private:private-fixed-ip->direct"
    );
    assert_eq!(decision.terminal.kind(), "direct");
    assert_eq!(decision.terminal.label(), "direct");
}

#[tokio::test]
async fn quick_fails_bad_path() {
    let directory = TempDir::new().expect("tempdir");
    let error = RuntimeStore::open(directory.path())
        .await
        .expect_err("store open fails");

    assert!(
        error.to_string().contains("sqlite runtime store error"),
        "unexpected error: {error}"
    );
}

struct StoreFixture {
    _directory: TempDir,
    store: RuntimeStore,
    inspector: SqlitePool,
}

impl StoreFixture {
    async fn open() -> Self {
        let directory = TempDir::new().expect("tempdir");
        let path = directory.path().join("runtime.sqlite");
        let store = RuntimeStore::open(&path).await.expect("runtime store");
        let inspector = open_inspector(path).await;
        Self {
            _directory: directory,
            store,
            inspector,
        }
    }

    async fn count_rows(&self, table: &str) -> i64 {
        let query = format!("select count(*) as count from {table}");
        let row = sqlx::query(&query)
            .fetch_one(&self.inspector)
            .await
            .expect("count rows");
        row.get::<i64, _>("count")
    }

    async fn wait_for_count(&self, table: &str, expected: i64) {
        for _ in 0..50 {
            if self.count_rows(table).await == expected {
                return;
            }
            time::sleep(Duration::from_millis(10)).await;
        }
        assert_eq!(self.count_rows(table).await, expected);
    }

    async fn insert_complete_bootstrap(&self, tag: &str) {
        self.insert_node_only(tag).await;
        sqlx::query(
            "insert into runtime_forward_groups (id, enabled, scheduler, next, updated_at_unix_ms)
             values ('default', 1, 'single-first-enabled', 'direct', 1)",
        )
        .execute(&self.inspector)
        .await
        .expect("insert group");
        sqlx::query(
            "insert into runtime_group_members (
                group_id, node_id, enabled, priority, updated_at_unix_ms
             )
             values ('default', 'default-node', 1, 0, 1)",
        )
        .execute(&self.inspector)
        .await
        .expect("insert member");
        sqlx::query(
            "insert into runtime_dns_upstreams (id, address, enabled, priority, updated_at_unix_ms)
             values ('cloudflare', '1.1.1.1:53', 1, 0, 1)",
        )
        .execute(&self.inspector)
        .await
        .expect("insert dns upstream");
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('default_group_id', 'default')",
        )
        .execute(&self.inspector)
        .await
        .expect("insert default group meta");
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('dns_race_strategy', 'parallel')",
        )
        .execute(&self.inspector)
        .await
        .expect("insert dns strategy meta");
        sqlx::query(
            "insert into runtime_meta (key, value)
             values ('dns_race_timeout_ms', '2000')",
        )
        .execute(&self.inspector)
        .await
        .expect("insert dns timeout meta");
    }

    async fn insert_node_only(&self, tag: &str) {
        sqlx::query(
            "insert into runtime_nodes (id, tag, enabled, updated_at_unix_ms)
             values ('default-node', ?1, 1, 1)",
        )
        .bind(tag)
        .execute(&self.inspector)
        .await
        .expect("insert node");
    }

    async fn selection_decision(&self) -> PersistedSelectionDecision {
        let row = sqlx::query(
            "select group_id, node_id, next, reason, scheduler, candidate_count
             from selection_decisions",
        )
        .fetch_one(&self.inspector)
        .await
        .expect("selection decision");
        PersistedSelectionDecision {
            group_id: row.get("group_id"),
            node_id: row.get("node_id"),
            next: row.get("next"),
            reason: row.get("reason"),
            scheduler: row.get("scheduler"),
            candidate_count: row.get("candidate_count"),
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
struct PersistedSelectionDecision {
    group_id: String,
    node_id: String,
    next: String,
    reason: String,
    scheduler: String,
    candidate_count: i64,
}

fn tunnel_seed() -> RuntimeSeed {
    RuntimeSeed {
        nodes: vec![
            ForwardNode {
                id: NodeId::new("airport-us-01"),
                tag: "ss".to_string(),
                enabled: true,
            },
            ForwardNode {
                id: NodeId::new("private-fixed-ip"),
                tag: "ss".to_string(),
                enabled: true,
            },
        ],
        default_group_id: GroupId::new("Tunnel"),
        groups: vec![
            ForwardGroup {
                id: GroupId::new("Tunnel"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                next: NextRef::named("Private"),
            },
            ForwardGroup {
                id: GroupId::new("Private"),
                enabled: true,
                scheduler: SchedulerPolicy::SingleFirstEnabled,
                next: NextRef::direct_audit_outlet(),
            },
        ],
        group_members: vec![
            GroupMember {
                group_id: GroupId::new("Tunnel"),
                node_id: NodeId::new("airport-us-01"),
                enabled: true,
                priority: 0,
            },
            GroupMember {
                group_id: GroupId::new("Private"),
                node_id: NodeId::new("private-fixed-ip"),
                enabled: true,
                priority: 0,
            },
        ],
        route_rules: Vec::new(),
        dns_upstreams: RuntimeSeed::single_node("direct").dns_upstreams,
        dns_policy: RuntimeSeed::single_node("direct").dns_policy,
    }
}

async fn open_inspector(path: PathBuf) -> SqlitePool {
    let options = SqliteConnectOptions::new().filename(path);
    SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(options)
        .await
        .expect("inspector pool")
}

fn selection_context(session_id: u64) -> SelectionContext {
    SelectionContext {
        session_id,
        inbound: InboundKind::Tcp,
        target: TargetContext::fixed_upstream(SocketAddr::from(([127, 0, 0, 1], 80))),
    }
}
