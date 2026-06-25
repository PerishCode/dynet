use std::{net::SocketAddr, path::PathBuf, time::Duration};

use dynet_runtime::{
    InboundKind, IngressEventKind, RuntimeSeed, RuntimeState, RuntimeStore, SelectionContext,
    TargetContext,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    SqlitePool,
};
use tempfile::TempDir;
use tokio::time;

#[tokio::test]
async fn restart_hydrates_matrix() {
    let fixture = StoreFixture::open().await;
    let runtime =
        RuntimeState::from_store_seed(fixture.store.clone(), RuntimeSeed::single_node("direct"))
            .await
            .expect("runtime state");

    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "7".to_string()),
            ("decisionId", "7".to_string()),
            ("inbound", "tcp".to_string()),
            ("nodeProtocol", "direct".to_string()),
            ("target", "203.0.113.10:443".to_string()),
            ("targetIp", "203.0.113.10".to_string()),
            ("targetPort", "443".to_string()),
            ("targetDomain", "example.test".to_string()),
            ("targetSource", "external-context".to_string()),
            ("selectionGroups", "default".to_string()),
            ("selectionNodes", "default-node".to_string()),
            ("selectionTrace", "default:default-node->direct".to_string()),
        ],
    );
    runtime.events().record(
        IngressEventKind::TcpClose,
        [
            ("sessionId", "7".to_string()),
            ("decisionId", "7".to_string()),
            ("inbound", "tcp".to_string()),
            ("clientToUpstreamBytes", "55".to_string()),
            ("upstreamToClientBytes", "89".to_string()),
            ("closeReason", "eof".to_string()),
        ],
    );
    runtime
        .select(selection_context(7))
        .expect("selection succeeds");

    fixture.wait_for_count("runtime_traffic_sessions", 1).await;
    fixture.wait_for_count("matrix_shadow_decisions", 1).await;

    let restarted =
        RuntimeState::from_store_seed(fixture.store.clone(), RuntimeSeed::single_node("changed"))
            .await
            .expect("restarted runtime state");

    let sessions = restarted.matrix().traffic_sessions();
    assert_eq!(sessions.len(), 1);
    assert_eq!(sessions[0].session_key, "tcp:7:7");
    assert_eq!(sessions[0].close_reason.as_deref(), Some("eof"));

    let stats = restarted.matrix_node_stats();
    let default_stats = stats
        .iter()
        .find(|stats| stats.group_id == "default" && stats.node_id == "default-node")
        .expect("default node stats");
    assert_eq!(default_stats.session_count, 1);
    assert_eq!(default_stats.success_count, 1);
    assert_eq!(default_stats.error_count, 0);
    assert_eq!(default_stats.active_session_count, 0);
    assert_eq!(default_stats.client_to_upstream_bytes, 55);
    assert_eq!(default_stats.upstream_to_client_bytes, 89);

    let target_stats = restarted.matrix_target_node_stats();
    assert!(target_stats.iter().any(|stats| {
        stats.group_id == "default"
            && stats.node_id == "default-node"
            && stats.target_scope == "domain"
            && stats.target_value == "example.test"
            && stats.success_count == 1
    }));

    let shadows = restarted.matrix().shadow_decisions();
    assert_eq!(shadows.len(), 1);
    assert_eq!(shadows[0].decision_id, 1);
    assert_eq!(shadows[0].actual_node_id, "default-node");
}

#[tokio::test]
async fn restart_skips_active() {
    let fixture = StoreFixture::open().await;
    let runtime =
        RuntimeState::from_store_seed(fixture.store.clone(), RuntimeSeed::single_node("direct"))
            .await
            .expect("runtime state");

    runtime.events().record(
        IngressEventKind::TcpAccept,
        [
            ("sessionId", "9".to_string()),
            ("decisionId", "9".to_string()),
            ("inbound", "tcp".to_string()),
            ("nodeProtocol", "direct".to_string()),
            ("target", "203.0.113.11:443".to_string()),
            ("targetIp", "203.0.113.11".to_string()),
            ("targetPort", "443".to_string()),
            ("targetSource", "external-context".to_string()),
            ("selectionGroups", "default".to_string()),
            ("selectionNodes", "default-node".to_string()),
            ("selectionTrace", "default:default-node->direct".to_string()),
        ],
    );

    fixture.wait_for_count("runtime_traffic_sessions", 1).await;

    let restarted =
        RuntimeState::from_store_seed(fixture.store.clone(), RuntimeSeed::single_node("changed"))
            .await
            .expect("restarted runtime state");

    assert!(restarted.matrix().traffic_sessions().is_empty());
    assert!(restarted.matrix_node_stats().is_empty());
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
        let row = sqlx::query_scalar::<_, i64>(&query)
            .fetch_one(&self.inspector)
            .await
            .expect("count rows");
        row
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
