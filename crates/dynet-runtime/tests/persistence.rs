use std::{net::SocketAddr, path::PathBuf, time::Duration};

use dynet_runtime::{
    InboundKind, IngressEventKind, NodeId, OutboundNode, RuntimeState, RuntimeStore,
    SelectionContext, TargetContext,
};
use sqlx::{
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
    Row, SqlitePool,
};
use tempfile::TempDir;
use tokio::time;

#[tokio::test]
async fn seeds_default_node() {
    let fixture = StoreFixture::open().await;

    let runtime = RuntimeState::from_store_seed(fixture.store.clone(), "ss")
        .await
        .expect("runtime state");

    assert_eq!(fixture.count_rows("runtime_nodes").await, 1);
    let nodes = runtime.nodes().snapshot();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id.as_str(), "default");
    assert_eq!(nodes[0].tag, "ss");
}

#[tokio::test]
async fn hydrates_existing_nodes() {
    let fixture = StoreFixture::open().await;
    fixture
        .store
        .seed_node(&OutboundNode {
            id: NodeId::new("default"),
            tag: "persisted".to_string(),
            enabled: true,
        })
        .await
        .expect("seed node");

    let runtime = RuntimeState::from_store_seed(fixture.store.clone(), "config-changed")
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
    RuntimeState::from_store_seed(fixture.store.clone(), "first-config")
        .await
        .expect("initial runtime state");

    let runtime = RuntimeState::from_store_seed(fixture.store.clone(), "changed-config")
        .await
        .expect("restarted runtime state");

    assert_eq!(fixture.count_rows("runtime_nodes").await, 1);
    let nodes = runtime.nodes().snapshot();
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].tag, "first-config");
}

#[tokio::test]
async fn persists_observations() {
    let fixture = StoreFixture::open().await;
    let runtime = RuntimeState::from_store_seed(fixture.store.clone(), "direct")
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
    assert_eq!(runtime.persistence_stats().dropped_observations, 0);
    assert_eq!(runtime.persistence_stats().sink_errors, 0);
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
