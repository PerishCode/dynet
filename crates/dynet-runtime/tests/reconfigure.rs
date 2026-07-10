use dynet_runtime::{InboundKind, RuntimeSeed, RuntimeState, SelectionContext, TargetContext};
use std::net::SocketAddr;

#[test]
fn publishes_new_generation() {
    let runtime = RuntimeState::from_seed(RuntimeSeed::single_node("direct"));
    let prepared = runtime.prepare_reconfigure(RuntimeSeed::single_node("ss"));

    assert_eq!(runtime.generation(), 1);
    assert_eq!(prepared.generation(), 2);
    assert_eq!(runtime.nodes().snapshot()[0].tag, "direct");

    let generation = runtime
        .commit_reconfigure(prepared)
        .expect("prepared generation commits");

    assert_eq!(generation, 2);
    assert_eq!(runtime.generation(), 2);
    assert_eq!(runtime.nodes().snapshot()[0].tag, "ss");
    let decision = runtime
        .select(selection_context(1))
        .expect("selection succeeds");
    assert_eq!(decision.config_generation, 2);
}

#[test]
fn rejects_stale_generation() {
    let runtime = RuntimeState::default();
    let first = runtime.prepare_reconfigure(RuntimeSeed::single_node("ss"));
    let stale = runtime.prepare_reconfigure(RuntimeSeed::single_node("trojan"));

    runtime
        .commit_reconfigure(first)
        .expect("first generation commits");
    let error = runtime
        .commit_reconfigure(stale)
        .expect_err("stale generation is rejected");

    assert!(error.contains("changed from 1 to 2"));
    assert_eq!(runtime.generation(), 2);
    assert_eq!(runtime.nodes().snapshot()[0].tag, "ss");
}

fn selection_context(session_id: u64) -> SelectionContext {
    SelectionContext {
        session_id,
        inbound: InboundKind::Tcp,
        target: TargetContext::fixed_upstream(SocketAddr::from(([127, 0, 0, 1], 80))),
    }
}
