use std::net::SocketAddr;

use dynet_runtime::{InboundKind, RuntimeState, SelectionContext, SelectionReason, TargetContext};

#[test]
fn selects_default_node() {
    let runtime = RuntimeState::single_node("ss");
    let decision = runtime
        .select(selection_context(1))
        .expect("selection succeeds");

    assert_eq!(decision.node_id.as_str(), "default");
    assert_eq!(decision.reason, SelectionReason::SingleNode);
    assert_eq!(decision.decision_id, 1);
    assert_eq!(runtime.nodes().snapshot()[0].tag, "ss");
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

fn selection_context(session_id: u64) -> SelectionContext {
    SelectionContext {
        session_id,
        inbound: InboundKind::Tcp,
        target: TargetContext::fixed_upstream(SocketAddr::from(([127, 0, 0, 1], 80))),
    }
}
