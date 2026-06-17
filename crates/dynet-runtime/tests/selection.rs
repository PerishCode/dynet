use std::net::SocketAddr;

use dynet_runtime::{
    InboundKind, RuntimeState, SchedulerPolicy, SelectionContext, SelectionReason,
    SelectionTerminal, TargetContext,
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

fn selection_context(session_id: u64) -> SelectionContext {
    SelectionContext {
        session_id,
        inbound: InboundKind::Tcp,
        target: TargetContext::fixed_upstream(SocketAddr::from(([127, 0, 0, 1], 80))),
    }
}
