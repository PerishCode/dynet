use dynet_core::OutboundPath;

use crate::{
    resolver::trace::{candidate_tags, hop_kinds, hop_tags, json_field},
    RuntimeCounters, RuntimeEvent, RuntimeEventKind,
};

pub(crate) fn emit_path_events(
    counters: &RuntimeCounters,
    scope: &str,
    transport: &str,
    path: &OutboundPath,
) -> Result<(), String> {
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::OutboundAdmissionPassed)
            .field("scope", scope)
            .field("outbound", &path.requested)
            .field("gate", "admission")
            .field("transport", transport),
    )?;
    for decision in &path.decisions {
        counters.emit(
            RuntimeEvent::new(RuntimeEventKind::OutboundCandidateSet)
                .field("scope", scope)
                .field("plan", &decision.plan)
                .field("strategySource", &decision.strategy.source)
                .field("strategyKey", &decision.strategy.key)
                .field("strategyVersion", &decision.strategy.version)
                .field("selector", format!("{:?}", decision.strategy.selector))
                .field("candidateCount", decision.candidates.len())
                .field("selected", &decision.selected)
                .field(
                    "selectedEdgeType",
                    format!("{:?}", decision.selected_edge_type),
                )
                .field("candidates", candidate_tags(decision))
                .field("candidatesJson", json_field(&decision.candidates)),
        )?;
    }
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::OutboundGraphSelected)
            .field("scope", scope)
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("hops", path.hops.len())
            .field("hopTags", hop_tags(path))
            .field("hopKinds", hop_kinds(path))
            .field("decisions", path.decisions.len()),
    )?;
    counters.emit(
        RuntimeEvent::new(RuntimeEventKind::OutboundEgressPassed)
            .field("scope", scope)
            .field("gate", "egress")
            .field("requested", &path.requested)
            .field("selected", &path.selected)
            .field("transport", transport),
    )
}
