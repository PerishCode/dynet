use std::collections::BTreeMap;

use dynet_ingress::OutboundConfig;
use dynet_runtime::{ForwardGroup, GroupMember};

use super::FileGroupThresholds;

pub(super) fn validate_execution_node(
    default_group: &str,
    groups: &[ForwardGroup],
    group_members: &[GroupMember],
    node_execution_configs: &BTreeMap<String, OutboundConfig>,
) -> Result<(), String> {
    let group = groups
        .iter()
        .find(|group| group.id.as_str() == default_group)
        .ok_or_else(|| format!("forwarding.default_group {default_group:?} is missing"))?;
    if !group.enabled {
        return Err(format!(
            "forwarding.default_group {default_group:?} is disabled"
        ));
    }
    let member = group_members
        .iter()
        .filter(|member| member.group_id == group.id)
        .min_by(|left, right| {
            left.priority
                .cmp(&right.priority)
                .then_with(|| left.node_id.cmp(&right.node_id))
        })
        .ok_or_else(|| format!("forwarding.default_group {default_group:?} has no members"))?;
    if !node_execution_configs.contains_key(member.node_id.as_str()) {
        return Err(format!(
            "forwarding.default_group {default_group:?} member {:?} is missing",
            member.node_id.as_str()
        ));
    }
    Ok(())
}

pub(super) fn validate_thresholds(
    id: &str,
    thresholds: Option<&FileGroupThresholds>,
) -> Result<(), String> {
    let Some(thresholds) = thresholds else {
        return Ok(());
    };
    if thresholds.window_secs == Some(0) {
        return Err(format!(
            "forwarding group {id:?} thresholds.window_secs must be positive"
        ));
    }
    for (name, value) in [
        ("min_confidence", thresholds.min_confidence),
        ("max_explore_ratio", thresholds.max_explore_ratio),
    ] {
        if let Some(value) = value {
            if !(0.0..=1.0).contains(&value) {
                return Err(format!(
                    "forwarding group {id:?} thresholds.{name} must be between 0 and 1"
                ));
            }
        }
    }
    let _ = thresholds.failure_cooldown_secs;
    Ok(())
}
