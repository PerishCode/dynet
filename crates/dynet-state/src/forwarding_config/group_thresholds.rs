use dynet_runtime::GroupThresholds;

use super::FileGroupThresholds;

pub(super) fn load_thresholds(
    thresholds: Option<FileGroupThresholds>,
    defaults: GroupThresholds,
) -> Result<GroupThresholds, String> {
    let Some(thresholds) = thresholds else {
        return Ok(defaults);
    };
    Ok(GroupThresholds {
        min_success_rate_ppm: thresholds
            .min_success_rate
            .map(rate_to_ppm)
            .transpose()?
            .unwrap_or(defaults.min_success_rate_ppm),
        min_samples: thresholds.min_samples.unwrap_or(defaults.min_samples),
        max_active_sessions: thresholds
            .max_active_sessions
            .or(defaults.max_active_sessions),
    })
}

fn rate_to_ppm(value: f64) -> Result<u32, String> {
    if !(0.0..=1.0).contains(&value) {
        return Err(
            "forwarding.groups[].thresholds.min_success_rate must be between 0 and 1".into(),
        );
    }
    Ok((value * 1_000_000.0).round() as u32)
}
