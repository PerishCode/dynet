use crate::SchedulerPolicy;

pub(super) fn bool_from_i64(value: i64) -> Option<bool> {
    match value {
        0 => Some(false),
        1 => Some(true),
        _ => None,
    }
}

pub(super) fn u32_from_i64(value: i64) -> Option<u32> {
    u32::try_from(value).ok()
}

pub(super) fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

pub(super) fn scheduler_from_str(value: &str) -> Option<SchedulerPolicy> {
    (value == "single-first-enabled").then_some(SchedulerPolicy::SingleFirstEnabled)
}
