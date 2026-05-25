use std::vec::IntoIter;

use super::values::parse_u64;

const POLL_TIMEOUT_FLAG: &str = "--probe-read-poll-timeout-ms";
const PENDING_BUDGET_FLAG: &str = "--probe-read-pending-budget-ms";
const PENDING_SLEEP_FLAG: &str = "--probe-read-pending-sleep-ms";

pub(super) fn parse_arg(
    arg: &str,
    args: &mut IntoIter<String>,
    poll_timeout_ms: &mut u64,
    pending_budget_ms: &mut u64,
    pending_sleep_ms: &mut u64,
) -> Result<bool, String> {
    if arg == POLL_TIMEOUT_FLAG {
        let value = args
            .next()
            .ok_or_else(|| format!("{POLL_TIMEOUT_FLAG} requires a positive integer"))?;
        *poll_timeout_ms = parse_u64(POLL_TIMEOUT_FLAG, &value)?;
        return Ok(true);
    }
    if let Some(value) = arg.strip_prefix(&format!("{POLL_TIMEOUT_FLAG}=")) {
        *poll_timeout_ms = parse_u64(POLL_TIMEOUT_FLAG, value)?;
        return Ok(true);
    }
    if arg == PENDING_BUDGET_FLAG {
        let value = args
            .next()
            .ok_or_else(|| format!("{PENDING_BUDGET_FLAG} requires a non-negative integer"))?;
        *pending_budget_ms = parse_u64(PENDING_BUDGET_FLAG, &value)?;
        return Ok(true);
    }
    if let Some(value) = arg.strip_prefix(&format!("{PENDING_BUDGET_FLAG}=")) {
        *pending_budget_ms = parse_u64(PENDING_BUDGET_FLAG, value)?;
        return Ok(true);
    }
    if arg == PENDING_SLEEP_FLAG {
        let value = args
            .next()
            .ok_or_else(|| format!("{PENDING_SLEEP_FLAG} requires a non-negative integer"))?;
        *pending_sleep_ms = parse_u64(PENDING_SLEEP_FLAG, &value)?;
        return Ok(true);
    }
    if let Some(value) = arg.strip_prefix(&format!("{PENDING_SLEEP_FLAG}=")) {
        *pending_sleep_ms = parse_u64(PENDING_SLEEP_FLAG, value)?;
        return Ok(true);
    }
    Ok(false)
}
