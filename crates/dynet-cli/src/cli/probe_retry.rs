use std::vec::IntoIter;

use super::values::{parse_u64, parse_usize};

const ATTEMPTS_FLAG: &str = "--retry-direct-tls-eof-attempts";
const SLEEP_FLAG: &str = "--retry-direct-tls-eof-sleep-ms";

pub(super) fn parse_arg(
    arg: &str,
    args: &mut IntoIter<String>,
    attempts: &mut usize,
    sleep_ms: &mut u64,
) -> Result<bool, String> {
    if arg == ATTEMPTS_FLAG {
        let value = args
            .next()
            .ok_or_else(|| format!("{ATTEMPTS_FLAG} requires a positive integer"))?;
        *attempts = parse_usize(ATTEMPTS_FLAG, &value)?;
        return Ok(true);
    }
    if let Some(value) = arg.strip_prefix(&format!("{ATTEMPTS_FLAG}=")) {
        *attempts = parse_usize(ATTEMPTS_FLAG, value)?;
        return Ok(true);
    }
    if arg == SLEEP_FLAG {
        let value = args
            .next()
            .ok_or_else(|| format!("{SLEEP_FLAG} requires a non-negative integer"))?;
        *sleep_ms = parse_u64(SLEEP_FLAG, &value)?;
        return Ok(true);
    }
    if let Some(value) = arg.strip_prefix(&format!("{SLEEP_FLAG}=")) {
        *sleep_ms = parse_u64(SLEEP_FLAG, value)?;
        return Ok(true);
    }
    Ok(false)
}
