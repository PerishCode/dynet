use std::vec::IntoIter;

use super::values::parse_u64;

const CONNECT_TIMEOUT_FLAG: &str = "--outbound-tcp-connect-timeout-ms";
const READ_WRITE_TIMEOUT_FLAG: &str = "--outbound-tcp-read-write-timeout-ms";

pub(super) fn parse_arg(
    arg: &str,
    args: &mut IntoIter<String>,
    connect_timeout_ms: &mut u64,
    read_write_timeout_ms: &mut u64,
) -> Result<bool, String> {
    if parse_timeout(arg, args, CONNECT_TIMEOUT_FLAG, connect_timeout_ms)? {
        return Ok(true);
    }
    if parse_timeout(arg, args, READ_WRITE_TIMEOUT_FLAG, read_write_timeout_ms)? {
        return Ok(true);
    }
    Ok(false)
}

fn parse_timeout(
    arg: &str,
    args: &mut IntoIter<String>,
    flag: &str,
    target: &mut u64,
) -> Result<bool, String> {
    if arg == flag {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} requires a positive integer"))?;
        *target = parse_u64(flag, &value)?;
        return Ok(true);
    }
    if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
        *target = parse_u64(flag, value)?;
        return Ok(true);
    }
    Ok(false)
}
