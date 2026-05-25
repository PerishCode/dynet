use std::vec::IntoIter;

use super::values::parse_usize;

#[derive(Debug, Default)]
pub(super) struct RunLimitArgs {
    pub(super) max_dns_queries: Option<usize>,
    pub(super) max_tun_packets: Option<usize>,
    pub(super) max_tcp_sessions: Option<usize>,
    pub(super) max_tcp_closed_sessions: Option<usize>,
    pub(super) max_tcp_terminal_sessions: Option<usize>,
    pub(super) max_udp_sessions: Option<usize>,
    pub(super) max_udp_downstream_bytes: Option<usize>,
}

pub(super) fn parse_arg(
    arg: &str,
    args: &mut IntoIter<String>,
    limits: &mut RunLimitArgs,
) -> Result<bool, String> {
    if parse_limit(arg, args, "--max-dns-queries", &mut limits.max_dns_queries)? {
        return Ok(true);
    }
    if parse_limit(arg, args, "--max-tun-packets", &mut limits.max_tun_packets)? {
        return Ok(true);
    }
    if parse_limit(
        arg,
        args,
        "--max-tcp-sessions",
        &mut limits.max_tcp_sessions,
    )? {
        return Ok(true);
    }
    if parse_limit(
        arg,
        args,
        "--max-tcp-closed-sessions",
        &mut limits.max_tcp_closed_sessions,
    )? {
        return Ok(true);
    }
    if parse_limit(
        arg,
        args,
        "--max-tcp-terminal-sessions",
        &mut limits.max_tcp_terminal_sessions,
    )? {
        return Ok(true);
    }
    if parse_limit(
        arg,
        args,
        "--max-udp-sessions",
        &mut limits.max_udp_sessions,
    )? {
        return Ok(true);
    }
    if parse_limit(
        arg,
        args,
        "--max-udp-downstream-bytes",
        &mut limits.max_udp_downstream_bytes,
    )? {
        return Ok(true);
    }
    Ok(false)
}

fn parse_limit(
    arg: &str,
    args: &mut IntoIter<String>,
    flag: &str,
    target: &mut Option<usize>,
) -> Result<bool, String> {
    if arg == flag {
        let value = args
            .next()
            .ok_or_else(|| format!("{flag} requires a positive integer"))?;
        *target = Some(parse_usize(flag, &value)?);
        return Ok(true);
    }
    if let Some(value) = arg.strip_prefix(&format!("{flag}=")) {
        *target = Some(parse_usize(flag, value)?);
        return Ok(true);
    }
    Ok(false)
}
