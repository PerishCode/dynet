pub(crate) fn help_text() -> &'static str {
    r#"dynet

Sing-box-like experimental proxy/VPN CLI and runtime.

Commands:
  api capabilities [--format text|json]
  api serve [--bind 127.0.0.1:9977] [--once] [--allow-non-loopback]
  check [--root <path>] [--config <path>] [--format text|json]
        [--log-level off|error|warn|info|debug|trace]
  doctor [--root <path>] [--config <path>] [--format text|json]
         [--log-level off|error|warn|info|debug|trace]
  install --check [--root <path>] [--config <path>] [--format text|json]
        [--log-level off|error|warn|info|debug|trace]
  plan  [--root <path>] [--config <path>] [--format text|json]
        [--context <json>] [--dns-answer domain=ip[,ip...]]
        [--dns-now <seconds>] [--dns-ttl <seconds>]
        [--log-level off|error|warn|info|debug|trace]
  probe [--root <path>] [--config <path>] [--format text|json]
        --url https://host/path | --host <host> [--port 443] [--path /]
        [--inbound <tag>] [--quality-state <path>]
        [--log-level off|error|warn|info|debug|trace]
  repair [--format text|json]
  run   [--root <path>] [--config <path>] [--format text|json]
        [--max-dns-queries <n>] [--max-tun-packets <n>]
        [--max-tcp-sessions <n>] [--max-udp-sessions <n>]
        [--experimental-tcp-forward] [--experimental-udp-forward]
        [--timeout <seconds>] [--upstream-dns <ip:port>]
        [--quality-state <path>]
        [--log-level off|error|warn|info|debug|trace]
  status [--format text|json]
  uninstall [--format text|json]
  verify [--format text|json]
  help
  version

Config:
  --config, -c <path>  Load this JSON config. The file's directory becomes the
                       project root for relative runtime state.
  (no --config)        Walk ancestors of --root (default: cwd) looking for a
                       dynet.json. The nearest match wins. `check` falls back
                       to an empty built-in config if none is found.

Reports:
  check reports config summary and validation diagnostics in text or JSON.
  doctor reports config, platform, tun, resolver, and API bind readiness.
  install --check reports network ownership preflight, owned-resource scope,
  render-only desired state artifacts, and artifact validation status.
  plan compiles explicit routes into an explainable plan model.
  probe runs an explicit dynet-observed HTTPS HEAD through route, plan,
  outbound selection, and outbound stage tracing. probe is unprivileged by
  default and does not apply the runtime socket mark. --quality-state loads an
  expiring observation snapshot for quality-aware diagnostic strategies.
  status, verify, repair, and uninstall report dynet-owned resource state.

API:
  capabilities prints the local API surface. serve starts a loopback-only HTTP
  skeleton with GET /health and GET /v1/capabilities.

Runtime:
  run starts dynet's self-owned Linux runtime boundary: TUN packet observation,
  DNS hijack into a dynet-controlled DNS chain, socket-mark loop avoidance, and
  DNS reverse capture. --upstream-dns is a plain-UDP diagnostic override; the
  default and configured product path use DoH with bootstrap IPs. --quality-state
  lets runtime DNS routing consume the same scoped outbound observations as
  probe. --experimental-tcp-forward enables the first narrow IPv4 TCP forwarding
  experiment for TUN traffic on ports 80 and 443. --experimental-udp-forward
  enables the first narrow IPv4 UDP forwarding experiment for TUN traffic on
  ports 53, 123, and 443; unsupported outbound types fail closed instead of
  falling back across identity or plan boundaries. probe is an active diagnostic
  path for attributing HTTPS/TLS failures before the full forwarding plane lands.

Exit codes:
  0  report completed without deny-level issues.
  1  config read/parse/validation failure, lifecycle deny issue, or runtime
     deny issue.

Project:
  Source:  https://github.com/PerishCode/dynet
"#
}
