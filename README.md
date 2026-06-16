# dynet

`dynet` is intentionally reset to a minimal Rust project skeleton.

The previous TUN, DNS hijack, platform takeover, VM lab, proxy runtime, config,
and command surfaces have been removed so the next design can grow from the new
boundary:

```text
dynet does not capture traffic.
dynet does not own system network state.
dynet assumes any future traffic/context input is provided by an external
capture frontend.
```

The first reintroduced surface is a minimal local control plane under
`/api/v1`. Cold start currently exposes:

```text
GET /api/v1/health
GET /api/v1/events
```

The first ingress experiment is a fixed-upstream relay set. It does not parse
HTTP, HTTP/3, or DNS semantics; it only verifies transparent delivery and event
capture.

Default local listeners:

```text
control: 127.0.0.1:9977
dns:     127.0.0.1:1053  -> 1.1.1.1:53
tcp:     127.0.0.1:18080 -> 93.184.216.34:80
udp:     127.0.0.1:18443 -> 1.1.1.1:443
```

Cold-start bind/upstream values can be overridden with environment variables:

```text
DYNET_CONTROL_BIND
DYNET_DNS_BIND
DYNET_DNS_UPSTREAM
DYNET_DNS_TIMEOUT_MS
DYNET_TCP_BIND
DYNET_TCP_UPSTREAM
DYNET_TCP_MAX_SESSIONS      # default: 1024 active sessions
DYNET_UDP_BIND
DYNET_UDP_UPSTREAM
DYNET_UDP_IDLE_TIMEOUT_MS
DYNET_UDP_MAX_SESSIONS      # default: 1024 active associations
```

`dynet` also reads a TOML config file. `--config <path>` selects a file; without
`--config`, it looks for `dynet.toml` in the current working directory and
continues with defaults when that file is absent. Environment variables override
file values.

```toml
[control]
bind = "127.0.0.1:9977"

[ingress.dns]
bind = "127.0.0.1:1053"
upstream = "1.1.1.1:53"
timeout_ms = 5000

[ingress.tcp]
bind = "127.0.0.1:18080"
upstream = "93.184.216.34:80"
max_sessions = 1024

[ingress.udp]
bind = "127.0.0.1:18443"
upstream = "1.1.1.1:443"
idle_timeout_ms = 30000
max_sessions = 1024

[outbound]
type = "direct"
```

For the first protocol-backed experiment, `dynet.toml` can hold a local
dual-protocol Shadowsocks node. Keep `dynet.toml` uncommitted.

```toml
[outbound]
type = "shadowsocks"
server = "node.example.com"
port = 8388
method = "aes-256-gcm"
password = "local-secret"
udp = true
```

Supported prototype Shadowsocks methods are `aes-256-gcm` and
`2022-blake3-aes-128-gcm`. For `2022-blake3-aes-128-gcm`, `password` must be
the node's base64-encoded 16-byte pre-shared key.

`dynet.toml` can also hold a local dual-protocol Trojan node. `sni` is optional
when it matches `server`; `skip-cert-verify` is available for local experiment
nodes that require it.

```toml
[outbound]
type = "trojan"
server = "node.example.com"
port = 443
password = "local-secret"
sni = "node.example.com"
skip-cert-verify = true
udp = true
```

## Development

```bash
cargo fmt --all --check
flavor check --root . --config flavor.json
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/smoke/ingress.sh
```
