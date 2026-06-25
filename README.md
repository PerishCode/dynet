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
GET /api/v1/dns/observed
```

The first ingress experiment is a fixed-upstream TCP/UDP relay set plus a DNS
relay backed by runtime DNS upstreams. It does not parse HTTP or HTTP/3; it only
verifies transparent delivery and event capture.

Default local listeners:

```text
control:      127.0.0.1:9977
dns:          127.0.0.1:1053
runtime DNS:  1.1.1.1:53, 8.8.8.8:53
tcp:          127.0.0.1:18080 -> 93.184.216.34:80
udp:          127.0.0.1:18443 -> 1.1.1.1:443
socks5:       127.0.0.1:11080
```

Cold-start bind/upstream values can be overridden with environment variables:

```text
DYNET_CONTROL_BIND
DYNET_DNS_BIND
DYNET_TCP_BIND
DYNET_TCP_UPSTREAM
DYNET_TCP_MAX_SESSIONS      # default: 1024 active sessions
DYNET_UDP_BIND
DYNET_UDP_UPSTREAM
DYNET_UDP_IDLE_TIMEOUT_MS
DYNET_UDP_MAX_SESSIONS      # default: 1024 active associations
DYNET_SOCKS5_BIND
DYNET_SOCKS5_UDP_ADVERTISE_IP
DYNET_SOCKS5_UDP_IDLE_TIMEOUT_MS
DYNET_SOCKS5_MAX_SESSIONS   # default: 1024 active sessions
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

[ingress.tcp]
bind = "127.0.0.1:18080"
upstream = "93.184.216.34:80"
max_sessions = 1024

[ingress.udp]
bind = "127.0.0.1:18443"
upstream = "1.1.1.1:443"
idle_timeout_ms = 30000
max_sessions = 1024

[ingress.socks5]
bind = "127.0.0.1:11080"
udp_advertise_ip = "192.168.5.2"
udp_idle_timeout_ms = 30000
max_sessions = 1024

[forwarding]
default_group = "default"

[[forwarding.nodes]]
id = "default-node"
type = "direct"

[[forwarding.groups]]
id = "default"
mode = "smart"
members = ["default-node"]
```

For a local Linux VM capture experiment using Mihomo TUN as the external
capture frontend, see `docs/lab/mihomo-tun.md`.

For local long-running validation, `scripts/dynetctl.sh` manages one stamped
background dynet process:

```bash
scripts/dynetctl.sh start
scripts/dynetctl.sh status
scripts/dynetctl.sh log -f
scripts/dynetctl.sh stop
```

The script defaults to `dynet.toml`, `target/dynet-user-sim.sqlite`, and logs
under `.tmp/logs/`. The running process carries a `--process-stamp=...` argv
marker so `status` and `stop` do not rely on port scans alone.

For the first protocol-backed experiment, `dynet.toml` can hold a local
dual-protocol Shadowsocks node. Keep `dynet.toml` uncommitted.

```toml
[forwarding]
default_group = "default"

[[forwarding.nodes]]
id = "default-node"
type = "shadowsocks"
server = "node.example.com"
port = 8388
method = "aes-256-gcm"
password = "local-secret"
udp = true

[[forwarding.groups]]
id = "default"
mode = "smart"
members = ["default-node"]
```

Supported prototype Shadowsocks methods are `aes-256-gcm` and
`2022-blake3-aes-128-gcm`. For `2022-blake3-aes-128-gcm`, `password` must be
the node's base64-encoded 16-byte pre-shared key.

`dynet.toml` can also hold a local dual-protocol Trojan node. `sni` is optional
when it matches `server`; `skip-cert-verify` is available for local experiment
nodes that require it.

```toml
[forwarding]
default_group = "default"

[[forwarding.nodes]]
id = "default-node"
type = "trojan"
server = "node.example.com"
port = 443
password = "local-secret"
sni = "node.example.com"
skip-cert-verify = true
udp = true

[[forwarding.groups]]
id = "default"
mode = "smart"
members = ["default-node"]
```

For the current VMess cold-start experiment, only raw TCP transport,
`alterId = 0`, `cipher = "auto"`, and `udp = true` are accepted.

```toml
[forwarding]
default_group = "default"

[[forwarding.nodes]]
id = "default-node"
type = "vmess"
server = "node.example.com"
port = 10086
uuid = "11111111-2222-3333-4444-555555555555"
alterId = 0
cipher = "auto"
udp = true

[[forwarding.groups]]
id = "default"
mode = "smart"
members = ["default-node"]
```

Groups can also describe connection-direction TCP composition with `next`.
Rules select the first group, that group's selected node acts as the dialer,
and the final group supplies the business egress node. The reserved default is
`next = "direct"` when the field is omitted.

```toml
[forwarding]
default_group = "Tunnel"

[[forwarding.nodes]]
id = "airport-us-01"
type = "shadowsocks"
server = "airport.example.com"
port = 8388
method = "aes-256-gcm"
password = "local-secret"
udp = true

[[forwarding.nodes]]
id = "private-us-01"
type = "shadowsocks"
server = "private.example.com"
port = 8388
method = "aes-256-gcm"
password = "local-secret"
udp = true

[[forwarding.groups]]
id = "Tunnel"
mode = "smart"
next = "Private"
members = ["airport-us-01"]

[[forwarding.groups]]
id = "Private"
mode = "smart"
members = ["private-us-01"]
```

## Development

```bash
cargo fmt --all --check
flavor check --root . --config flavor.json
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/smoke/ingress.sh
```
