# dynet

`dynet` is a full-takeover network runtime.

Its product shape is intentionally narrow:

```text
dynet owns DNS / UDP / TCP capture.
dynet owns routing and forwarding decisions.
dynet owns observability feedback.
```

Linux cold start is TUN-first and IPv4-only. System integration must use
dynet-owned `.d` fragments, dedicated route/nft state, and explicit owner
markers. If an isolated carrier is unavailable, dynet hard fails. `--auto` may
create missing dynet-owned isolated fragments, but it must never fall back to
directly overwriting global configuration files.

See `docs/full-takeover.md` for the current architecture direction.

`crates/dynet-capture` now defines the platform-neutral capture boundary:
backends produce normalized DNS / UDP / TCP flow context, while runtime
selection, egress execution, and observability remain in the existing core.

Cold-start lifecycle commands:

```bash
dynet plan            # print the takeover plan; no writes
dynet doctor          # probe full-takeover prerequisites; no writes
dynet status          # report current takeover readiness; no writes
dynet apply --auto    # create missing dynet-owned isolated fragments only
dynet reconcile       # verify already-applied isolated state
dynet tun-probe       # VM-only /dev/net/tun TUNSETIFF probe for dynet0
dynet ipstack-poc     # VM-only direct TCP/UDP TUN consumption probe
dynet ipstack-runtime-poc
                      # VM-only TUN -> runtime selection -> graph egress probe
dynet hooks-status    # VM-only capture hook status; no writes
dynet hooks-apply     # VM-only install of the current output capture hook
dynet hooks-cleanup   # VM-only removal of current hook route/rule state
dynet cleanup         # remove dynet-owned isolated fragments only
dynet run --config dynet.toml
                      # long-running runtime; optional [capture.tun] consumes dynet0
```

Missing parent carriers, missing kernel/device capabilities, or missing
required host commands are hard failures. `apply --auto` only creates
dynet-owned fragments when their parent `.d` carrier already exists. It also
creates the current runtime skeleton, `dynet0` plus an `inet dynet` nftables
table with inert `bypass` / `dns` / `tcp` / `udp` chains, without installing
traffic-capturing route or nft hooks.

The local-safe packet path currently parses IPv4 TCP / UDP / DNS packet metadata
from bytes and maps it into normalized captured flow context. Linux TUN IO can
bind `dynet0` through `/dev/net/tun` and expose packet read/write. The
VM-only `ipstack-poc` command validates that captured TCP and UDP/DNS flows can
be consumed from `dynet0` and direct-forwarded back to the local kernel.

`ipstack-runtime-poc` is the next VM-only slice: it consumes the same TUN TCP
and UDP streams, converts packet destinations into `TargetContext`, calls
runtime selection, and relays through the existing graph egress implementation.
It has been validated for direct/default graph TCP and UDP/DNS probes. The same
path is now available to `dynet run` through disabled-by-default `[capture.tun]`
configuration for long-running VM capture windows.

The first hook slice is VM-only: `hooks-apply` installs a local output hook, a
fwmark policy rule before the main table, and a dynet route table that routes
marked VM-originated TCP/UDP traffic to `dynet0`. It bypasses SSH, loopback,
the dynet service UID, and the default service LAN IPv4 ranges
`192.168.1.0/24`, `192.168.20.0/24`, and `10.199.0.0/24` so the experiment can
be cleaned up through `hooks-cleanup` after each validation window.

`dynet run` does not install or remove capture hooks. The host capture lifecycle
remains explicit: apply the skeleton with `apply --auto`, start `dynet run` with
`[capture.tun].enabled = true`, then use `hooks-apply` and `hooks-cleanup` for
the short VM validation window.

Run real TUN/nft/route/sysctl validation only inside the Proxmox dynet
experiment VM. Local development should stay limited to build checks, static
checks, and fake-runner tests.

The local control plane under `/api/v1` currently exposes:

```text
GET /api/v1/health
GET /api/v1/events
GET /api/v1/dns/observed
```

The current ingress crate still contains fixed-upstream TCP/UDP relay
experiments plus DNS and SOCKS5 listeners. These are implementation references
while the full-takeover TUN runtime is introduced; they are not the target
product boundary.

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
DYNET_CAPTURE_TUN_ENABLED
DYNET_CAPTURE_TUN_INTERFACE
DYNET_CAPTURE_TUN_TCP_IDLE_TIMEOUT_MS
DYNET_CAPTURE_TUN_UDP_IDLE_TIMEOUT_MS
DYNET_CAPTURE_TUN_UDP_RESPONSE_TIMEOUT_MS
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

[capture.tun]
enabled = false
interface = "dynet0"
tcp_idle_timeout_ms = 2000
udp_idle_timeout_ms = 2000
udp_response_timeout_ms = 1500

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

For the historical local Linux VM capture experiment using Mihomo TUN as an
external capture frontend, see `docs/lab/mihomo-tun.md`. That lab is a reference
only; dynet's target architecture absorbs the capture layer.

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
