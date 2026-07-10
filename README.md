# dynet

`dynet` is a full-takeover network runtime.

Its product shape is intentionally narrow:

```text
dynet owns DNS / UDP / TCP capture.
dynet owns routing and forwarding decisions.
dynet owns observability feedback.
```

Linux cold start is TUN-first and dual-stack-capable. IPv6 participation is
disabled until `[ipv6].enabled = true`; once enabled, IPv6 defaults to allow and
follows the selected forwarding graph. Dynet never disables host IPv6 and is
not a firewall. System integration uses dynet-owned `.d` fragments, dedicated
route/nft state, and explicit owner markers.

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
dynet hooks status --config dynet.toml
                      # validate hook state against the configured service UID
dynet hooks apply --config dynet.toml
                      # VM-only install/reconcile of the output capture hook
dynet hooks cleanup --config dynet.toml
                      # VM-only removal of current hook route/rule state
dynet router-hooks plan|doctor|status --config dynet.toml
dynet router-hooks apply --config dynet.toml
                      # source-scoped router-forwarded TCP/UDP capture
dynet router-hooks cleanup --config dynet.toml
                      # remove owned router hook and unshared route/rule state
dynet dns-mapping plan|doctor|status --config dynet.toml
dynet dns-mapping apply --config dynet.toml
                      # explicitly map caller-selected UDP/TCP port 53 to DNS ingress
dynet dns-mapping cleanup --config dynet.toml
                      # remove only the dynet-owned optional mapping chain
dynet config summary --config dynet.toml
                      # redacted config inventory; no proxy secrets or endpoints
dynet config validate --config dynet.toml
                      # load config and environment overrides, then exit
dynet service plan|doctor|status --config dynet.toml
dynet service apply|cleanup --config dynet.toml
dynet service start|stop|restart --config dynet.toml
dynet service reload --config dynet.toml
dynet service logs 120 --config dynet.toml
                      # optional native systemd/procd lifecycle control
dynet cleanup         # remove dynet-owned isolated fragments only
dynet run --config dynet.toml
                      # foreground-only runtime; optional [capture.tun] consumes dynet0
```

`dynet run` remains foreground-only. The optional Linux service control plane
generates one strictly owned systemd unit or OpenWrt procd init script. Apply is
idempotent, refuses foreign or externally drifted artifacts, enables boot start,
and never installs traffic capture hooks. Before every runtime spawn it cleans
stale hooks and runs the idempotent takeover `apply --auto`, so a cold boot or a
restart from fully stopped state restores a persistent, UP TUN skeleton before
the non-root runtime starts. Managed definition changes are written but require
an explicit restart when the service is already active.

The runtime handles `SIGHUP` as an explicit configuration reload and
`SIGTERM`/`SIGINT` as bounded graceful shutdown. Reload parses and validates the
complete candidate before publishing anything. Invalid candidates and changes
that require a restart keep the last-good generation active. A no-op is audited
without incrementing the generation. Shutdown stops accepting new work, drains
active tasks within a fixed budget, and flushes queued persistence before exit.
Both service backends clean output/router capture hooks and any explicitly
applied owned DNS mapping before startup and after every terminal runtime exit
so manager-driven restart fails open. Neither backend implicitly applies hooks
or port mapping.

Missing parent carriers, missing kernel/device capabilities, or missing
required host commands are hard failures. `apply --auto` only creates
dynet-owned fragments when their parent `.d` carrier already exists. It also
creates the current runtime skeleton, `dynet0` plus an `inet dynet` nftables
table with inert `bypass` / `dns` / `tcp` / `udp` chains, without installing
traffic-capturing route or nft hooks.

`doctor` tests `ip tuntap show` functionally, so an ip-tiny binary is rejected
even if an `ip` executable exists. The takeover layer does not require a
systemd carrier; service-manager-specific checks belong to `dynet service
doctor`, allowing the same capture prerequisites to work with OpenWrt procd.

The local-safe packet path parses IPv4 and IPv6 TCP / UDP / DNS packet metadata
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

The output-hook helper is VM-only and explicit. It reserves mark bit
`0x40000000/0x40000000`, preserves every other caller mark bit, uses policy rule
priority `10000`, route table ID `51880`, and nft output priority `-150`.
IPv4 is always installed; IPv6 route/rule state is installed only when enabled.
Only TCP/UDP are marked, while SSH, loopback, link-local/multicast traffic, the
service UID, and already-marked packets bypass capture. Foreign or drifted
artifacts are hard refusals and are never overwritten or removed.

The router-hook helper is a separate explicit surface. It uses a strictly owned
`prerouting` chain at priority `-151`, requires a caller-selected interface and
explicit IPv4/IPv6 source CIDRs, and installs no catch-all source default. It
marks only selected TCP/UDP while bypassing local, private, link-local,
multicast, non-TCP/UDP, and already dynet-marked traffic. It preserves foreign
mark bits by OR-ing only `0x40000000`. Any later interceptor must be configured
by the caller to bypass that bit; otherwise it can overwrite or redirect the
packet after dynet marks it. This is especially relevant to router-wide TProxy
chains such as mihomo.

Traffic admission and firewall policy remain caller-owned. The optional
`dns-mapping` command uses the exact same router-ingress interface and source
CIDRs, plus a caller-selected source port. It clears only dynet's mark bit before
redirecting selected DNS traffic to the local dynet listener, so unrelated mark
bits survive and policy routing remains fail-open. It never changes firewall
admission, DHCP, dnsmasq, UCI, or fw4. Apply is never implicit. DNS ingress
serves UDP and length-prefixed TCP on the same configured socket.

`dynet run` does not install or remove capture hooks. The host capture lifecycle
remains explicit: apply the skeleton with `apply --auto`, start `dynet run` with
`[capture.tun].enabled = true`, then use `hooks apply` and `hooks cleanup` for
the short VM validation window.

Run real TUN/nft/route/sysctl validation only inside the Proxmox dynet
experiment VM. Local development should stay limited to build checks, static
checks, and fake-runner tests.

The local control plane under `/api/v1` currently exposes:

```text
GET /api/v1/health
GET /api/v1/events
GET /api/v1/dns/observed
GET /api/v1/runtime/config
GET /api/v1/runtime/reloads
GET /api/v1/observability/sessions
GET /api/v1/observability/matrix/shadow
GET /api/v1/observability/matrix/signals/error
GET /api/v1/observability/matrix/stats/nodes
GET /api/v1/observability/matrix/stats/targets
```

`events`, `runtime/reloads`, and `observability/sessions` accept bounded query
filters. Events support `afterId`, `limit`, `kind`, `sessionId`, and
`configGeneration`; reload audit supports `afterId`, `limit`, and `outcome`;
sessions support `limit`, `inbound`, `sessionId`, and `configGeneration`.

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
DYNET_DNS_MAX_SESSIONS      # default: 256 TCP DNS sessions
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
DYNET_IPV6_ENABLED
DYNET_DNS_MAPPING_INTERFACE
DYNET_DNS_MAPPING_SOURCE_PORT
DYNET_PERSISTENCE_RETENTION_HOURS # default: 24
DYNET_PERSISTENCE_MAX_BYTES       # default: 67108864
DYNET_SERVICE_MANAGER             # auto, systemd, or procd
DYNET_SERVICE_USER
DYNET_RUNTIME_DB
DYNET_SERVICE_ENVIRONMENT_FILE
```

`dynet` also reads a TOML config file. `--config <path>` selects a file; without
`--config`, it looks for `dynet.toml` in the current working directory and
continues with defaults when that file is absent. Environment variables override
file values.

`dynet config summary --config <path>` loads the same file and prints a
redacted operational summary: bind addresses, capture timers, default group,
node protocol counts, group member counts, route counts, and DNS upstream
count. It intentionally does not print proxy endpoints, passwords, UUIDs, SNI,
Reality public keys, short IDs, or group member node IDs. `dynet config validate
--config <path>` only checks that the file loads after environment overrides.

The configuration file plus the process's inherited `DYNET_*` environment is
the runtime authority. Environment values are re-read on reload, but an
external process cannot change an already-running process environment; changing
service environment therefore requires a restart. SQLite transactionally
mirrors the current forwarding seed and preserves events, completed sessions,
matrix observations, and shadow decisions across restarts. Persistent
observations default to a 24-hour retention window and a 64 MiB budget: expired
rows are pruned, size pressure evicts the oldest observations, active sessions
are protected from time-based pruning, and SQLite page/WAL growth is bounded.
Payloads and credentials are not persisted. The database does not override the
current file/environment configuration. When a retained database is opened,
event, session, and decision IDs continue from their persisted high-water marks;
resetting those counters would make a new session collide with an older
`runtime_traffic_sessions` key and corrupt its audit timeline.

The current reload contract is all-or-nothing:

- `forwarding` and the three `capture.tun` timeout values are hot reloadable.
- control/ingress binds and capacity limits, `ipv6`, `dns_mapping`,
  `persistence`, `capture.tun.enabled`, `capture.tun.interface`, and all
  `[service]` fields require a process restart.
- mixed candidates containing any restart-required field are rejected as a
  whole; hot fields from that candidate are not partially applied.
- new decisions carry `configGeneration`; the execution layer retains a bounded
  set of compiled egress generations so a decision cannot cross into a newer
  graph between selection and dialing. Existing sessions remain on their
  selected generation.
- reload audit is available through `/api/v1/runtime/reloads`; current source,
  semantic SHA-256 fingerprint, generation, and last outcome are available
  through `/api/v1/runtime/config`. Values and proxy credentials are never
  included in these responses.

```toml
[control]
bind = "127.0.0.1:9977"

[ingress.dns]
bind = "[::]:1053"
max_sessions = 256

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

# Required only by explicit `router-hooks` and `dns-mapping` commands.
# Use /32 and /128 identities for a single-client canary.
[capture.router_ingress]
interface = "br-lan"
ipv4_sources = ["192.168.20.12/32"]
ipv6_sources = ["fd00:20::12/128"]

[ipv6]
enabled = true

[persistence]
retention_hours = 24
max_bytes = 67108864

# Optional and inert until `dynet dns-mapping apply` is run. Dual-stack
# redirect requires DNS ingress to bind an unspecified IPv6 address such as [::].
# If set, this compatibility field must match capture.router_ingress.interface.
[dns_mapping]
interface = "br-lan"
source_port = 53

[service]
manager = "auto"
user = "dynet"
runtime_database = "/var/lib/dynet/dynet.sqlite"
# environment_file = "/etc/dynet/dynet.env"

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

With IPv6 enabled, a forwarding rule's optional `ipv6 = "allow" | "deny" |
"inherit"` controls dynet-owned DNS/TCP/UDP participation. `inherit` is the
default and resolves to the global allow policy; `allow` never means direct
egress, because the selected group/node graph still applies. Nodes may declare
`ipv6 = false`; an IPv6 selection then fails explicitly instead of silently
crossing groups or falling back to direct. An explicit rule deny can filter an
AAAA response and reject matching IPv6 TCP/UDP selection, but it is not a
security boundary during fail-open cleanup. Callers must enforce hard deny
requirements in their firewall.

For the historical local Linux VM capture experiment using Mihomo TUN as an
external capture frontend, see `docs/lab/mihomo-tun.md`. That lab is a reference
only; dynet's target architecture absorbs the capture layer.

For a Linux host that should keep dynet running across reboots, use the native
service control plane after the takeover skeleton and config validate cleanly:

```bash
dynet service doctor --config /etc/dynet/dynet.toml
dynet service apply --config /etc/dynet/dynet.toml
dynet service status --config /etc/dynet/dynet.toml
dynet service logs 120 --config /etc/dynet/dynet.toml
dynet service stop --cleanup-hooks --config /etc/dynet/dynet.toml
dynet service cleanup --config /etc/dynet/dynet.toml
```

`manager = "auto"` detects systemd first and then procd. The configured account
must resolve to a stable non-root UID; `hooks apply` derives its `meta skuid`
bypass from that identity instead of assuming a fixed numeric UID. Service
artifacts contain an ownership marker and content hash. A symlink, foreign file,
or modified owned file is a hard refusal for apply and cleanup. The procd
supervisor drops to that UID while retaining only `CAP_NET_ADMIN` for the child,
so OpenWrt does not require `setcap`/`libcap-bin` on the deployed binary. When
capture is enabled, the root supervisor pre-opens `/dev/net/tun`, passes that
single descriptor across exec, and drops its copy after spawn. This lets the
child bind `dynet0` even when OpenWrt exposes the device as `0600 root:root`,
without changing global device ownership or mode.

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

Build the self-contained x86_64-musl binary used by OpenWrt without installing
a host cross-toolchain:

```bash
scripts/build-openwrt.sh
```

The script uses a disposable `rust:1.96-bookworm` container, installs only its
container-local musl compiler, and writes
`target/x86_64-unknown-linux-musl/release/dynet`. `native-tls` enables vendored
OpenSSL for musl builds so the artifact does not depend on OpenWrt's shared
OpenSSL ABI; normal glibc development builds continue to use the system backend.
