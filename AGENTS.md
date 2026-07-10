# AGENTS

`dynet` is being reset around a full-takeover product boundary.

The project does not currently own a stable command surface, config format,
runtime architecture, traffic capture layer, or experiment API. Do not preserve
old APIs or module boundaries unless the user explicitly reintroduces them.

## Product Boundary

- `dynet` has exactly one product runtime shape: full DNS / UDP / TCP takeover.
- Linux cold start is TUN-first and dual-stack when `[ipv6].enabled = true`;
  enabling IPv6 default-passes dynet-owned DNS/TCP/UDP policy unless a rule
  explicitly denies it, and never disables host IPv6 when false.
- `dynet` owns its capture lifecycle, strictly marked routing/nftables/sysctl
  artifacts, service lifecycle expectations, forwarding decisions, and
  observability feedback loop. The caller owns firewall admission, DHCP,
  dnsmasq/UCI/fw4, and port-53 mapping; dynet's optional mapping helper is
  explicit, strictly owned, and never a security boundary during fail-open.
- `dynet run` is foreground-only. Optional background lifecycle is owned by the
  backend-neutral `dynet service` control plane; Linux cold start supports
  systemd and OpenWrt procd without external process-state or log-file runners.
- System integration must be isolated through dynet-owned `.d` fragments,
  dedicated nftables tables/chains, dedicated route tables/rules, and explicit
  owner markers. If an isolation carrier is unavailable, hard fail.
- `--auto` may create missing dynet-owned isolated fragments, but it must never
  fall back to directly overwriting global configuration files.
- TUN capture is an implementation backend. Keep it decoupled from the runtime
  decision, session, matrix, and egress core so future platform capture backends
  can reuse the same core.
- Do not add compatibility scaffolding for partial takeover, external capture
  frontends, Clash-style product boundaries, or legacy client-proxy habits.

## Directory Rules

- `crates/dynet-cli/` currently contains only the minimal installable Rust
  binary entrypoint and the cold-start lifecycle command surface.
- `crates/dynet-capture/` owns platform capture backends and host takeover
  lifecycle. The first backend is Linux TUN with `.d` isolation probing;
  `src/linux/hooks/` separates hook ownership/status parsing, and
  `tests/support/` owns shared fake host fixtures for capture integration tests.
- `crates/dynet-api/` owns the local control-plane HTTP API shape under
  `/api/v1`.
- `crates/dynet-ingress/` owns the fixed-upstream transparent DNS/TCP/UDP relay
  experiment and ingress event model. Keep protocol-specific parsing out unless
  a later phase explicitly needs it. This crate is no longer the product
  capture boundary.
- `crates/dynet-runtime/` owns the shared runtime facade, event store, node
  metadata, DNS-map placeholder, selector-matrix placeholder, and forwarding
  selection decision boundary. It also owns atomic routing generations,
  configuration reload audit state, persisted observation ID watermarks, and
  the SQLite forwarding mirror. Keep hot runtime state and persistence hooks
  here instead of hiding them inside ingress adapters.
- `crates/dynet-service/` owns backend-neutral service lifecycle contracts,
  strict generated-artifact ownership, systemd/procd rendering, native manager
  commands, and the privileged procd supervisor used for fail-open cleanup.
- `crates/dynet-state/` owns the current in-memory `AppState { config }` shape
  plus reload field classification and semantic configuration fingerprints.
- `docs/lab/` owns historical external capture-frontend lab runbooks and sample
  configs. Keep them as references while the full-takeover runtime replaces
  that model.
- `scripts/smoke/` owns small local shell smoke checks. Keep it dependency-light
  and do not rebuild the old Python/VM experiment system here.
- `scripts/build-openwrt.sh` owns the reproducible x86_64-musl release build
  used by the OpenWrt canary. It may use a disposable container toolchain but
  must leave the host workspace user-owned and emit only the dynet binary.
- `prototype/shadowsocks/` owns the experimental hand-written Shadowsocks
  client protocol implementation. Keep protocol mechanics here; `dynet-ingress`
  should only adapt it behind the egress/dial boundary.
- `prototype/shadowsocks/src/aead2022/` owns Shadowsocks 2022 crypto and UDP
  session internals.
- `prototype/shadowsocks/tests/` owns Shadowsocks wire-format integration
  tests against the prototype public API.
- `prototype/trojan/` owns the experimental hand-written Trojan client
  protocol implementation. Keep TLS/protocol mechanics here; `dynet-ingress`
  should only adapt it behind the egress/dial boundary.
- `prototype/trojan/tests/` owns Trojan wire-format integration tests against
  the prototype public API.
- `prototype/vless/` owns the experimental VLESS Reality/Vision client protocol
  implementation. Keep VLESS headers, Vision framing, REALITY transport, and
  related wire-format tests here; `dynet-ingress` should only adapt it behind
  the egress/dial boundary.
- `prototype/vmess/` owns the experimental hand-written VMess client protocol
  implementation. Keep VMess AEAD/data chunk mechanics here; `dynet-ingress`
  should only adapt it behind the egress/dial boundary.
- `prototype/vmess/tests/` owns VMess wire-format integration tests against
  the prototype public API.
- `flavor.json` owns the source shape scan for supported files.
- When adding a new subtree, document its ownership here in the same change.

## Common Commands

```bash
cargo fmt --all --check
flavor check --root . --config flavor.json
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/smoke/ingress.sh
```

Run commands that create TUN/nft/route/sysctl state only inside explicitly
scoped Proxmox VM canaries. The real OpenWrt VM additionally requires a frozen
service.lan decision card and must keep production hooks/mappings inactive until
that card explicitly admits a traffic slice.

Service artifacts must remain isolated, atomically replaced, content-hashed,
and idempotent. Never execute, overwrite, or remove a foreign/drifted artifact.
Service startup and every terminal runtime exit must clean capture hooks. Keep
normal runtime shutdown bounded and flush persistence before returning.
