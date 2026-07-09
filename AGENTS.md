# AGENTS

`dynet` is being reset around a full-takeover product boundary.

The project does not currently own a stable command surface, config format,
runtime architecture, traffic capture layer, or experiment API. Do not preserve
old APIs or module boundaries unless the user explicitly reintroduces them.

## Product Boundary

- `dynet` has exactly one product runtime shape: full DNS / UDP / TCP takeover.
- Linux cold start is TUN-first and IPv4-only.
- `dynet` owns its capture lifecycle, system routing, DNS takeover, nftables
  state, sysctl state, service lifecycle expectations, forwarding decisions,
  and observability feedback loop.
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
  lifecycle. The first backend is Linux TUN with `.d` isolation probing.
- `crates/dynet-api/` owns the local control-plane HTTP API shape under
  `/api/v1`.
- `crates/dynet-ingress/` owns the fixed-upstream transparent DNS/TCP/UDP relay
  experiment and ingress event model. Keep protocol-specific parsing out unless
  a later phase explicitly needs it. This crate is no longer the product
  capture boundary.
- `crates/dynet-runtime/` owns the shared runtime facade, event store, node
  metadata, DNS-map placeholder, selector-matrix placeholder, and forwarding
  selection decision boundary. Keep hot runtime state and future persistence
  hooks here instead of hiding them inside ingress adapters.
- `crates/dynet-state/` owns the current in-memory `AppState { config }` shape
  for cold-start ports and upstreams.
- `docs/lab/` owns historical external capture-frontend lab runbooks and sample
  configs. Keep them as references while the full-takeover runtime replaces
  that model.
- `scripts/smoke/` owns small local shell smoke checks. Keep it dependency-light
  and do not rebuild the old Python/VM experiment system here.
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

Run `dynet ipstack-poc`, `dynet hooks-apply`, `dynet hooks-cleanup`, and any
command that creates TUN/nft/route/sysctl state only inside the Proxmox dynet
experiment VM.
