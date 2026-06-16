# AGENTS

`dynet` is being reset around a zero-intrusion product boundary.

The project does not currently own a stable command surface, config format,
runtime architecture, traffic capture layer, or experiment API. Do not preserve
old APIs or module boundaries unless the user explicitly reintroduces them.

## Product Boundary

- `dynet` does not own TUN, DNS hijack, system routing, nftables, service
  supervision, VM lab orchestration, or Clash configuration.
- Capture frontends are external to `dynet`.
- Future `dynet` infrastructure should be designed from the requirement that
  input traffic/context is already captured by something else.
- Do not add compatibility scaffolding for the removed native takeover model.

## Directory Rules

- `crates/dynet-cli/` currently contains only the minimal installable Rust
  binary entrypoint. Keep command parsing out until a command surface is
  explicitly introduced.
- `crates/dynet-api/` owns the local control-plane HTTP API shape under
  `/api/v1`.
- `crates/dynet-ingress/` owns the fixed-upstream transparent DNS/TCP/UDP relay
  experiment and ingress event model. Keep protocol-specific parsing out unless
  a later phase explicitly needs it.
- `crates/dynet-state/` owns the current in-memory `AppState { config }` shape
  for cold-start ports and upstreams.
- `scripts/smoke/` owns small local shell smoke checks. Keep it dependency-light
  and do not rebuild the old Python/VM experiment system here.
- `prototype/shadowsocks/` owns the experimental hand-written Shadowsocks
  client protocol implementation. Keep protocol mechanics here; `dynet-ingress`
  should only adapt it behind the outbound boundary.
- `prototype/shadowsocks/src/aead2022/` owns Shadowsocks 2022 crypto and UDP
  session internals.
- `prototype/shadowsocks/tests/` owns Shadowsocks wire-format integration
  tests against the prototype public API.
- `prototype/trojan/` owns the experimental hand-written Trojan client
  protocol implementation. Keep TLS/protocol mechanics here; `dynet-ingress`
  should only adapt it behind the outbound boundary.
- `prototype/trojan/tests/` owns Trojan wire-format integration tests against
  the prototype public API.
- `prototype/vmess/` owns the experimental hand-written VMess client protocol
  implementation. Keep VMess AEAD/data chunk mechanics here; `dynet-ingress`
  should only adapt it behind the outbound boundary.
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
