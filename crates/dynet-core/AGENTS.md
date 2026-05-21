# AGENTS

`crates/dynet-core/` owns shared dynet config/domain primitives, validation
contracts, and plan derivation contracts.

## Directory Rules

- `src/lib.rs` exports the public core API; keep implementation details in
  focused modules.
- `src/model.rs`, `src/capability.rs`, `src/validate.rs`, `src/state.rs`,
  `src/context.rs`, `src/verdict.rs`, and `src/plan/` own the current domain
  model, capability inference, validation, app state, inbound context, verdict,
  outbound plan strategy registry, outbound graph resolution, and explicit
  route plan derivation boundaries.
- `harness/configs/` contains representative config fixtures owned by this
  crate.
- `tests/` validates config and validation contracts.

Do not add CLI command parsing, config discovery, report rendering, installer
behavior, or runtime process management here.

## Common Commands

```bash
cargo test --locked -p dynet-core
```

## Standard Workflow

- Keep core contracts serializable and boring.
- Add harness fixtures when config shape changes in a meaningful way.
- Model inbound/outbound nodes as stable identity/capability objects plus
  protocol payload. Pure `tcp` and `udp` nodes are first-class model fixtures,
  not runtime backends.
- Model DNS chains as their own plane under `dns.chains`. Do not add config
  selectors such as `dns.default` before there is a real DNS plan layer. For
  now the runtime uses the first chain as the explicit entrypoint.
- Keep future protocol/runtime details behind explicit core or runtime
  contracts; do not leak CLI behavior into this crate.
