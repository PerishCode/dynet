# AGENTS

`crates/dynet-core/` owns shared dynet config/domain primitives, validation
contracts, and plan derivation contracts.

## Directory Rules

- `src/lib.rs` owns the public core API for the current skeleton.
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
- Keep future protocol/runtime details behind explicit core or runtime
  contracts; do not leak CLI behavior into this crate.
