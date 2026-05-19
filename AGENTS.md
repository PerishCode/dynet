# AGENTS

`dynet` is a sing-box-like proxy CLI skeleton. It owns CLI shape, config
loading, report output, release packaging, and future proxy runtime boundaries.
It does not yet own concrete protocol implementations, route engines, service
supervision, or platform-specific network device management.

## Directory Rules

- `crates/` contains Rust workspace crates. Each crate owns its local
  `AGENTS.md`; read the child file before editing that subtree.
- `crates/dynet-cli/` owns the installable `dynet` binary, command parsing,
  config discovery, reports, exit codes, and CLI-facing behavior.
- `crates/dynet-core/` owns shared config/domain primitives and validation
  contracts that should not depend on CLI rendering or filesystem discovery.
- `crates/*/harness/` contains representative fixtures owned by that crate.
  Harness fixtures should not become runtime discovery inputs.
- `.github/workflows/` contains CI and release workflows.
- `.github/scripts/` contains workflow-only helper scripts. Keep workflow-only
  scripts there.
- `scripts/init.py` is the idempotent post-clone initializer.
- `install.sh` and `install.ps1` are the public installation entrypoints at the
  repository root.
- Release and installer downloads use R2 metadata and artifacts as the source
  of truth.

When adding or removing a core subtree, update this file in the same change.

## Project Boundaries

- Keep the CLI entrypoint thin: parse command, resolve config, dispatch work,
  render output, return exit code.
- Keep runtime/protocol implementation details out of `dynet-cli`.
- Keep reusable config and validation contracts in `dynet-core`.
- Keep harnesses local to the crate whose boundary they exercise.
- Do not add long-running service execution until the runtime boundary is
  explicitly introduced.

## Common Commands

```bash
python3 scripts/init.py
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo run --locked -p dynet-cli -- check --root . --config dynet.json
```

## Standard Workflow

- CLI shape changes update help text and focused CLI unit tests.
- Config or output compatibility changes should call that out in PR text.
- Runtime/protocol features should land behind crate-owned tests or harness
  fixtures, not by coupling CLI tests to private implementation details.
- Release script changes should keep Unix and Windows paths aligned.

## FAQ

### Does `dynet run` Start A Proxy Yet?

No. The skeleton validates config and reports clearly that runtime execution is
not implemented yet. The runtime boundary will be introduced separately.

### Where Do Protocol Backends Belong?

In future runtime or protocol crates. `dynet-cli` should consume stable
contracts and reports, not backend-specific parser or network types.
