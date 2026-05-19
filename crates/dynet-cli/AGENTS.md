# AGENTS

`crates/dynet-cli/` owns the installable `dynet` binary, command parsing,
config discovery, report output, and exit behavior.

## Directory Rules

- `src/main.rs` wires command dispatch, config resolution, report printing,
  logging, and exit codes.
- `src/cli.rs` owns command parsing and help text.
- `src/config.rs` owns config file discovery and filesystem loading.
- `src/model.rs` and `src/output.rs` own CLI-facing report modeling and
  text/JSON output.
- `tests/unit/` contains CLI unit coverage. Register modules in
  `tests/unit.rs`.

Do not add protocol backends, long-running runtime loops, service management,
or platform network device code here.

## Common Commands

```bash
cargo test --locked -p dynet-cli --test unit
cargo run --locked -p dynet-cli -- check --root . --config dynet.json
```

## Standard Workflow

- CLI compatibility changes update help text and tests.
- Config discovery and exit-code changes are compatibility-sensitive.
- Tests here should exercise CLI contracts, not private future runtime details.
