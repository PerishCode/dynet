# AGENTS

`crates/dynet-cli/` owns the installable `dynet` binary, command parsing,
config discovery, report output, and exit behavior.

## Directory Rules

- `src/api.rs` owns the loopback-only cold-start HTTP API skeleton.
- `src/main.rs` wires command dispatch, config resolution, report printing,
  logging, and exit codes.
- `src/cli.rs` owns command parsing and help text.
- `src/config.rs` owns config file discovery and filesystem loading.
- `src/model.rs` and `src/output.rs` own CLI-facing report modeling and
  text/JSON output.
- `src/platform.rs` owns the CLI-only platform lifecycle reports for
  `install --check`, `status`, `verify`, `repair`, and `uninstall`. It may
  inventory dynet-owned nft/tun/DNS/routing resources and render desired-state
  artifacts with non-mutating validation status, but real network mutation stays
  gated until the VM evidence loop proves the lifecycle.
- `tests/unit/` contains CLI unit coverage. Register modules in
  `tests/unit.rs`.

Do not add protocol backends, product runtime loops, service management, or
platform network device mutation here. Read-only cold-start checks and the
loopback API skeleton are allowed CLI contracts.

## Common Commands

```bash
cargo test --locked -p dynet-cli --test unit
cargo run --locked -p dynet-cli -- check --root . --config dynet.json
cargo run --locked -p dynet-cli -- doctor --config dynet.json
cargo run --locked -p dynet-cli -- plan --config dynet.json
cargo run --locked -p dynet-cli -- install --check --config dynet.json
cargo run --locked -p dynet-cli -- status
cargo run --locked -p dynet-cli -- verify
cargo run --locked -p dynet-cli -- api capabilities
```

## Standard Workflow

- CLI compatibility changes update help text and tests.
- Config discovery and exit-code changes are compatibility-sensitive.
- Tests here should exercise CLI contracts, not private future runtime details.
