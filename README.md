# dynet

Sing-box-like proxy CLI skeleton.

`dynet` currently establishes the installable CLI, workspace boundaries, config
loading, reporting, release packaging, and harness conventions. Concrete proxy
runtime, protocol, routing, and platform networking behavior will be added
behind those boundaries later.

## Usage

```bash
dynet check                       # auto-discovers dynet.json from --root
dynet check --config dynet.json   # explicit path
dynet check --format json
dynet run --config dynet.json     # validates config; runtime is not implemented yet
dynet version
dynet help
```

`dynet check` exits `1` when the config cannot be read, parsed, or validated.
`dynet run` currently validates config and exits `1` after reporting that runtime
execution has not been implemented.

## Config

The skeleton config is intentionally small and generic:

```json
{
  "log": {
    "level": "info"
  },
  "inbounds": [
    { "tag": "mixed-in", "type": "mixed" }
  ],
  "outbounds": [
    { "tag": "direct", "type": "direct" }
  ],
  "routes": [
    { "inbound": "mixed-in", "outbound": "direct" }
  ]
}
```

Discovery order:

1. `--config <path>` if provided. The file's directory becomes the project root.
2. The nearest `dynet.json` found by walking ancestors from `--root`.
3. Built-in empty config for `check` only.

## Workspace

- `crates/dynet-cli`: installable binary, command parsing, config discovery,
  reports, and exit behavior.
- `crates/dynet-core`: shared config/domain primitives and validation contracts.

Harness fixtures live with the crate that owns the boundary being tested. CLI
tests should exercise command/config/output contracts, not private future
runtime details.

## Development

```bash
python3 scripts/init.py
cargo fmt --all --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo run --locked -p dynet-cli -- check --root . --config dynet.json
```
