# AGENTS

`crates/dynet-runtime/` owns dynet's self-written runtime and platform mutation
boundary.

## Directory Rules

- `src/lib.rs` exports stable runtime reports and operations.
- `src/settings.rs` owns runtime and takeover settings shared by runtime
  services and CLI adapters.
- `src/takeover.rs` owns Linux takeover apply/cleanup, manifest authority, and
  dynet-owned resource mutation.
- `src/dns.rs` owns the real DNS hijack listener and reverse-answer capture.
- `src/resolver.rs` owns DNS chain execution such as direct DoH over pinned
  bootstrap IPs. Keep HTTP wire handling explicit here; TLS roots and TLS
  protocol implementation may use focused crates.
- `src/tun.rs` owns Linux TUN device attachment and packet observation.
- `src/socket.rs` owns low-level socket controls such as Linux `SO_MARK`.

Do not add CLI parsing, config discovery, report text rendering, VM orchestration,
or high-level product plan policy here.

## Common Commands

```bash
cargo test --locked -p dynet-runtime
```

## Standard Workflow

- Keep this crate self-owned: do not wrap generic TUN-to-proxy binaries as the
  dynet product runtime shape.
- Prefer rough, explicit runtime code over abstracting before VM evidence.
- Full TCP/UDP forwarding and outbound protocol adapters belong here or below
  this crate, never in `dynet-cli`.
