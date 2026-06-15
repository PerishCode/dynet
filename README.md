# dynet

`dynet` is intentionally reset to a minimal Rust project skeleton.

The previous TUN, DNS hijack, platform takeover, VM lab, proxy runtime, config,
and command surfaces have been removed so the next design can grow from the new
boundary:

```text
dynet does not capture traffic.
dynet does not own system network state.
dynet assumes any future traffic/context input is provided by an external
capture frontend.
```

The first reintroduced surface is a minimal local control plane under
`/api/v1`. Cold start currently exposes:

```text
GET /api/v1/health
GET /api/v1/events
```

The first ingress experiment is a fixed-upstream relay set. It does not parse
HTTP, HTTP/3, or DNS semantics; it only verifies transparent delivery and event
capture.

Default local listeners:

```text
control: 127.0.0.1:9977
dns:     127.0.0.1:1053  -> 1.1.1.1:53
tcp:     127.0.0.1:18080 -> 93.184.216.34:80
udp:     127.0.0.1:18443 -> 1.1.1.1:443
```

Cold-start bind/upstream values can be overridden with environment variables:

```text
DYNET_CONTROL_BIND
DYNET_DNS_BIND
DYNET_DNS_UPSTREAM
DYNET_DNS_TIMEOUT_MS
DYNET_TCP_BIND
DYNET_TCP_UPSTREAM
DYNET_UDP_BIND
DYNET_UDP_UPSTREAM
DYNET_UDP_IDLE_TIMEOUT_MS
```

## Development

```bash
cargo fmt --all --check
flavor check --root . --config flavor.json
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
scripts/smoke/ingress.sh
```
