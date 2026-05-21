# AGENTS

`dynet` is a sing-box-like proxy CLI skeleton. It owns CLI shape, config
loading, report output, release packaging, and future proxy runtime boundaries.
It does not yet own concrete protocol implementations, route engines, or
service supervision.

`dynet` is also a new experimental VPN tool for complex user needs. It should
learn high-value lessons from sing-box, Clash, WireGuard, and Tailscale without
becoming a compatibility-first clone of any of them. Aggressively drop
historical baggage when it blocks a cleaner design. During active development,
repeated refactors and breaking changes are expected; prefer an excellent final
shape over preserving early internal APIs, config formats, or implementation
choices.

## Directory Rules

- `crates/` contains Rust workspace crates. Each crate owns its local
  `AGENTS.md`; read the child file before editing that subtree.
- `crates/dynet-cli/` owns the installable `dynet` binary, command parsing,
  config discovery, reports, exit codes, and CLI-facing behavior.
- `crates/dynet-core/` owns shared config/domain primitives and validation
  contracts that should not depend on CLI rendering or filesystem discovery.
- `crates/dynet-runtime/` owns the self-written Linux runtime boundary for TUN,
  DNS hijack serving, DNS chain execution, takeover apply/cleanup, socket
  marking, and future outbound adapters.
- `crates/*/harness/` contains representative fixtures owned by that crate.
  Harness fixtures should not become runtime discovery inputs.
- `.github/workflows/` contains CI and release workflows.
- `.github/scripts/` contains workflow-only helper scripts. Keep workflow-only
  scripts there.
- `scripts/init.py` is the idempotent post-clone initializer.
- `scripts/experiments/` owns standalone experiment tooling for access-profile
  cleaning, black-box real-access probes, dynet-observed probe reruns,
  TTL/windowed quality summaries, and trace attribution summaries; read
  `scripts/experiments/AGENTS.md` before editing that subtree.
- `scripts/vmctl.py` is the local aggregate entrypoint for VM lab operations.
- `scripts/vm/` owns VM lab lifecycle tooling; read `scripts/vm/AGENTS.md`
  before editing that subtree.
- `install.sh` and `install.ps1` are the public installation entrypoints at the
  repository root.
- `flavor.json` owns the code-shape/style scan for supported source files.
- Release and installer downloads use R2 metadata and artifacts as the source
  of truth.

When adding or removing a core subtree, update this file in the same change.

## Project Boundaries

- Keep the CLI entrypoint thin: parse command, resolve config, dispatch work,
  render output, return exit code.
- Favor clear final architecture over backward compatibility while the project
  is experimental.
- Do not preserve temporary APIs, config shapes, or module boundaries solely
  because they already exist.
- Keep runtime/protocol implementation details out of `dynet-cli`.
- Keep reusable config and validation contracts in `dynet-core`.
- Keep TUN/DNS/platform mutation and future outbound adapters in
  `dynet-runtime`; do not wrap a generic TUN-to-proxy binary as dynet's product
  runtime shape.
- Keep DNS chain modeling in `dynet-core` and DNS chain execution in
  `dynet-runtime`. Plain upstream UDP DNS is diagnostic only; product DNS
  evidence should go through explicit chains such as DoH with bootstrap IPs.
- Keep dynamic inbound/outbound node modeling in `dynet-core`: stable node
  identity/capability fields belong above protocol payloads, while concrete
  protocol adapters and runtime forwarding stay out of this repo slice.
- Keep harnesses local to the crate whose boundary they exercise.
- Keep VM tooling diagnostics on the shared `scripts/vm/common.py` logger.
  Reserve stdout for command results that callers may parse or compose.
- The loopback-only `dynet api serve` skeleton is an explicit cold-start API
  boundary. Do not turn it into product runtime/network execution without a
  separate runtime crate/boundary.
- `dynet install --check`, `status`, `verify`, `repair`, and `uninstall` are
  the first platform ownership lifecycle boundary. CLI owns reporting; runtime
  owns any real network mutation and cleanup.

## Observability And Attribution

- Observability has priority over planner, protocol, and node-quality
  optimization. Do not optimize a strategy before dynet can explain where the
  current failures occurred.
- Treat local clients, disposable VMs, and the KVM lab as product dogfooding
  surfaces. Black-box workloads are symptom generators; attribution must come
  from dynet runtime events, reports, traces, quality state, and stage timings.
- Preserve stable correlation whenever a feature touches traffic flow:
  workload entry -> DNS query/cache record -> rule/route decision -> outbound
  or plan -> selected candidate/bound -> dialer attempt -> TCP/UDP session ->
  protocol stage -> close reason/error.
- Every retained failure should be classifiable as one of:
  `node-suspect`, `dynet-infra-suspect`, `plan-suspect`,
  `target-or-probe-suspect`, `experiment-shape-suspect`, or `unknown`.
  `unknown` is acceptable only when the missing evidence fields are named.
- Do not claim "node unreliable" without repeatable correlation to a selected
  node/candidate plus stage evidence. Do not claim "plan bad" without
  repeatable correlation to planner selection, state, or fallback behavior.
- Batch gates should separate non-node attribution cleanliness from node
  quality confidence. Single-run `node-suspect` evidence may be retained as
  observe-only, but it must not become a planner penalty until it repeats with
  runtime-backed candidate and stage evidence.
- Keep user identity out of observability artifacts by default. Do not retain
  cookies, Authorization headers, account state, provider secrets, raw response
  bodies, or response headers unless a later scoped experiment explicitly adds
  sanitized capture.
- Prefer structured events and machine-readable summaries over log-only
  debugging. Human logs may explain, but artifacts should let scripts join and
  classify evidence without text scraping.

## Common Commands

```bash
python3 scripts/init.py
cargo fmt --all --check
flavor check --root . --config flavor.json
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo run --locked -p dynet-cli -- check --root . --config dynet.json
cargo run --locked -p dynet-cli -- doctor --config dynet.json
cargo run --locked -p dynet-cli -- plan --config dynet.json
cargo run --locked -p dynet-cli -- install --check --config dynet.json
cargo run --locked -p dynet-cli -- status
cargo run --locked -p dynet-cli -- verify
cargo run --locked -p dynet-cli -- api capabilities
python3 scripts/vmctl.py --help
python3 scripts/vmctl.py guest --host fuisp status
python3 scripts/vmctl.py snapshot --host fuisp list dynet-smoke
python3 scripts/vmctl.py check --host fuisp guest dynet-smoke
python3 scripts/vmctl.py dev --host fuisp guest dynet-smoke --user ubuntu
python3 scripts/vmctl.py smoke --host fuisp guest dynet-smoke --label cold-start --user ubuntu
python3 scripts/vmctl.py collect --host fuisp guest dynet-smoke --label baseline --user ubuntu
python3 scripts/vmctl.py capture --host fuisp host dynet-smoke --label probe --duration 4 --filter 'icmp or arp' --probe 'ping -c 1 192.168.122.1'
python3 scripts/vmctl.py cleanup --host fuisp report
python3 scripts/experiments/clash_verge_profile.py --help
python3 scripts/experiments/real_access_blackbox.py --help
python3 scripts/experiments/dynet_probe_manifest.py --help
python3 scripts/experiments/dynet_probe_quality.py --help
python3 scripts/experiments/dynet_trace_attribution.py --help
```

## Standard Workflow

- CLI shape changes update help text and focused CLI unit tests.
- Config or output compatibility changes should call that out in PR text.
- Runtime/protocol features should land behind crate-owned tests or harness
  fixtures, not by coupling CLI tests to private implementation details.
- Release script changes should keep Unix and Windows paths aligned.

## FAQ

### Does `dynet run` Start A Proxy Yet?

It starts the self-owned runtime boundary for Linux TUN packet observation,
real DNS hijack forwarding through dynet DNS chains, and DNS reverse capture.
Full TCP/UDP forwarding and concrete outbound protocol adapters are still
future work.

### Where Do Protocol Backends Belong?

In `dynet-runtime` or a crate below it. `dynet-cli` should consume stable
contracts and reports, not backend-specific parser or network types.
