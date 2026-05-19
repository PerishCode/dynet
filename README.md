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
dynet doctor --config dynet.json  # local/VM cold-start readiness checks
dynet plan --config dynet.json    # explain explicit route plan ordering
dynet install --check --config dynet.json
dynet status
dynet verify
dynet repair
dynet uninstall
dynet api capabilities            # list local API surface
dynet api serve --bind 127.0.0.1:9977
dynet run --config dynet.json     # validates config; runtime is not implemented yet
dynet version
dynet help
```

`dynet check` exits `1` when the config cannot be read, parsed, or validated.
`dynet doctor` reports config, platform, tun, resolver, and API bind readiness.
`dynet plan` turns explicit route rules into an explainable plan. `dynet
install --check` validates network ownership preflight and lists dynet-owned
resources plus render-only nft/tun/DNS desired-state artifacts and validation
status without mutating system network paths. `status`, `verify`, `repair`, and
`uninstall` report the current dynet-owned resource state; mutating network
apply/cleanup is intentionally gated until the ownership invariants are proven.
`dynet api serve` is a loopback-only HTTP skeleton with `/health` and
`/v1/capabilities`.
`dynet run` currently validates config and exits `1` after reporting that
runtime execution has not been implemented.

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

Inbound and outbound nodes are dynamic network objects. The stable node fields
are `tag`, `type`, optional `id`, optional `capabilities`, optional
`constraints`, and optional `metadata`; protocol-specific fields stay on the
same object as payload for the protocol adapter. `tag` is the user-facing route
reference, while dynet derives an internal fingerprint for state/history
matching.

Pure TCP and UDP nodes are first-class model fixtures:

```json
{
  "inbounds": [
    {
      "tag": "tcp-in",
      "type": "tcp",
      "listen": "127.0.0.1",
      "listenPort": 1080
    }
  ],
  "outbounds": [
    {
      "tag": "tcp-out",
      "type": "tcp",
      "server": "example.com",
      "serverPort": 443
    }
  ],
  "routes": [
    { "inbound": "tcp-in", "outbound": "tcp-out" }
  ]
}
```

Built-in capability inference currently covers `tcp`, `udp`, `dns`,
`ip-target`, `domain-target`, `transparent`, and `probeable`. Unknown
capabilities are preserved with warnings so future protocol adapters can evolve
without turning the core model into a protocol-specific schema dump.

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
cargo run --locked -p dynet-cli -- doctor --config dynet.json
cargo run --locked -p dynet-cli -- plan --config dynet.json
cargo run --locked -p dynet-cli -- install --check --config dynet.json
cargo run --locked -p dynet-cli -- status
cargo run --locked -p dynet-cli -- verify
cargo run --locked -p dynet-cli -- api capabilities
cargo zigbuild --locked --target x86_64-unknown-linux-gnu -p dynet-cli
python3 scripts/vmctl.py dev --host fuisp guest dynet-smoke --user ubuntu
```

## VM Lab Tooling

The VM lab scripts are local operator tools for disposable dynet experiments on
the remote KVM host. The physical host remains control-plane only; tun, DNS,
route, firewall, and failure-injection experiments belong inside guests.

```bash
python3 scripts/vmctl.py image catalog
python3 scripts/vmctl.py image --host fuisp list
python3 scripts/vmctl.py image --host fuisp ensure ubuntu-24.04
python3 scripts/vmctl.py image --host fuisp overlay ubuntu-24.04 dynet-smoke
python3 scripts/vmctl.py net --host fuisp list
python3 scripts/vmctl.py net --host fuisp start default
python3 scripts/vmctl.py guest --host fuisp key-ensure
python3 scripts/vmctl.py guest --host fuisp cloud-init dynet-smoke --image ubuntu-24.04
python3 scripts/vmctl.py guest --host fuisp status
python3 scripts/vmctl.py snapshot --host fuisp create dynet-smoke dynet-installed --force
python3 scripts/vmctl.py snapshot --host fuisp revert dynet-smoke dynet-installed --yes
python3 scripts/vmctl.py check --host fuisp guest dynet-smoke
python3 scripts/vmctl.py dev --host fuisp guest dynet-smoke --user ubuntu
python3 scripts/vmctl.py setup --host fuisp install-bin dynet-smoke target/x86_64-unknown-linux-gnu/debug/dynet --user ubuntu
python3 scripts/vmctl.py smoke --host fuisp guest dynet-smoke --label cold-start --user ubuntu
python3 scripts/vmctl.py collect --host fuisp guest dynet-smoke --label baseline --user ubuntu
python3 scripts/vmctl.py capture --host fuisp host dynet-smoke --label probe --duration 4 --filter 'icmp or arp' --probe 'ping -c 1 192.168.122.1'
python3 scripts/vmctl.py capture --host fuisp guest dynet-smoke --label probe --duration 4 --iface enp1s0 --filter 'icmp or arp' --probe 'ping -c 1 192.168.122.1'
python3 scripts/vmctl.py cleanup --host fuisp report
python3 scripts/vmctl.py cleanup --host fuisp prune-remote pcap --older-than-days 7
python3 scripts/vmctl.py cleanup prune-local pcap --older-than-days 7
```

`scripts/vm/image.py` owns image-layer operations. `scripts/vm/setup.py` owns
staging and installing local dynet artifacts into guests. `scripts/vm/guest.py`
owns guest definitions and lifecycle commands. `scripts/vm/net.py` owns explicit
libvirt network operations. `scripts/vm/snapshot.py` owns offline qcow2
snapshot/revert operations. `scripts/vm/collect.py` owns host/guest evidence
bundles. `scripts/vm/check.py` owns high-level readiness checks.
`scripts/vm/capture.py` owns short scoped packet captures on guest tap
interfaces or inside guest interfaces. `scripts/vm/cleanup.py` owns resource
usage reporting and safe pruning for generated cache/artifact buckets.
`scripts/vm/smoke.py` owns guest cold-start smoke checks for dynet CLI/API
contracts. `scripts/vm/dev.py` owns the high-frequency build/install/smoke/check
developer loop.

Commands that can grow image caches, overlays, cloud-init seeds, staged
artifacts, snapshots, evidence bundles, or pcaps print current resource usage
before mutating state. Each guarded bucket has warning and fail thresholds; fail
thresholds stop growth commands. Remote paths are constrained under the lab root
and local fetched artifacts are constrained under `dist/lab/`. Cleanup commands
preview candidates by default and require `--yes` before deletion.
VM tooling diagnostics are logged to stderr through the shared VM logger. Use
`--log-level error|warning|info|debug|trace` or `DYNET_VM_LOG_LEVEL` to adjust
verbosity; `--verbose` implies debug. Stdout is reserved for command results
such as paths, catalog rows, guest IPs, and check status lines.
`setup install-bin` rejects non-ELF host binaries by default so a macOS build is
not accidentally installed into a Linux guest.
`dev guest` builds the Linux guest artifact with `cargo zigbuild`, installs it,
runs smoke checks, and finishes with guest readiness checks. If install, smoke,
or readiness fails after the guest has been touched, `dev guest` collects a
host/guest evidence bundle by default. Add `--capture-on-failure` when packet
evidence is useful. `check guest` and `smoke guest` verify the guest default
route, resolver, DNS lookup, and HTTPS egress before dynet network ownership is
enabled. `smoke guest` also probes the real loopback API `/health` endpoint
through `dynet api serve --once`.
