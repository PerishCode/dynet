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

Commands that can grow image caches, overlays, cloud-init seeds, staged
artifacts, snapshots, evidence bundles, or pcaps print current resource usage
before mutating state. Each guarded bucket has warning and fail thresholds; fail
thresholds stop growth commands. Remote paths are constrained under the lab root
and local fetched artifacts are constrained under `dist/lab/`. Cleanup commands
preview candidates by default and require `--yes` before deletion.
