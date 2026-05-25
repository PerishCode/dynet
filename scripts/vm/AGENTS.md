# VM Tooling

`scripts/vm/` contains local operator tooling for the dynet VM lab. The public
aggregate entrypoint is `scripts/cli/vmctl.py`; invoke it from the repo root
with `uv --project scripts run python -m scripts.cli.vmctl`. VM modules are
allowed to orchestrate the remote KVM/libvirt host, but dynet network
experiments must stay inside disposable guests.

## Boundaries

- Keep the physical host as control plane: image cache, VM definitions,
  snapshots, artifact staging, and evidence collection.
- Do not change host DNS, host resolver state, host default route, host tun, or
  host firewall policy for dynet experiments.
- Do not start libvirt networks, create VMs, destroy VMs, or revert snapshots as
  side effects of read-only/status commands.
- Any command that can rapidly grow cache, snapshot, archive, pcap, or staged
  artifact resources must report existing usage at the start, apply warning and
  fail thresholds, and keep all paths inside the configured lab root or local
  `dist/lab/`.
- Use `logger.xxx` from `common.py` for diagnostics, progress, resource reports,
  warnings, and errors. Keep stdout for command results that can be piped or
  parsed, such as paths, catalog rows, guest IPs, and check status lines.
- Cleanup commands must preview candidates by default, require `--yes` for
  deletion, and operate only on named managed buckets or validated guest/image
  names.
- Prefer explicit commands with clear names over hidden workflow magic.
- Keep scripts dependency-light. Use the Python standard library unless a real
  repeated need justifies a dependency.

## File Roles

- `common.py` is the compatibility facade for shared SSH, path, logging,
  libvirt, resource, and guest helpers.
- `lib/common_resources.py` owns resource usage scans, reports, and guard
  helpers used by VM lab commands.
- `lib/common_guest.py` owns guest key, guest IP, guest SSH, guest SCP, and
  remote command argument helpers.
- `lib/interface.py` owns guest interface detection and validation for scoped
  outbound socket binding in VM experiments.
- `lib/probe_summary.py` owns sanitized dynet probe event summarization helpers
  shared by VM probe/runtime entrypoints.
- `ops/capture.py` owns packet captures scoped to guest tap interfaces or guest
  internal interfaces.
- `ops/check.py` owns high-level readiness checks that compose lower-level tools,
  including guest default route, resolver, DNS lookup, and HTTPS egress
  baselines.
- `ops/cleanup.py` owns resource usage reporting and safe pruning of generated lab
  cache/artifact buckets.
- `ops/collect.py` owns host/guest evidence bundles for lab runs.
- `ops/dev.py` owns high-frequency developer loops that compose local Linux artifact
  builds, guest installation, smoke checks, and readiness checks.
- `image.py` owns cloud image catalog, downloads, image validation, and overlay
  creation.
- `net.py` owns explicit libvirt network visibility and start/stop/autostart
  operations.
- `guest.py` owns guest definitions and lifecycle commands.
- `private_probe.py` owns VM guest execution of sanitized Private cascade
  acceptance probes. It may use local provider material to generate temporary
  dynet-native configs, but retained artifacts must remain sanitized and secret
  configs must be written only to guest temp files and cleaned after probing.
  Its paired mode coordinates local Clash black-box probes with VM guest
  dynet probes when an adapter needs Linux interface-bound product-effect
  comparison evidence.
- `private_runtime.py` owns VM guest execution of sanitized Private cascade
  runtime acceptance. It verifies `dynet run` takeover, DNS hijack, scoped
  quality-driven dialer selection, TUN packet observation, cleanup, and retained
  sanitized runtime reports without retaining secret configs.
- `private_runtime_lib/` owns helper modules for the Private runtime acceptance
  entrypoint: generated guest probe scripts, runtime command construction, VM
  orchestration, summaries, checks, and sanitized report rendering.
- `private_runtime_lib/reporting/` owns local post-processing for retained
  runtime artifacts, including repeat, round-gap, cascade-stop, stage-pressure,
  and workload-surface attribution summaries.
- `private_runtime_lib/tcp_flow/` owns TCP flow/workload correlation and
  primary-vs-fallback dialer-bound selection summaries used by runtime
  acceptance gates.
- `probe_smoke.py` owns VM guest execution of sanitized non-direct adapter
  smoke probes. It stages local smoke helpers into guest temp files, collects
  reports back under `.task/resources`, and verifies attribution, probe-batch,
  quality-state, and offline plan artifacts.
- `smokes/quality_gap.py` owns VM guest execution of sanitized repeated
  selected-vs-best quality-gap smoke probes. It keeps guest work to raw probe
  collection and runs attribution, quality-state, plan, and verification on
  the host after collection.
- `smoke.py` owns VM guest cold-start smoke checks that exercise guest network
  access, dynet CLI contracts, loopback API health, and the minimal
  install/run/uninstall TUN + DNS runtime boundary inside a disposable guest.
- `snapshot.py` owns offline qcow2 snapshot create/revert/delete operations.
- `setup.py` owns staging and installing local dynet artifacts into guests.

When a script starts owning a new lifecycle layer, document that role here.
