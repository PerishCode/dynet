# VM Tooling

`scripts/vm/` contains local operator tooling for the dynet VM lab. These
scripts are allowed to orchestrate the remote KVM/libvirt host, but dynet
network experiments must stay inside disposable guests.

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
- Cleanup commands must preview candidates by default, require `--yes` for
  deletion, and operate only on named managed buckets or validated guest/image
  names.
- Prefer explicit commands with clear names over hidden workflow magic.
- Keep scripts dependency-light. Use the Python standard library unless a real
  repeated need justifies a dependency.

## File Roles

- `common.py` owns shared SSH, path, libvirt, and guest helper functions.
- `capture.py` owns packet captures scoped to guest tap interfaces or guest
  internal interfaces.
- `check.py` owns high-level readiness checks that compose lower-level tools.
- `cleanup.py` owns resource usage reporting and safe pruning of generated lab
  cache/artifact buckets.
- `collect.py` owns host/guest evidence bundles for lab runs.
- `image.py` owns cloud image catalog, downloads, image validation, and overlay
  creation.
- `net.py` owns explicit libvirt network visibility and start/stop/autostart
  operations.
- `guest.py` owns guest definitions and lifecycle commands.
- `snapshot.py` owns offline qcow2 snapshot create/revert/delete operations.
- `setup.py` owns staging and installing local dynet artifacts into guests.

When a script starts owning a new lifecycle layer, document that role here.
