# Experiment Tooling

`scripts/experiments/` owns standalone experimental tools that support dynet
product research without becoming product runtime code.

## Boundaries

- Keep experiment tools black-box unless a tool explicitly says otherwise.
  Black-box tools must not read dynet runtime state, call dynet APIs, or depend
  on dynet route/verdict/event internals.
- Keep identity out of real-access probes by default: no cookies,
  Authorization headers, browser profiles, login sessions, POSTs, or
  account-specific flows.
- Store generated profiles, manifests, and run reports under `.task/resources`
  by default. Keep `.task/` out of git.
- Scripts may read local operator logs when explicitly invoked, but generated
  artifacts should store aggregates rather than raw log lines.
- Use only the Python standard library unless a repeated experiment need
  justifies a dependency.

## File Roles

- `clash_verge_profile.py` cleans local Clash Verge Rev service logs into a
  privacy-preserving access profile.
- `clash_profile_taxonomy.py` owns static suffix/category taxonomy used by
  `clash_verge_profile.py`.
- `real_access_blackbox.py` builds deterministic replay manifests from an
  access profile and runs zero-identity black-box network probes.
- `dynet_probe_manifest.py` replays selected manifest HTTPS targets through
  `dynet probe` so black-box fault signals can be rerun with dynet route,
  plan, outbound, and stage events.
- `dynet_probe_quality.py` builds TTL/windowed outbound quality state from
  dynet probe reports.
- `dynet_trace_attribution.py` summarizes dynet runtime event reports into
  route/plan/outbound/stage attribution evidence that can be compared with
  black-box probe failures, and aggregates repeated summaries into
  planner-safe batch evidence.
- `dynet_trace/` owns helper modules for trace attribution event summaries,
  workload correlation, batch gates, and report rendering. Keep
  `dynet_trace_attribution.py` as the CLI entrypoint.
- `real_access/` owns helper modules for real-access manifest sampling,
  zero-identity probe execution, run aggregation, comparison, and report
  rendering. Keep `real_access_blackbox.py` as the CLI entrypoint.
- `tunnel_private_config.py` owns Clash/Tunnel provider loading, bootstrap
  resolution, and dynet config construction for Tunnel-to-Private experiments.
- `tunnel_private_lab.py` owns CLI commands that build/probe those configs and
  write sanitized run reports.
