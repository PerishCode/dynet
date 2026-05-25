# Experiment Tooling

`scripts/experiments/` owns standalone experimental helper packages that
support dynet product research without becoming product runtime code. Public
experiment entrypoints live under `scripts/cli/` and should be invoked from
the repo root with `uv --project scripts run python -m scripts.cli.<entry>`.

## Boundaries

- Keep experiment tools black-box unless a tool explicitly says otherwise.
  Black-box tools must not read dynet runtime state, call dynet APIs, or depend
  on dynet route/verdict/event internals.
- Keep identity out of real-access probes by default: no cookies,
  Authorization headers, browser profiles, login sessions, POSTs, or
  account-specific flows.
- Store generated profiles, manifests, and run reports under `.task/resources`
  by default. Keep `.task/` out of git.
- CLI entrypoints live under `scripts/cli/`; keep reusable experiment logic in
  `scripts/experiments/`.
- Scripts may read local operator logs when explicitly invoked, but generated
  artifacts should store aggregates rather than raw log lines.
- Use only the Python standard library unless a repeated experiment need
  justifies a dependency.

## File Roles

- `scripts/cli/clash_verge_profile.py` cleans local Clash Verge Rev service
  logs into a privacy-preserving access profile.
- `clash_profile_taxonomy.py` owns static suffix/category taxonomy used by
  `scripts/cli/clash_verge_profile.py`.
- `scripts/cli/dynet_clash_contract.py` builds a GitHub-focused dynet-vs-Clash
  proof contract from sanitized Clash profile aggregates.
- `scripts/cli/dynet_clash_compare.py` compares a real-access Clash baseline
  summary with a dynet probe manifest summary for the GitHub proof lane, and its `batch`
  subcommand aggregates repeated comparison JSONs into proof gates for scheduler
  cleanliness, guardrails, and repeated primary bucket advantage. Its `gap`
  subcommand explains repeated product-effect parity vs superiority gaps from
  comparison, paired replay, Clash failure-cluster, and dynet probe surfaces.
  Its `gap-drilldown` subcommand joins retained dynet-only and both-fail
  paired rows back to dynet probe event reports. Its `gap-recommend`
  subcommand turns gap/drilldown evidence into an explicit observe/policy/
  planner-feedback recommendation. Its `gap-retry` subcommand reruns retained
  direct TLS EOF rows with an experiment-only retry policy and records whether
  retry explains the product-effect gap. Its `gap-protocol-retry` subcommand
  reruns retained protocol-read rows with an experiment-only external retry
  policy and records whether repeated probe attempts recover or drift. Its
  `gap-read-budget` subcommand reruns retained protocol-read rows with a scoped
  probe read policy and records whether the read-budget surface persists or
  changes. Its `paired-read-surface` subcommand joins paired replay timing with
  protocol read follow-up summaries so side order, stagger, and read-surface
  evidence are machine-readable.
- `dynet_clash/` owns helper modules for dynet-vs-Clash comparison modes that
  are too large to keep in the single-window CLI entrypoint. Paired replay
  may run experiment-only dynet-side direct TLS EOF retries, but this must stay
  opt-in and artifact-visible.
- `scripts/cli/real_access_blackbox.py` builds deterministic replay manifests
  from an access profile and runs zero-identity black-box network probes.
- `scripts/cli/dynet_probe_manifest.py` replays selected manifest HTTPS targets
  through `dynet probe` so black-box fault signals can be rerun with dynet
  route, plan, outbound, and stage events.
- `dynet_probe/` owns helper modules for dynet probe manifest replay flows
  that are too large for the CLI entrypoint, including post-run quality-state
  refresh.
- `scripts/cli/dynet_probe_quality.py` builds TTL/windowed outbound quality
  state from dynet probe reports.
- `scripts/cli/dynet_trace_attribution.py` summarizes dynet runtime event
  reports into route/plan/outbound/stage attribution evidence that can be
  compared with black-box probe failures, and aggregates repeated summaries
  into planner-safe batch evidence.
- `dynet_trace/` owns helper modules for trace attribution event summaries,
  workload correlation, probe-manifest attribution, batch gates, and report
  rendering. Keep `scripts/cli/dynet_trace_attribution.py` as the CLI
  entrypoint.
- `dynet_mainline/` owns cross-surface mainline baseline gates and runtime
  hardening handoffs that combine already-sanitized product-effect,
  runtime-pressure, and read-surface artifacts into policy-safe next-step
  evidence.
- `dynet_mainline/runtime_surface/` owns aggregate-only runtime surface readers
  for mainline gates. Keep raw targets, outbound identities, candidates, and
  error text out of these summaries.
- `real_access/` owns helper modules for real-access manifest sampling,
  zero-identity probe execution, optional sanitized Clash controller
  attribution, run aggregation, comparison, and report rendering. Keep
  `scripts/cli/real_access_blackbox.py` as the CLI entrypoint.
- `probe_smoke/` owns local dynet probe smoke helpers that write sanitized
  artifacts under `.task/resources`, including non-direct `tcp-connect`
  candidate, dialer-to-private outbound, repeated selected-vs-best quality-gap
  probes, and repeated manifest-window quality refresh controls.
- `tunnel_private_config.py` owns Clash/Tunnel provider loading, bootstrap
  resolution, and dynet config construction for Tunnel-to-Private experiments.
- `scripts/cli/tunnel_private_lab.py` owns CLI commands that build/probe those
  configs and write sanitized run reports.
- `tunnel_private/` owns helper modules for Tunnel-to-Private experiment
  commands that are too large to keep in the CLI entrypoint, including matrix
  comparison, adapter readiness/product-effect gates, controlled target
  observation, and temporary self-owned Private control services.
