from __future__ import annotations

import argparse
from pathlib import Path
from typing import Callable

from tunnel_private_config import MERGED_CONFIG, PROVIDER_DIR


PROTOCOLS = ["tcp-connect", "https-head", "tls-handshake"]
Handler = Callable[[argparse.Namespace], int]

MAINLINE_BASELINE_ARGS = """
adapter-product-effect runtime-pressure runtime-fallback runtime-dns-product
runtime-dns-refresh runtime-dns-forward runtime-quality-plan
runtime-route-refresh runtime-selection-refresh runtime-workload-flow
runtime-quality-workload runtime-workload-surface runtime-close-surface
runtime-payload-surface runtime-event-stream runtime-event-correlation
runtime-event-causality runtime-failure-attribution runtime-failure-impact
runtime-stage-surface runtime-timing-surface runtime-dns-timing
runtime-outbound-timing runtime-outbound-attempt runtime-candidate-set
runtime-candidate-quality runtime-failure-propagation runtime-stage-chain
runtime-stage-order runtime-route-decision runtime-outbound-gate
runtime-outbound-retry runtime-packet-surface runtime-tcp-pressure
runtime-tcp-target runtime-stage-pressure runtime-udp-session runtime-ipv6-denial
runtime-takeover-lifecycle runtime-retained-artifact runtime-exit-limit
runtime-collection-stage runtime-cascade-stop runtime-round-gap
runtime-round-gap-compare runtime-flow-refresh runtime-cascade-refresh
runtime-target-identity quality-feedback
plan-quality-bridge runtime-udp runtime-ipv6 runtime-guardrail
paired-read-surface recommendation
""".split()


def build_tunnel_private_parser(handlers: dict[str, Handler]) -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build and probe dynet-native Tunnel-to-Private configs."
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    add_build(subparsers, handlers["build"])
    add_probe_candidates(subparsers, handlers["probe_candidates"])
    add_probe_plan(subparsers, handlers["probe_plan"])
    add_probe_private(subparsers, handlers["probe_private"])
    add_matrix(subparsers, handlers["matrix"])
    add_compare_matrices(subparsers, handlers["compare_matrices"])
    add_observe_target(subparsers, handlers["observe_target"])
    add_observe_owned_private(subparsers, handlers["observe_owned_private"])
    add_quality_refresh(subparsers, handlers["quality_refresh"])
    add_quality_regression(subparsers, handlers["quality_regression"])
    add_quality_sweep(subparsers, handlers["quality_sweep"])
    add_quality_sweep_summary(subparsers, handlers["quality_sweep_summary"])
    add_transport_check(subparsers, handlers["transport_check"])
    add_transport_evidence(subparsers, handlers["transport_evidence"])
    add_adapter_readiness(subparsers, handlers["adapter_readiness"])
    add_adapter_maturity(subparsers, handlers["adapter_maturity"])
    add_adapter_product_effect(subparsers, handlers["adapter_product_effect"])
    add_mainline_baseline(subparsers, handlers["mainline_baseline"])
    add_mainline_provider_availability(
        subparsers,
        handlers["mainline_provider_availability"],
    )
    add_mainline_adapter_coverage(subparsers, handlers["mainline_adapter_coverage"])
    add_mainline_runtime_handoff(subparsers, handlers["mainline_runtime_handoff"])
    add_protocol_followup(subparsers, handlers["protocol_followup"])
    add_protocol_followup_batch(subparsers, handlers["protocol_followup_batch"])
    add_paired(subparsers, handlers["paired"])
    add_inspect_plan_quality(subparsers, handlers["inspect_plan_quality"])
    add_compare_plan_quality(subparsers, handlers["compare_plan_quality"])
    return parser


def add_build(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    build = subparsers.add_parser("build")
    add_common(build)
    build.add_argument("--output-config", required=True)
    build.add_argument("--output-meta", required=True)
    build.set_defaults(handler=handler)


def add_probe_candidates(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    probe = subparsers.add_parser("probe-candidates")
    add_probe_common(probe)
    probe.add_argument("--attempts", type=int, default=1)
    probe.add_argument("--probe-mode", choices=["private", "candidate"], default="private")
    probe.set_defaults(handler=handler)


def add_probe_plan(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    probe_plan = subparsers.add_parser("probe-plan")
    add_probe_common(probe_plan)
    probe_plan.add_argument("--probe-mode", choices=["private", "candidate"], default="private")
    probe_plan.set_defaults(handler=handler)


def add_probe_private(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    private = subparsers.add_parser("probe-private")
    add_probe_common(private)
    private.set_defaults(handler=handler)


def add_matrix(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    matrix = subparsers.add_parser("matrix")
    add_probe_common(matrix, protocol=False)
    matrix.set_defaults(handler=handler)


def add_compare_matrices(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    compare = subparsers.add_parser("compare-matrices")
    compare.add_argument("--output-dir", required=True)
    compare.add_argument("--matrix", action="append", required=True)
    compare.set_defaults(handler=handler)


def add_observe_target(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    observer = subparsers.add_parser("observe-target")
    add_probe_common(observer, protocol=False)
    observer.add_argument("--ssh-host", default="bandwagon")
    observer.add_argument("--target-host")
    observer.add_argument("--target-port", type=int, default=0)
    observer.add_argument("--server-timeout", type=float, default=70.0)
    observer.add_argument("--ready-timeout", type=float, default=10.0)
    observer.add_argument("--reply-text", default="dynet-observer-response")
    observer.set_defaults(handler=handler)


def add_observe_owned_private(
    subparsers: argparse._SubParsersAction,
    handler: Handler,
) -> None:
    owned = subparsers.add_parser("observe-owned-private")
    add_probe_common(owned, protocol=False)
    owned.add_argument("--ssh-host", default="fuisp")
    owned.add_argument("--private-host")
    owned.add_argument("--server-timeout", type=float, default=70.0)
    owned.add_argument("--ready-timeout", type=float, default=10.0)
    owned.add_argument("--owned-private-password", default="dynet-owned-private")
    owned.add_argument("--reply-text", default="dynet-owned-private-response")
    owned.set_defaults(handler=handler)


def add_quality_refresh(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    refresh = subparsers.add_parser("quality-refresh")
    add_probe_common(refresh)
    refresh.add_argument("--probe-mode", choices=["private", "candidate"], default="private")
    refresh.add_argument("--window-size", type=int, default=2)
    refresh.add_argument("--allow-failures", action="store_true")
    refresh.add_argument("--initial-quality-state")
    refresh.add_argument("--initial-attribution")
    refresh.add_argument("--quality-ttl-seconds", type=int, default=3600)
    refresh.add_argument("--quality-window-seconds", type=int, default=3600)
    refresh.set_defaults(handler=handler)


def add_paired(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    paired = subparsers.add_parser("paired")
    add_probe_common(paired, protocol=False)
    paired.add_argument("--manifest", required=True)
    paired.add_argument("--sudo", action="store_true")
    paired.add_argument("--dynet-direct-tls-retry-attempts", type=int, default=1)
    paired.add_argument("--dynet-direct-tls-retry-sleep-ms", type=int, default=250)
    paired.add_argument("--probe-read-poll-timeout-ms", dest="read_poll_ms", type=positive_int)
    paired.add_argument("--probe-read-pending-budget-ms", dest="read_budget_ms", type=non_negative_int)
    paired.add_argument("--probe-read-pending-sleep-ms", dest="read_sleep_ms", type=non_negative_int)
    paired.add_argument("--pair-limit", type=int)
    paired.add_argument("--bucket", action="append")
    paired.add_argument("--behavior", action="append")
    paired.add_argument("--probe-type", action="append")
    paired.add_argument("--timeout-seconds", type=float, default=5)
    paired.add_argument("--spacing-ms", type=int, default=250)
    paired.add_argument("--lag-budget-ms", type=int, default=1000)
    paired.add_argument("--schedule-scale", type=non_negative_float, default=1.0)
    paired.add_argument("--max-concurrency", type=int, default=1)
    paired.add_argument("--pair-scheduler", choices=["sequential", "open-loop"], default="sequential")
    paired.add_argument("--clash-environment", default="local-clash-paired")
    paired.add_argument("--replay-mode", default="paired-interleaved")
    paired.add_argument("--replay-schedule", action="store_true", default=True)
    paired.add_argument("--no-respect-schedule", action="store_false", dest="respect_schedule")
    paired.add_argument("--side-order", choices=["alternate", "clash-first", "dynet-first"], default="alternate")
    paired.add_argument("--side-mode", choices=["sequential", "parallel"], default="sequential")
    paired.add_argument("--parallel-side-stagger-ms", type=non_negative_int, default=0)
    paired.add_argument("--dynet-protocol", choices=["source", "tcp-connect", "https-head", "tls-handshake"], default="source")
    paired.add_argument("--clash-controller-unix-socket")
    paired.add_argument("--clash-controller-url")
    paired.add_argument("--clash-controller-secret")
    paired.add_argument("--clash-controller-hash-salt", default="dynet-clash-proof-v1")
    paired.add_argument("--clash-controller-poll-ms", type=int, default=100)
    paired.add_argument("--clash-controller-tail-ms", type=int, default=250)
    paired.set_defaults(respect_schedule=True)
    paired.set_defaults(handler=handler)


def add_quality_regression(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    regression = subparsers.add_parser("quality-regression")
    add_common(regression)
    regression.add_argument("--output-dir", required=True)
    regression.add_argument("--dynet-bin", default="target/debug/dynet")
    regression.add_argument("--target-url", default="https://chatgpt.com/")
    regression.add_argument("--protocol", choices=PROTOCOLS, default="https-head")
    regression.add_argument(
        "--gate-mode",
        choices=["product", "direct", "all"],
        default="product",
    )
    regression.add_argument(
        "--refresh-probe-mode",
        choices=["auto", "private", "candidate"],
        default="auto",
    )
    regression.add_argument("--window-size", type=int, default=3)
    regression.add_argument("--initial-quality-state")
    regression.add_argument("--initial-attribution")
    regression.add_argument("--quality-ttl-seconds", type=int, default=3600)
    regression.add_argument("--quality-window-seconds", type=int, default=3600)
    regression.add_argument("--refresh-require-pass", action="store_true")
    regression.add_argument("--require-candidate-direct", action="store_true")
    regression.add_argument("--baseline-matrix", action="append", default=[])
    regression.set_defaults(handler=handler)


def add_quality_sweep(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    sweep = subparsers.add_parser("quality-sweep")
    add_common(sweep)
    sweep.add_argument("--output-dir", required=True)
    sweep.add_argument("--dynet-bin", default="target/debug/dynet")
    sweep.add_argument("--target-url", action="append", required=True)
    sweep.add_argument("--protocol", choices=PROTOCOLS, default="https-head")
    sweep.add_argument("--gate-mode", choices=["product", "direct", "all"], default="product")
    sweep.add_argument("--refresh-probe-mode", choices=["auto", "private", "candidate"], default="auto")
    sweep.add_argument("--window-size", type=int, default=3)
    sweep.add_argument("--initial-quality-state")
    sweep.add_argument("--initial-attribution")
    sweep.add_argument("--quality-ttl-seconds", type=int, default=3600)
    sweep.add_argument("--quality-window-seconds", type=int, default=3600)
    sweep.add_argument("--refresh-require-pass", action="store_true")
    sweep.add_argument("--require-candidate-direct", action="store_true")
    sweep.add_argument("--baseline-matrix", action="append", default=[])
    sweep.add_argument("--sweep-offset", type=non_negative_int, action="append")
    sweep.add_argument("--sweep-allow-failures", action="store_true")
    sweep.set_defaults(handler=handler)


def add_quality_sweep_summary(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    summary = subparsers.add_parser("quality-sweep-summary")
    summary.add_argument("--output-dir", required=True)
    summary.add_argument("--sweep-summary", action="append", required=True)
    summary.set_defaults(handler=handler)


def add_transport_check(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    check = subparsers.add_parser("transport-check")
    add_common(check)
    check.add_argument("--output-dir", required=True)
    check.add_argument(
        "--check",
        choices=[
            "trojan-tls",
            "go-tls",
            "utls",
            "clash-delay",
            "mihomo-delay",
            "mihomo-proxy",
        ],
        default="trojan-tls",
    )
    check.add_argument("--timeout-seconds", type=float, default=5.0)
    check.add_argument("--clash-controller-unix-socket")
    check.add_argument("--clash-controller-url")
    check.add_argument("--clash-controller-secret")
    check.add_argument("--clash-delay-url", default="https://www.gstatic.com/generate_204")
    check.add_argument("--utls-fingerprint", action="append")
    check.add_argument(
        "--mihomo-bin",
        default="/Applications/Clash Verge.app/Contents/MacOS/verge-mihomo",
    )
    check.add_argument("--mihomo-probe-url", default="https://www.gstatic.com/generate_204")
    check.add_argument("--mihomo-interface-name")
    check.add_argument("--baseline-transport-summary", action="append", default=[])
    check.set_defaults(handler=handler)


def add_transport_evidence(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    evidence = subparsers.add_parser("transport-evidence")
    evidence.add_argument("--output-dir", required=True)
    evidence.add_argument("--transport-summary", action="append", required=True)
    evidence.set_defaults(handler=handler)


def add_adapter_readiness(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    readiness = subparsers.add_parser("adapter-readiness")
    readiness.add_argument("--output-dir", required=True)
    readiness.add_argument("--adapter-type", required=True)
    readiness.add_argument("--product-evidence", action="append", default=[])
    readiness.add_argument("--runtime-evidence", action="append", default=[])
    readiness.add_argument("--transport-evidence", action="append", default=[])
    readiness.set_defaults(handler=handler)


def add_adapter_maturity(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    maturity = subparsers.add_parser("adapter-maturity")
    maturity.add_argument("--output-dir", required=True)
    maturity.add_argument("--adapter-type", required=True)
    maturity.add_argument("--readiness", required=True)
    maturity.add_argument("--runtime-evidence", action="append", default=[])
    maturity.add_argument("--flow-refresh-evidence", action="append", default=[])
    maturity.add_argument("--cascade-stage-evidence", action="append", default=[])
    maturity.add_argument("--min-product-targets", type=int, default=4)
    maturity.add_argument("--min-runtime-runs", type=int, default=6)
    maturity.add_argument("--min-workload-attempted", type=int, default=12)
    maturity.add_argument("--min-runtime-targets", type=int, default=4)
    maturity.add_argument("--min-primary-candidates", type=int, default=2)
    maturity.set_defaults(handler=handler)


def add_adapter_product_effect(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    product_effect = subparsers.add_parser("adapter-product-effect")
    product_effect.add_argument("--output-dir", required=True)
    product_effect.add_argument("--adapter-type", required=True)
    product_effect.add_argument("--maturity", required=True)
    product_effect.add_argument("--dynet-product-evidence", action="append", default=[])
    product_effect.add_argument("--clash-transport-evidence", action="append", default=[])
    product_effect.add_argument("--runtime-evidence", action="append", default=[])
    product_effect.add_argument("--paired-evidence", action="append", default=[])
    product_effect.add_argument("--min-dynet-product-targets", type=int, default=4)
    product_effect.add_argument("--min-paired-windows", type=int, default=1)
    product_effect.add_argument("--min-paired-entries", type=int, default=0)
    product_effect.add_argument("--min-runtime-workload-entries", type=int, default=0)
    product_effect.set_defaults(handler=handler)


def add_mainline_baseline(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    baseline = subparsers.add_parser("mainline-baseline")
    baseline.add_argument("--output-dir", required=True)
    add_append_arguments(baseline, MAINLINE_BASELINE_ARGS)
    baseline.set_defaults(handler=handler)


def add_mainline_provider_availability(
    subparsers: argparse._SubParsersAction,
    handler: Handler,
) -> None:
    availability = subparsers.add_parser("mainline-provider-availability")
    add_common(availability)
    availability.add_argument("--output-dir", required=True)
    availability.add_argument("--expected-adapter-type", action="append", default=[])
    availability.add_argument("--historical-provider-meta", action="append", default=[])
    availability.set_defaults(handler=handler)


def add_mainline_adapter_coverage(
    subparsers: argparse._SubParsersAction,
    handler: Handler,
) -> None:
    coverage = subparsers.add_parser("mainline-adapter-coverage")
    coverage.add_argument("--output-dir", required=True)
    coverage.add_argument("--expected-adapter-type", action="append", default=[])
    coverage.add_argument("--mainline-baseline", action="append", default=[])
    coverage.add_argument("--provider-meta", action="append", default=[])
    coverage.add_argument("--provider-availability", action="append", default=[])
    coverage.add_argument("--adapter-product-effect", action="append", default=[])
    coverage.add_argument("--adapter-readiness", action="append", default=[])
    coverage.add_argument("--adapter-maturity", action="append", default=[])
    coverage.add_argument("--runtime-repeat", action="append", default=[])
    coverage.add_argument("--runtime-fallback", action="append", default=[])
    coverage.set_defaults(handler=handler)


def add_mainline_runtime_handoff(
    subparsers: argparse._SubParsersAction,
    handler: Handler,
) -> None:
    handoff = subparsers.add_parser("mainline-runtime-handoff")
    handoff.add_argument("--output-dir", required=True)
    handoff.add_argument("--mainline-baseline", action="append", required=True)
    handoff.add_argument("--adapter-coverage", action="append", required=True)
    handoff.add_argument("--runtime-stage-pressure", action="append", required=True)
    handoff.add_argument("--runtime-cascade-stop", action="append", required=True)
    handoff.add_argument("--runtime-round-gap", action="append", required=True)
    handoff.add_argument("--runtime-round-gap-compare", action="append", required=True)
    handoff.set_defaults(handler=handler)


def add_append_arguments(
    parser: argparse.ArgumentParser,
    names: list[str],
) -> None:
    for name in names:
        kwargs = {"action": "append", "default": []}
        if name == "adapter-product-effect":
            kwargs["required"] = True
        parser.add_argument(f"--{name}", **kwargs)


def add_protocol_followup(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    followup = subparsers.add_parser("protocol-followup")
    followup.add_argument("--output-dir", required=True)
    followup.add_argument("--readiness")
    followup.add_argument("--compare", action="append", default=[])
    followup.add_argument("--attribution", action="append", default=[])
    followup.add_argument("--report", action="append", default=[])
    followup.add_argument("--report-dir", action="append", default=[])
    followup.set_defaults(handler=handler)


def add_protocol_followup_batch(subparsers: argparse._SubParsersAction, handler: Handler) -> None:
    batch = subparsers.add_parser("protocol-followup-batch")
    batch.add_argument("--output-dir", required=True)
    batch.add_argument("--summary", action="append", required=True)
    batch.set_defaults(handler=handler)


def add_inspect_plan_quality(
    subparsers: argparse._SubParsersAction,
    handler: Handler,
) -> None:
    inspect = subparsers.add_parser("inspect-plan-quality")
    add_probe_common(inspect, protocol=False)
    inspect.add_argument(
        "--plan-quality-scope",
        choices=["dialer-bound", "plan-candidate"],
        default="dialer-bound",
    )
    inspect.set_defaults(handler=handler)


def add_compare_plan_quality(
    subparsers: argparse._SubParsersAction,
    handler: Handler,
) -> None:
    compare = subparsers.add_parser("compare-plan-quality")
    compare.add_argument("--output-dir", required=True)
    compare.add_argument("--inspection", action="append", required=True)
    compare.set_defaults(handler=handler)


def add_common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--merged-config", default=str(MERGED_CONFIG))
    parser.add_argument("--provider-dir", default=str(PROVIDER_DIR))
    parser.add_argument("--private-provider", default=str(PROVIDER_DIR / "private.yaml"))
    parser.add_argument("--tunnel-name", default="Tunnel")
    parser.add_argument("--filter")
    parser.add_argument("--private-name")
    parser.add_argument("--private-contains", default="Private")
    parser.add_argument("--private-server-ip")
    parser.add_argument("--resolve-private-server", action="store_true")
    parser.add_argument("--resolve-tunnel-server", action="store_true")
    parser.add_argument("--trojan-interface-name")
    parser.add_argument("--supported-type", action="append")
    parser.add_argument("--strategy-key", default="cascade-quality")
    parser.add_argument("--tcp-route-plan-private", action="store_true")
    parser.add_argument("--domain", action="append", default=[])
    parser.add_argument("--domain-suffix", action="append", default=["chatgpt.com"])
    parser.add_argument("--limit", type=int)
    parser.add_argument("--candidate-offset", type=non_negative_int, default=0)


def add_probe_common(parser: argparse.ArgumentParser, protocol: bool = True) -> None:
    add_common(parser)
    parser.add_argument("--output-dir", required=True)
    parser.add_argument("--dynet-bin", default="target/debug/dynet")
    parser.add_argument("--target-url", default="https://chatgpt.com/")
    parser.add_argument("--inbound")
    if protocol:
        parser.add_argument("--protocol", choices=PROTOCOLS, default="https-head")
    parser.add_argument("--quality-state")


def non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"expected integer: {value}") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def positive_int(value: str) -> int:
    parsed = non_negative_int(value)
    if parsed == 0:
        raise argparse.ArgumentTypeError("must be positive")
    return parsed


def non_negative_float(value: str) -> float:
    try:
        parsed = float(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError(f"expected number: {value}") from error
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed
