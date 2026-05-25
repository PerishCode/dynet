from __future__ import annotations

import argparse

from common import CommandError

POISON_TAG = "tunnel-poison-001"
POISON_BOUND_PLAN_TAG = "tunnel-poison-bound"
ROUTE_FALLBACK_TAG = "private-route-fallback"
POISON_DIALER_TAG = "private-via-poison-bound"
PRIVATE_DOWNSTREAM_POISON_HOST = "example.com"
PRIVATE_DOWNSTREAM_POISON_PORT = 80


def add_poison_bound_candidate(config: dict) -> None:
    ensure_poison_outbound(config)
    edges = tunnel_plan_edges(config, "poison candidate")
    if not any(isinstance(edge, dict) and edge.get("to") == POISON_TAG for edge in edges):
        edges.insert(0, {"type": "candidate", "to": POISON_TAG})


def set_poison_bound_only(config: dict) -> None:
    ensure_poison_outbound(config)
    edges = tunnel_plan_edges(config, "poison bound only")
    edges[:] = [{"type": "candidate", "to": POISON_TAG}]


def force_bound_candidate(config: dict, tag: str) -> None:
    edges = tunnel_plan_edges(config, "force bound candidate")
    matching = [edge for edge in edges if isinstance(edge, dict) and edge.get("to") == tag]
    if not matching:
        candidates = [
            str(edge.get("to"))
            for edge in edges
            if isinstance(edge, dict) and edge.get("type") == "candidate" and edge.get("to")
        ]
        raise CommandError(
            "--force-bound-candidate target not found: "
            + tag
            + " (available: "
            + ", ".join(candidates)
            + ")"
        )
    edges[:] = [matching[0]]


def poison_private_downstream(config: dict) -> None:
    private = next(
        (
            item
            for item in config.setdefault("outbounds", [])
            if isinstance(item, dict) and item.get("tag") == "private"
        ),
        None,
    )
    if not isinstance(private, dict):
        raise CommandError("generated config has no `private` outbound for downstream poison")
    metadata = private.setdefault("metadata", {})
    if isinstance(metadata, dict):
        metadata["purpose"] = "vm-runtime-non-bound-cascade-stop-proof"
    else:
        private["metadata"] = {"purpose": "vm-runtime-non-bound-cascade-stop-proof"}
    private["type"] = "trojan"
    private["capabilities"] = ["tcp", "domain-target", "ip-target", "probeable"]
    private["payload"] = {
        "server": PRIVATE_DOWNSTREAM_POISON_HOST,
        "port": PRIVATE_DOWNSTREAM_POISON_PORT,
        "password": "dynet-private-downstream-poison",
        "sni": PRIVATE_DOWNSTREAM_POISON_HOST,
        "skipCertVerify": True,
    }


def add_direct_fallback(config: dict, args: argparse.Namespace) -> None:
    if not getattr(args, "tcp_route_plan_private", False):
        raise CommandError("--tcp-route-direct-fallback requires --tcp-route-plan-private")
    outbounds = config.setdefault("outbounds", [])
    if not any(item.get("tag") == ROUTE_FALLBACK_TAG for item in outbounds if isinstance(item, dict)):
        outbounds.append(route_fallback_plan())
    rewrite_private_routes(config, "direct fallback")


def add_non_direct_fallback(config: dict, args: argparse.Namespace) -> None:
    if not getattr(args, "tcp_route_plan_private", False):
        raise CommandError("--tcp-route-non-direct-fallback requires --tcp-route-plan-private")
    ensure_poison_outbound(config)
    outbounds = config.setdefault("outbounds", [])
    upsert_outbound(outbounds, poison_bound_plan())
    upsert_outbound(outbounds, poison_dialer())
    upsert_outbound(outbounds, non_direct_fallback_plan())
    rewrite_private_routes(config, "non-direct fallback")


def ensure_poison_outbound(config: dict) -> None:
    outbounds = config.setdefault("outbounds", [])
    if not any(item.get("tag") == POISON_TAG for item in outbounds if isinstance(item, dict)):
        outbounds.insert(1, poison_vmess_outbound())


def tunnel_plan_edges(config: dict, purpose: str) -> list:
    tunnel = next(
        (
            item
            for item in config.setdefault("outbounds", [])
            if isinstance(item, dict)
            and item.get("tag") == "tunnel"
            and item.get("type") == "plan"
        ),
        None,
    )
    if not isinstance(tunnel, dict):
        raise CommandError(f"generated config has no `tunnel` plan for {purpose}")
    selection = tunnel.setdefault("payload", {}).setdefault("selection", {})
    edges = selection.setdefault("edges", [])
    if not isinstance(edges, list):
        raise CommandError(f"generated config has non-list tunnel edges for {purpose}")
    return edges


def rewrite_private_routes(config: dict, purpose: str) -> None:
    changed = False
    for route in config.setdefault("routes", []):
        if isinstance(route, dict) and route.get("outbound") == "private-via-tunnel":
            route["outbound"] = ROUTE_FALLBACK_TAG
            changed = True
    if not changed:
        raise CommandError(f"generated config has no private route to wrap for {purpose}")


def upsert_outbound(outbounds: list, item: dict) -> None:
    for index, existing in enumerate(outbounds):
        if isinstance(existing, dict) and existing.get("tag") == item["tag"]:
            outbounds[index] = item
            return
    outbounds.append(item)


def poison_vmess_outbound() -> dict:
    return {
        "tag": POISON_TAG,
        "type": "vmess",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "metadata": {"purpose": "vm-runtime-pre-payload-fallback-proof"},
        "payload": {
            "server": "127.0.0.1",
            "port": 1,
            "uuid": "00000000-0000-0000-0000-000000000001",
            "cipher": "auto",
        },
    }


def route_fallback_plan() -> dict:
    return {
        "tag": ROUTE_FALLBACK_TAG,
        "type": "plan",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "metadata": {"purpose": "vm-runtime-route-fallback-proof"},
        "payload": {
            "selection": {
                "edges": [
                    {"type": "candidate", "to": "private-via-tunnel"},
                    {"type": "candidate", "to": "direct"},
                ]
            }
        },
    }


def poison_bound_plan() -> dict:
    return {
        "tag": POISON_BOUND_PLAN_TAG,
        "type": "plan",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "metadata": {"purpose": "vm-runtime-route-non-direct-fallback-poison-bound"},
        "payload": {"selection": {"edges": [{"type": "candidate", "to": POISON_TAG}]}},
    }


def poison_dialer() -> dict:
    return {
        "tag": POISON_DIALER_TAG,
        "type": "dialer",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "metadata": {"purpose": "vm-runtime-route-non-direct-fallback-first-candidate"},
        "payload": {
            "bound": POISON_BOUND_PLAN_TAG,
            "target": "private",
        },
    }


def non_direct_fallback_plan() -> dict:
    return {
        "tag": ROUTE_FALLBACK_TAG,
        "type": "plan",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "metadata": {"purpose": "vm-runtime-route-non-direct-fallback-proof"},
        "payload": {
            "selection": {
                "edges": [
                    {"type": "candidate", "to": POISON_DIALER_TAG},
                    {"type": "candidate", "to": "private-via-tunnel"},
                ]
            }
        },
    }
