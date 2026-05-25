from __future__ import annotations

import argparse
import json
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
VM_PATH = ROOT / "scripts" / "vm"
sys.path.insert(0, str(VM_PATH))

from private_runtime_lib.checks import acceptance_checks
from private_runtime_lib.config import augment_runtime_config
from tests.private_runtime_fixtures import lifecycle_report, runtime_args
import private_runtime


class PrivateRuntimeDownstreamTest(unittest.TestCase):
    def test_parser(self) -> None:
        args = private_runtime.build_parser().parse_args([
            "guest",
            "dynet-smoke",
            "--force-private-downstream-failure",
        ])

        self.assertTrue(args.force_private_downstream_failure)

    def test_config(self) -> None:
        args = runtime_args(tcp_forward=False)
        args.force_private_downstream_failure = True

        augmented = json.loads(augment_runtime_config(json.dumps(private_config()), args))

        private = next(item for item in augmented["outbounds"] if item["tag"] == "private")
        self.assertEqual(private["type"], "trojan")
        self.assertEqual(private["payload"]["server"], "example.com")
        self.assertEqual(private["payload"]["port"], 80)
        self.assertTrue(private["payload"]["skipCertVerify"])

    def test_acceptance(self) -> None:
        checks = acceptance_checks(
            downstream_report(),
            lifecycle_report(),
            lifecycle_report(),
            {},
            {},
            {},
            {},
            ["chatgpt.com"],
            argparse.Namespace(force_private_downstream_failure=True),
            {},
        )

        by_name = {item["name"]: item["passed"] for item in checks}
        self.assertTrue(all(by_name.values()), by_name)


def private_config() -> dict:
    return {
        "outbounds": [
            {"tag": "direct", "type": "direct"},
            {
                "tag": "private",
                "type": "ss",
                "payload": {
                    "server": "private.example",
                    "port": 8388,
                    "cipher": "aes-128-gcm",
                    "password": "secret",
                },
            },
            {
                "tag": "private-via-tunnel",
                "type": "dialer",
                "payload": {"bound": "tunnel", "target": "private"},
            },
        ]
    }


def downstream_report() -> dict:
    return {
        "status": "deny",
        "tunPackets": 1,
        "events": [
            {"kind": "dns-query-received", "fields": {"query": "chatgpt.com"}},
            {"kind": "dns-resolve-failed", "fields": {"query": "chatgpt.com"}},
            cascade_selected(),
            cascade_started(),
            stage(2, "tunnel-001", "tcp-connect", "success"),
            stage(3, "private", "private-trojan-connect", "failed"),
            cascade_finished(),
        ],
    }


def cascade_selected() -> dict:
    return {
        "kind": "dialer-cascade-selected",
        "fields": {
            "flowId": "dns-query-1",
            "dialer": "private-via-tunnel",
            "boundSelected": "tunnel-001",
            "private": "private",
        },
    }


def cascade_started() -> dict:
    return {
        "kind": "dialer-cascade-attempt-started",
        "sequence": 1,
        "fields": {
            "flowId": "dns-query-1",
            "attempt": "1",
            "candidateCount": "2",
            "boundSelected": "tunnel-001",
            "replaySafe": "pre-query",
        },
    }


def cascade_finished() -> dict:
    return {
        "kind": "dialer-cascade-attempt-finished",
        "sequence": 4,
        "fields": {
            "flowId": "dns-query-1",
            "attempt": "1",
            "candidateCount": "2",
            "boundSelected": "tunnel-001",
            "status": "failed",
            "failureScope": "downstream",
            "errorDisposition": "protocol-invalid",
            "retryAllowed": "false",
            "retryStopReason": "non-bound-failure",
        },
    }


def stage(sequence: int, outbound: str, name: str, status: str) -> dict:
    event_fields = {
        "flowId": "dns-query-1",
        "outbound": outbound,
        "stage": name,
        "status": status,
    }
    if status == "failed":
        event_fields["errorDisposition"] = "protocol-invalid"
    return {
        "kind": "outbound-stage-finished",
        "sequence": sequence,
        "fields": event_fields,
    }


if __name__ == "__main__":
    unittest.main()
