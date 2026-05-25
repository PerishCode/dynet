from __future__ import annotations

from collections import Counter
from typing import Any


CONFIG_SCHEMA = "dynet-tunnel-private-config/v1alpha1"


def dynet_vmess(proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    payload = {
        "server": str(proxy["server"]),
        "port": int(proxy["port"]),
        "uuid": str(proxy["uuid"]),
        "alterId": int(proxy.get("alterId", proxy.get("alter-id", 0)) or 0),
        "cipher": str(proxy.get("cipher") or "auto"),
    }
    add_if_present(payload, "serverIp", proxy.get("server-ip") or proxy.get("serverIp"))
    return {
        "tag": tag,
        "type": "vmess",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "payload": payload,
    }


def dynet_ss(proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    payload = {
        "server": str(proxy["server"]),
        "port": int(proxy["port"]),
        "cipher": str(proxy["cipher"]),
        "password": str(proxy["password"]),
    }
    add_if_present(payload, "serverIp", proxy.get("server-ip") or proxy.get("serverIp"))
    return {
        "tag": tag,
        "type": "ss",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "payload": payload,
    }


def dynet_trojan(proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    payload = {
        "server": str(proxy["server"]),
        "port": int(proxy["port"]),
        "password": str(proxy["password"]),
    }
    add_if_present(payload, "serverIp", proxy.get("server-ip") or proxy.get("serverIp"))
    add_if_present(
        payload,
        "interfaceName",
        proxy.get("interface-name") or proxy.get("interfaceName"),
    )
    add_if_present(payload, "sni", proxy.get("sni") or proxy.get("servername"))
    if "skip-cert-verify" in proxy:
        payload["skipCertVerify"] = bool(proxy["skip-cert-verify"])
    if "skipCertVerify" in proxy:
        payload["skipCertVerify"] = bool(proxy["skipCertVerify"])
    return {
        "tag": tag,
        "type": "trojan",
        "capabilities": ["tcp", "domain-target", "ip-target", "probeable"],
        "payload": payload,
    }


def dynet_proxy(proxy: dict[str, Any], tag: str) -> dict[str, Any]:
    kind = str(proxy.get("type", "")).lower()
    if kind == "vmess":
        return dynet_vmess(proxy, tag)
    if kind == "ss":
        return dynet_ss(proxy, tag)
    if kind == "trojan":
        return dynet_trojan(proxy, tag)
    raise SystemExit(f"unsupported dynet proxy type `{kind}`")


def add_if_present(target: dict[str, Any], key: str, value: Any) -> None:
    if value is not None and str(value):
        target[key] = str(value)


def metadata(
    group: dict[str, Any],
    all_candidates: list[dict[str, Any]],
    supported_candidates: list[dict[str, Any]],
    selected_candidates: list[dict[str, Any]],
    candidates: list[dict[str, Any]],
    private: dict[str, Any],
    resolution: dict[str, Any],
) -> dict[str, Any]:
    offset = metadata_candidate_offset(resolution)
    return {
        "schema": CONFIG_SCHEMA,
        "tunnel": {
            "nameLength": len(str(group.get("name", ""))),
            "type": group.get("type"),
            "filterPresent": group.get("filter") is not None,
            "providerCount": len(group.get("use", [])),
        },
        "counts": {
            "matched": len(all_candidates),
            "supported": len(supported_candidates),
            "selected": len(selected_candidates),
            "usable": len(candidates),
            "skipped": int(resolution.get("skipped", 0)),
            "matchedByType": dict(
                Counter(str(item.get("type", "<missing>")) for item in all_candidates)
            ),
        },
        "resolution": resolution,
        "private": safe_proxy(private),
        "candidates": [
            safe_proxy(proxy, f"tunnel-{offset + index:03d}")
            for index, proxy in enumerate(candidates, start=1)
        ],
        "privacy": {
            "rawSecretsStored": False,
            "identityInformationSent": False,
            "cookiesSent": False,
            "authorizationSent": False,
        },
    }


def metadata_candidate_offset(resolution: dict[str, Any]) -> int:
    selection = resolution.get("selection", {})
    if not isinstance(selection, dict):
        return 0
    return int(selection.get("candidateOffset") or 0)


def safe_proxy(proxy: dict[str, Any], tag: str | None = None) -> dict[str, Any]:
    skip_verify = proxy.get("skip-cert-verify")
    if proxy.get("skipCertVerify") is not None:
        skip_verify = proxy.get("skipCertVerify")
    alpn = proxy.get("alpn")
    interface_name = proxy.get("interface-name") or proxy.get("interfaceName")
    row = {
        "nameLength": len(str(proxy.get("name", ""))),
        "type": proxy.get("type"),
        "network": proxy.get("network"),
        "serverLength": len(str(proxy.get("server", ""))),
        "port": proxy.get("port"),
        "cipher": proxy.get("cipher"),
        "tag": tag,
        "uuidLength": (
            len(str(proxy.get("uuid", "")))
            if proxy.get("uuid") is not None
            else None
        ),
        "passwordLength": (
            len(str(proxy.get("password", "")))
            if proxy.get("password") is not None
            else None
        ),
        "serverIpPresent": (
            proxy.get("server-ip") is not None or proxy.get("serverIp") is not None
        ) or None,
        "interfaceNameConfigured": bool(interface_name) or None,
        "interfaceNameLength": len(str(interface_name)) if interface_name else None,
        "sniPresent": (
            proxy.get("sni") is not None or proxy.get("servername") is not None
        ) or None,
        "skipCertVerify": bool(skip_verify) if skip_verify is not None else None,
        "alpnCount": (
            len(alpn)
            if isinstance(alpn, list)
            else (1 if alpn is not None else None)
        ),
        "fingerprintPresent": (proxy.get("fingerprint") is not None) or None,
        "clientFingerprintPresent": (
            proxy.get("client-fingerprint") is not None
            or proxy.get("clientFingerprint") is not None
        ) or None,
    }
    return {key: value for key, value in row.items() if value is not None}


def with_trojan_interface_name(
    proxy: dict[str, Any],
    interface_name: str | None,
) -> dict[str, Any]:
    if not interface_name or str(proxy.get("type", "")).lower() != "trojan":
        return proxy
    proxy = dict(proxy)
    proxy["interface-name"] = interface_name
    return proxy
