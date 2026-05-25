from __future__ import annotations

from typing import Any, Iterable


PRIVACY_FLAGS = {
    "rawLogsStored": False,
    "rawPacketsStored": False,
    "rawSecretsStored": False,
    "rawResponseBodiesStored": False,
    "rawResponseHeadersStored": False,
    "identityInformationSent": False,
    "cookiesSent": False,
    "authorizationSent": False,
    "accountStateStored": False,
}
RUNTIME_SURFACE_PRIVACY_FLAGS = {
    "rawLogsStored": False,
    "rawPacketsStored": False,
    "rawSecretsStored": False,
    "responseBodiesStored": False,
    "identityInformationSent": False,
}


def empty_privacy_flags() -> dict[str, bool]:
    return dict(PRIVACY_FLAGS)


def empty_surface_privacy_flags() -> dict[str, bool]:
    return dict(RUNTIME_SURFACE_PRIVACY_FLAGS)


def privacy_any(flags: Iterable[dict[str, Any]]) -> bool:
    return any(bool(value) for item in flags for value in item.values())


def raw_detail_keys(value: Any, deny_keys: set[str]) -> set[str]:
    if isinstance(value, dict):
        keys = {str(key) for key in value if str(key) in deny_keys}
        for item in value.values():
            keys.update(raw_detail_keys(item, deny_keys))
        return keys
    if isinstance(value, list):
        keys: set[str] = set()
        for item in value:
            keys.update(raw_detail_keys(item, deny_keys))
        return keys
    return set()
