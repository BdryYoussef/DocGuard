"""One-hop trusted proxy and canonical authority primitives."""

from __future__ import annotations

import hmac
import ipaddress
from urllib.parse import urlsplit

from fastapi import Request

from app.core.config import AppEnvironment, Settings

MAX_HOST_HEADER_BYTES = 255
MAX_CLIENT_ADDRESS_BYTES = 64


def canonical_authority(settings: Settings) -> str:
    origin = urlsplit(settings.application_origin)
    assert origin.hostname is not None
    host = origin.hostname.casefold()
    if ":" in host:
        host = f"[{host}]"
    default_port = 443 if origin.scheme == "https" else 80
    return host if origin.port in {None, default_port} else f"{host}:{origin.port}"


def host_is_allowed(raw_host: str | None, settings: Settings) -> bool:
    if raw_host is None or not raw_host or len(raw_host) > MAX_HOST_HEADER_BYTES:
        return False
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw_host):
        return False
    try:
        parsed = urlsplit(f"//{raw_host}")
        if parsed.username is not None or parsed.password is not None or parsed.path:
            return False
        observed_host = parsed.hostname
        observed_port = parsed.port
    except ValueError:
        return False
    if observed_host is None:
        return False
    if settings.env is not AppEnvironment.PRODUCTION and observed_host.casefold() == "test":
        return True
    origin = urlsplit(settings.application_origin)
    default_port = 443 if origin.scheme == "https" else 80
    expected_port = origin.port or default_port
    port_matches = (
        observed_port == expected_port
        if origin.port is not None and origin.port != default_port
        else observed_port in {None, default_port}
    )
    return (
        hmac.compare_digest(observed_host.casefold(), (origin.hostname or "").casefold())
        and port_matches
    )


def resolve_client_address(request: Request, settings: Settings) -> str:
    """Resolve exactly one client IP; forwarded chains are never trusted."""

    direct = request.client.host if request.client is not None else "unknown"
    try:
        direct_ip = ipaddress.ip_address(direct)
    except ValueError:
        return direct[:MAX_CLIENT_ADDRESS_BYTES]
    if direct_ip not in settings.parsed_trusted_proxy_ips:
        return str(direct_ip)
    supplied_values = request.headers.getlist("x-real-ip")
    if len(supplied_values) != 1:
        return str(direct_ip)
    supplied = supplied_values[0]
    if "," in supplied or supplied != supplied.strip():
        return str(direct_ip)
    try:
        return str(ipaddress.ip_address(supplied))
    except ValueError:
        return str(direct_ip)


__all__ = ["canonical_authority", "host_is_allowed", "resolve_client_address"]
