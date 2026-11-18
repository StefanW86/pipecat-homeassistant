"""Access control for the add-on HTTP/WebSocket API on the host-network port."""

from __future__ import annotations

import hmac
import ipaddress
import os

from loguru import logger
from starlette.requests import HTTPConnection
from starlette.responses import JSONResponse

# HA Core shares the host network (loopback); 172.30.32.2 is the Supervisor ingress proxy.
_BUILTIN = ("127.0.0.0/8", "::1/128", "172.30.32.2/32")
# The satellite token lives on every ESP device, so it only opens the satellite paths.
_SATELLITE_PATHS = ("/api/offer", "/api/assist/esphome", "/api/assist/browser/stream")


def parse_networks(value: str) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    networks = []
    for item in [*_BUILTIN, *value.replace(",", " ").split()]:
        try:
            networks.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            logger.warning("Ignoring invalid trusted network: {}", item)
    return networks


TRUSTED_NETWORKS = parse_networks(os.getenv("TRUSTED_NETWORKS", ""))


def extract_token(conn) -> str:
    auth = conn.headers.get("authorization", "")
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return conn.query_params.get("token", "")


def is_trusted_host(host: str | None, networks=None) -> bool:
    # Only the TCP peer address counts; X-Forwarded-For would be spoofable from the LAN.
    try:
        address = ipaddress.ip_address(host or "")
    except ValueError:
        return False
    if address.version == 6 and address.ipv4_mapped:
        address = address.ipv4_mapped
    return any(address in net for net in (TRUSTED_NETWORKS if networks is None else networks))


def is_satellite_path(path: str) -> bool:
    return path in _SATELLITE_PATHS or (path.startswith("/sessions/") and path.endswith("/api/offer"))


def is_authorized(conn, secret: str) -> bool:
    if is_trusted_host(conn.client.host if conn.client else None):
        return True
    return (
        bool(secret)
        and is_satellite_path(conn.url.path)
        and hmac.compare_digest(extract_token(conn), secret)
    )


class ApiAuthMiddleware:
    """Pure ASGI so WebSockets (incl. Pipecat's own /ws routes) are covered, not only HTTP."""

    def __init__(self, app, secret):
        self.app, self.secret = app, secret

    async def __call__(self, scope, receive, send):
        if scope["type"] in ("http", "websocket") and not is_authorized(
            HTTPConnection(scope), self.secret()
        ):
            if scope["type"] == "websocket":
                await send({"type": "websocket.close", "code": 1008})
            else:
                await JSONResponse({"detail": "Unauthorized"}, status_code=401)(scope, receive, send)
            return
        await self.app(scope, receive, send)
