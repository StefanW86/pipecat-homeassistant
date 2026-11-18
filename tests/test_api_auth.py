"""Add-on API access control: trusted hosts pass, the token only opens satellite paths."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "addons/pipecat_assist"))

from app import api_auth

SECRET = "s3cret"


def conn(host, token="", header="", path="/api/assist/config"):
    return SimpleNamespace(
        client=SimpleNamespace(host=host) if host else None,
        headers={"authorization": header} if header else {},
        query_params={"token": token} if token else {},
        url=SimpleNamespace(path=path),
    )


class ApiAuthTest(unittest.TestCase):
    def test_builtin_trusted_hosts(self):
        for host in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "172.30.32.2"):
            self.assertTrue(api_auth.is_authorized(conn(host), SECRET), host)

    def test_lan_client_without_valid_token(self):
        for c in (conn("192.168.1.50"), conn("192.168.1.50", "wrong", path="/api/offer"), conn(None)):
            self.assertFalse(api_auth.is_authorized(c, SECRET))
        self.assertFalse(api_auth.is_authorized(conn("192.168.1.50", path="/api/offer"), ""))
        self.assertFalse(api_auth.is_authorized(conn("172.30.32.5"), SECRET))

    def test_token_opens_only_satellite_paths(self):
        for path in ("/api/offer", "/sessions/abc/api/offer", "/api/assist/esphome", "/api/assist/browser/stream"):
            self.assertTrue(api_auth.is_authorized(conn("192.168.1.50", SECRET, path=path), SECRET), path)
        self.assertTrue(
            api_auth.is_authorized(conn("192.168.1.50", header=f"Bearer {SECRET}", path="/api/offer"), SECRET)
        )
        for path in ("/api/assist/config", "/api/assist/conversation", "/ws-client", "/ws", "/"):
            self.assertFalse(api_auth.is_authorized(conn("192.168.1.50", SECRET, path=path), SECRET), path)

    def test_configured_networks(self):
        networks = api_auth.parse_networks("192.168.1.0/24\nnot-a-net, 10.0.0.7")
        with patch.object(api_auth, "TRUSTED_NETWORKS", networks):
            self.assertTrue(api_auth.is_authorized(conn("192.168.1.50"), SECRET))
            self.assertTrue(api_auth.is_authorized(conn("10.0.0.7"), SECRET))
            self.assertFalse(api_auth.is_authorized(conn("10.0.0.8"), SECRET))


class MiddlewareTest(unittest.TestCase):
    """TestClient's peer is 'testclient' (untrusted), like a LAN device."""

    def setUp(self):
        try:
            from starlette.applications import Starlette
            from starlette.responses import PlainTextResponse
            from starlette.routing import Route, WebSocketRoute
            from starlette.testclient import TestClient
        except ImportError as err:
            self.skipTest(f"starlette test client unavailable: {err}")

        async def ok(request):
            return PlainTextResponse("ok")

        async def ws(websocket):
            await websocket.accept()
            await websocket.send_text("open")
            await websocket.close()

        app = Starlette(routes=[Route("/{p:path}", ok, methods=["GET", "POST"]), WebSocketRoute("/{p:path}", ws)])
        app.add_middleware(api_auth.ApiAuthMiddleware, secret=lambda: SECRET)
        self.client = TestClient(app)

    def test_http(self):
        self.assertEqual(self.client.get("/api/assist/config").status_code, 401)
        self.assertEqual(self.client.get(f"/api/assist/config?token={SECRET}").status_code, 401)
        self.assertEqual(self.client.post(f"/api/offer?token={SECRET}").status_code, 200)

    def test_websocket(self):
        from starlette.websockets import WebSocketDisconnect

        for path in ("/ws-client", "/ws", "/api/assist/stt/stream", f"/ws-client?token={SECRET}"):
            with self.assertRaises(WebSocketDisconnect, msg=path):
                with self.client.websocket_connect(path) as w:
                    w.receive_text()
        with self.client.websocket_connect(f"/api/assist/esphome?token={SECRET}") as w:
            self.assertEqual(w.receive_text(), "open")


if __name__ == "__main__":
    unittest.main()
