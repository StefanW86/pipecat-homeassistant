"""Add-on API access control: trusted hosts pass, LAN clients need the token."""

import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "addons/pipecat_assist"))

from app import api_auth


def conn(host, token="", header=""):
    headers = {"authorization": header} if header else {}
    return SimpleNamespace(
        client=SimpleNamespace(host=host) if host else None,
        headers=headers,
        query_params={"token": token} if token else {},
    )


class ApiAuthTest(unittest.TestCase):
    def test_builtin_trusted_hosts(self):
        for host in ("127.0.0.1", "::1", "::ffff:127.0.0.1", "172.30.32.2"):
            self.assertTrue(api_auth.is_authorized(conn(host), "s3cret"), host)

    def test_lan_client_needs_token(self):
        self.assertFalse(api_auth.is_authorized(conn("192.168.1.50"), "s3cret"))
        self.assertFalse(api_auth.is_authorized(conn("192.168.1.50", "wrong"), "s3cret"))
        self.assertFalse(api_auth.is_authorized(conn(None), "s3cret"))
        self.assertTrue(api_auth.is_authorized(conn("192.168.1.50", "s3cret"), "s3cret"))
        self.assertTrue(api_auth.is_authorized(conn("192.168.1.50", header="Bearer s3cret"), "s3cret"))

    def test_empty_secret_locks_lan(self):
        self.assertFalse(api_auth.is_authorized(conn("192.168.1.50"), ""))

    def test_other_supervisor_network_ips_not_trusted(self):
        self.assertFalse(api_auth.is_authorized(conn("172.30.32.5"), "s3cret"))

    def test_configured_networks(self):
        networks = api_auth.parse_networks("192.168.1.0/24\nnot-a-net, 10.0.0.7")
        with patch.object(api_auth, "TRUSTED_NETWORKS", networks):
            self.assertTrue(api_auth.is_authorized(conn("192.168.1.50"), "s3cret"))
            self.assertTrue(api_auth.is_authorized(conn("10.0.0.7"), "s3cret"))
            self.assertFalse(api_auth.is_authorized(conn("10.0.0.8"), "s3cret"))


if __name__ == "__main__":
    unittest.main()
