import os
import unittest
from unittest.mock import patch

os.environ["ENGINE_API_TOKEN"] = "test-token"
os.environ["AUTHORIZED_CIDRS"] = "192.0.2.10/32"

import main


class EngineGuardTests(unittest.TestCase):
    def test_exact_allowlisted_ip_is_accepted(self):
        self.assertEqual(main.check_target("192.0.2.10"), "192.0.2.10")

    def test_ip_outside_allowlist_is_rejected(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("192.0.2.11")
        self.assertEqual(ctx.exception.status_code, 403)

    def test_hostname_is_rejected(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("example.com")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_loopback_is_rejected(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("127.0.0.1")
        self.assertEqual(ctx.exception.status_code, 400)

    def test_missing_or_invalid_bearer_is_rejected(self):
        with self.assertRaises(main.HTTPException):
            main.require_auth(None)
        with self.assertRaises(main.HTTPException):
            main.require_auth("Bearer wrong")

    def test_valid_bearer_is_accepted(self):
        main.require_auth("Bearer test-token")

    def test_health_is_degraded_when_nmap_binary_is_missing(self):
        with patch.object(main, "NMAP_PATH", None):
            result = main.health("Bearer test-token")
        self.assertEqual(result["status"], "degraded")
        self.assertFalse(result["execution_enabled"])
        self.assertFalse(result["nmap_available"])

    def test_scan_is_blocked_when_nmap_binary_is_missing(self):
        request = main.ScanRequest(
            target_ip="192.0.2.10",
            authorization_reference="LAB-123",
            confirm_authorized=True,
        )
        with patch.object(main, "NMAP_PATH", None):
            with self.assertRaises(main.HTTPException) as ctx:
                main.nmap_scan(request, "Bearer test-token")
        self.assertEqual(ctx.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
