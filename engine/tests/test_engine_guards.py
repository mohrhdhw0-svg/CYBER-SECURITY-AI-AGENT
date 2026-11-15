import base64
import hashlib
import hmac
import json
import os
import time
import unittest
from unittest.mock import patch

os.environ["ENGINE_API_TOKEN"] = "test-token"
os.environ["AUTHORIZED_CIDRS"] = "8.8.8.8/32"
os.environ["SCAN_APPROVAL_SECRET"] = "test-approval-secret-at-least-32-bytes"

import main


def signed_permit(ip, exp=None):
    payload = {
        "ip": ip,
        "id": "test-request-id",
        "exp": exp if exp is not None else int((time.time() + 300) * 1000),
    }
    encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
    signature = hmac.new(
        os.environ["SCAN_APPROVAL_SECRET"].encode(),
        encoded.encode(),
        hashlib.sha256,
    ).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).decode().rstrip("=")
    return encoded + "." + encoded_signature


class EngineGuardTests(unittest.TestCase):
    def test_allowlisted_ip_still_requires_admin_approval(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("8.8.8.8")
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(main.check_target("8.8.8.8", signed_permit("8.8.8.8")), "8.8.8.8")

    def test_ip_outside_additional_cidr_restriction_is_rejected_even_with_approval(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("8.8.4.4", signed_permit("8.8.4.4"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_permit_bound_to_exact_ip(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("8.8.8.8", signed_permit("1.1.1.1"))
        self.assertEqual(ctx.exception.status_code, 403)

    def test_expired_admin_permit_is_rejected(self):
        expired = signed_permit("8.8.8.8", int((time.time() - 60) * 1000))
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("8.8.8.8", expired)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_hostname_is_rejected(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("example.com", signed_permit("example.com"))
        self.assertEqual(ctx.exception.status_code, 400)

    def test_loopback_is_rejected(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("127.0.0.1", signed_permit("127.0.0.1"))
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
            target_ip="8.8.8.8",
            authorization_reference="admin-approved:test-request-id",
            confirm_authorized=True,
        )
        with patch.object(main, "NMAP_PATH", None):
            with self.assertRaises(main.HTTPException) as ctx:
                main.nmap_scan(request, "Bearer test-token", signed_permit("8.8.8.8"))
        self.assertEqual(ctx.exception.status_code, 503)


if __name__ == "__main__":
    unittest.main()
