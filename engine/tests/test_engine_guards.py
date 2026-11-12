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


if __name__ == "__main__":
    unittest.main()
