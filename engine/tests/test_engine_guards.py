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
os.environ["UPSTASH_REDIS_REST_URL"] = "https://redis.example.test"
os.environ["UPSTASH_REDIS_REST_TOKEN"] = "test-redis-token"

import main


AUTH_REF = "admin-approved:" + "a" * 36


def signed_permit(ip, exp=None):
    payload = {
        "ip": ip,
        "id": "a" * 36,
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
            main.check_target("8.8.8.8", None, AUTH_REF)
        self.assertEqual(ctx.exception.status_code, 403)
        self.assertEqual(main.check_target("8.8.8.8", signed_permit("8.8.8.8"), AUTH_REF), "8.8.8.8")

    def test_ip_outside_authorized_cidr_restriction_is_rejected_even_with_approval(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("8.8.4.4", signed_permit("8.8.4.4"), AUTH_REF)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_empty_allowlist_blocks_scanning_even_with_admin_permit(self):
        with patch.object(main, "NETWORKS", []):
            with self.assertRaises(main.HTTPException) as ctx:
                main.check_target("8.8.8.8", signed_permit("8.8.8.8"), AUTH_REF)
        self.assertEqual(ctx.exception.status_code, 503)

    def test_health_is_degraded_when_authorized_cidr_allowlist_is_missing(self):
        with patch.object(main, "NETWORKS", []):
            result = main.health("Bearer test-token")
        self.assertEqual(result["status"], "degraded")
        self.assertFalse(result["allowlist_configured"])
        self.assertFalse(result["execution_enabled"])

    def test_permit_bound_to_exact_ip(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("8.8.8.8", signed_permit("1.1.1.1"), AUTH_REF)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_expired_admin_permit_is_rejected(self):
        expired = signed_permit("8.8.8.8", int((time.time() - 60) * 1000))
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("8.8.8.8", expired, AUTH_REF)
        self.assertEqual(ctx.exception.status_code, 403)

    def test_hostname_is_rejected(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("example.com", signed_permit("example.com"), AUTH_REF)
        self.assertEqual(ctx.exception.status_code, 400)

    def test_loopback_is_rejected(self):
        with self.assertRaises(main.HTTPException) as ctx:
            main.check_target("127.0.0.1", signed_permit("127.0.0.1"), AUTH_REF)
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
            authorization_reference="admin-approved:" + "a" * 36,
            confirm_authorized=True,
        )
        with patch.object(main, "NMAP_PATH", None):
            with self.assertRaises(main.HTTPException) as ctx:
                main.nmap_scan(request, "Bearer test-token", signed_permit("8.8.8.8"))
        self.assertEqual(ctx.exception.status_code, 503)

    def test_nmap_receives_target_via_stdin_not_process_arguments(self):
        completed = type("Completed", (), {
            "returncode": 0,
            "stdout": "<nmaprun><host><ports/></host></nmaprun>",
            "stderr": "",
        })()
        with patch.object(main, "NMAP_PATH", "/usr/bin/nmap"), patch.object(main.subprocess, "run", return_value=completed) as run:
            result = main.nmap_data("8.8.8.8", 10)
        command = run.call_args.args[0]
        self.assertNotIn("8.8.8.8", command)
        self.assertEqual(command[command.index("--top-ports") + 1], "10")
        self.assertEqual(command[-2:], ["-iL", "-"])
        self.assertEqual(run.call_args.kwargs["input"], "8.8.8.8\n")
        self.assertFalse(run.call_args.kwargs["shell"])
        self.assertEqual(result["summary"]["open_ports"], 0)


    def test_permit_requires_uuid_format_request_id(self):
        payload = {
            "ip": "8.8.8.8",
            "id": "not-a-request-id",
            "exp": int((time.time() + 300) * 1000),
        }
        encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
        signature = hmac.new(os.environ["SCAN_APPROVAL_SECRET"].encode(), encoded.encode(), hashlib.sha256).digest()
        permit = encoded + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
        self.assertFalse(main.valid_dynamic_permit(permit, "8.8.8.8", AUTH_REF))

    def test_permit_expiry_must_be_integer_not_boolean_or_float(self):
        for expiry in (True, time.time() * 1000 + 300_000):
            payload = {"ip": "8.8.8.8", "id": "a" * 36, "exp": expiry}
            encoded = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).decode().rstrip("=")
            signature = hmac.new(os.environ["SCAN_APPROVAL_SECRET"].encode(), encoded.encode(), hashlib.sha256).digest()
            permit = encoded + "." + base64.urlsafe_b64encode(signature).decode().rstrip("=")
            self.assertFalse(main.valid_dynamic_permit(permit, "8.8.8.8", AUTH_REF))

    def test_permit_is_bound_to_admin_approval_reference(self):
        permit = signed_permit("8.8.8.8")
        self.assertTrue(main.valid_dynamic_permit(permit, "8.8.8.8", AUTH_REF))
        self.assertFalse(main.valid_dynamic_permit(permit, "8.8.8.8", "admin-approved:" + "b" * 36))
        self.assertFalse(main.valid_dynamic_permit(permit, "8.8.8.8", "unrelated-reference"))


    def test_durable_scan_claim_blocks_duplicate_execution_and_replays_result(self):
        store = {}

        def fake_redis(command):
            if command[0] == "GET":
                return store.get(command[1])
            if command[0] == "SET":
                key, value = command[1], command[2]
                if "NX" in command and key in store:
                    return None
                store[key] = value
                return "OK"
            raise AssertionError("Unexpected Redis command")

        result = {
            "status": "completed",
            "target": "8.8.8.8",
            "authorization_reference": AUTH_REF,
            "ports": [],
        }
        with patch.object(main, "redis_command", side_effect=fake_redis):
            claimed, cached = main.claim_scan_execution("a" * 36, "8.8.8.8", AUTH_REF)
            self.assertTrue(claimed)
            self.assertIsNone(cached)
            with self.assertRaises(main.HTTPException) as ctx:
                main.claim_scan_execution("a" * 36, "8.8.8.8", AUTH_REF)
            self.assertEqual(ctx.exception.status_code, 409)
            main.persist_scan_result("a" * 36, result)
            claimed_again, replayed = main.claim_scan_execution("a" * 36, "8.8.8.8", AUTH_REF)
            self.assertFalse(claimed_again)
            self.assertEqual(replayed, result)

    def test_durable_idempotency_fails_closed_without_redis_configuration(self):
        with patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "", "UPSTASH_REDIS_REST_TOKEN": ""}):
            with self.assertRaises(main.HTTPException) as ctx:
                main.redis_command(["GET", "scan:test"])
        self.assertEqual(ctx.exception.status_code, 503)

    def test_health_requires_durable_idempotency_storage(self):
        with patch.dict(os.environ, {"UPSTASH_REDIS_REST_URL": "", "UPSTASH_REDIS_REST_TOKEN": ""}):
            result = main.health("Bearer test-token")
        self.assertEqual(result["status"], "degraded")
        self.assertFalse(result["durable_idempotency_configured"])
        self.assertFalse(result["execution_enabled"])

if __name__ == "__main__":
    unittest.main()
