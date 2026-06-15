"""API tests for audit and dead-rules endpoints."""

import unittest

from fastapi.testclient import TestClient

from main import app


class DeadRulesApiTests(unittest.TestCase):
    """Validate API behavior for dead-rules analysis endpoints."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_get_dead_rules_info(self) -> None:
        response = self.client.get("/api/v1/audit/check-dead-rules")
        self.assertEqual(response.status_code, 200)

        body = response.json()
        self.assertEqual(body.get("status"), "success")
        self.assertIn("data", body)
        self.assertIn("input_schema", body["data"])

    def test_post_dead_rules_detects_duplicate(self) -> None:
        payload = {
            "vendor": "cisco",
            "rules": [
                "access-list ACL1 extended permit tcp any host 10.0.0.10 eq 443",
                "access-list ACL1 extended permit tcp any host 10.0.0.10 eq 443",
            ],
        }

        response = self.client.post("/api/v1/audit/check-dead-rules", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()["data"]
        self.assertEqual(data["requested_vendor"], "cisco")
        self.assertGreaterEqual(data["dead_rules_count"], 1)
        self.assertEqual(data["summary"]["redundant_rules"], 1)

    def test_post_dead_rules_normalizes_blank_input(self) -> None:
        payload = {
            "vendor": "palo_alto",
            "rules": [
                "  ",
                "\t",
                "rule=AllowWeb src=192.168.1.0 dst=10.0.0.0 action=allow service=http",
                "",
            ],
        }

        response = self.client.post("/api/v1/audit/check-dead-rules", json=payload)
        self.assertEqual(response.status_code, 200)

        data = response.json()["data"]
        self.assertEqual(data["total_rules_analyzed"], 1)

    def test_post_audit_normalizes_blank_input(self) -> None:
        payload = {
            "vendor": "cisco",
            "rules": [
                "",
                "access-list OUTSIDE-IN extended permit tcp any host 10.0.0.10 eq 443",
                "   ",
            ],
        }

        response = self.client.post("/api/v1/audit", json=payload)
        self.assertEqual(response.status_code, 200)

        summary = response.json()["data"]["summary"]
        self.assertEqual(summary["total_rules"], 1)
        self.assertEqual(summary["parsed_successfully"], 1)


if __name__ == "__main__":
    unittest.main()
