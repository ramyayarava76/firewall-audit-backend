"""Backend tests for rule-related audit endpoints."""

import unittest

from fastapi.testclient import TestClient

from main import app


class BackendRuleTests(unittest.TestCase):
    """Validate backend behavior for rule parsing and dead-rule checks."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.client = TestClient(app)

    def test_audit_endpoint_parses_single_rule(self) -> None:
        payload = {
            "vendor": "cisco",
            "rules": [
                "access-list OUTSIDE-IN extended permit tcp any host 10.0.0.10 eq 443",
            ],
        }

        response = self.client.post("/api/v1/audit", json=payload)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body.get("status"), "success")

        summary = body["data"]["summary"]
        self.assertEqual(summary["total_rules"], 1)
        self.assertEqual(summary["parsed_successfully"], 1)
        self.assertEqual(summary["failed_to_parse"], 0)

        result = body["data"]["results"][0]
        self.assertEqual(result["vendor"], "cisco")
        self.assertEqual(result["action"], "permit")
        self.assertEqual(result["protocol"], "tcp")

    def test_dead_rules_endpoint_finds_redundant_rule(self) -> None:
        payload = {
            "vendor": "cisco",
            "rules": [
                "access-list ACL1 extended permit tcp any host 10.0.0.10 eq 443",
                "access-list ACL1 extended permit tcp any host 10.0.0.10 eq 443",
            ],
        }

        response = self.client.post("/api/v1/audit/check-dead-rules", json=payload)

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body.get("status"), "success")

        data = body["data"]
        self.assertEqual(data["total_rules_analyzed"], 2)
        self.assertEqual(data["dead_rules_count"], 1)
        self.assertEqual(data["summary"]["redundant_rules"], 1)

        finding = data["dead_rules"][0]
        self.assertEqual(finding["reason"], "Redundant rule")
        self.assertEqual(finding["duplicate_of"], 0)

    def test_dead_rules_endpoint_ignores_blank_lines(self) -> None:
        payload = {
            "vendor": "palo_alto",
            "rules": [
                " ",
                "\t",
                "",
                "rule=AllowWeb src=any dst=any action=allow service=http",
            ],
        }

        response = self.client.post("/api/v1/audit/check-dead-rules", json=payload)

        self.assertEqual(response.status_code, 200)
        data = response.json()["data"]
        self.assertEqual(data["total_rules_analyzed"], 1)

    def test_dead_rules_report_returns_csv(self) -> None:
        payload = {
            "vendor": "cisco",
            "rules": [
                "access-list ACL1 extended permit tcp any any",
                "access-list ACL1 extended permit tcp any any",
            ],
        }

        response = self.client.post("/api/v1/audit/check-dead-rules/report", json=payload)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("content-type"), "text/csv; charset=utf-8")
        self.assertIn("dead_rules_report.csv", response.headers.get("content-disposition", ""))

        csv_text = response.text
        self.assertIn("index,reason", csv_text)
        self.assertIn("Redundant rule", csv_text)


if __name__ == "__main__":
    unittest.main()
