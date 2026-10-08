"""
Unit tests for S.H.A.D.E. Local Security & Threat Engine API Server.
"""

import unittest

from fastapi.testclient import TestClient

from security.server import app


class TestSecurityServer(unittest.TestCase):
    """Test cases for the local FastAPI server."""

    def setUp(self) -> None:
        self.client = TestClient(app)

    def test_root_endpoint(self) -> None:
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "ONLINE")
        self.assertIn("endpoints", data)

    def test_health_check(self) -> None:
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["status"], "HEALTHY")
        self.assertEqual(data["components"]["threat_engine"], "ACTIVE")

    def test_evaluate_clean_payload(self) -> None:
        response = self.client.post(
            "/api/v1/security/evaluate",
            json={"text": "Clean payload without sensitive data"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["risk_assessment"]["severity"], "INFO")
        self.assertEqual(data["risk_assessment"]["action_required"], "ALLOW")

    def test_evaluate_sensitive_payload_tokenizes(self) -> None:
        response = self.client.post(
            "/api/v1/security/evaluate",
            json={"text": "Customer Aadhaar: 266853339452"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(data["risk_assessment"]["exposome_threat_index"], 0.0)
        self.assertIn("SHD_", data["tokenized_text"])

    def test_dlp_scan_endpoint(self) -> None:
        response = self.client.post(
            "/api/v1/security/dlp/scan",
            json={"text": "PAN is ABCDE1234F"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["has_sensitive_data"])
        self.assertEqual(len(data["findings"]), 1)

    def test_verhoeff_endpoint(self) -> None:
        response = self.client.post(
            "/api/v1/security/validators/verhoeff",
            json={"number": "266853339452"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["is_valid_verhoeff"])
        self.assertTrue(data["is_valid_aadhaar"])

    def test_canary_generate_and_scan(self) -> None:
        gen_res = self.client.post(
            "/api/v1/security/canary/generate",
            json={"kind": "api_key", "attribution_tag": "test_tag"},
        )
        self.assertEqual(gen_res.status_code, 200)
        canary_key = gen_res.json()["value"]

        scan_res = self.client.post(
            "/api/v1/security/canary/scan",
            json={"payload": f"Leaked token: {canary_key}"},
        )
        self.assertEqual(scan_res.status_code, 200)
        scan_data = scan_res.json()
        self.assertTrue(scan_data["leaked"])
        self.assertEqual(scan_data["alert_count"], 1)

    def test_breach_radar_password_endpoint(self) -> None:
        response = self.client.post(
            "/api/v1/security/breach-radar/password",
            json={"password": "password"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["is_breached"])
        self.assertGreater(data["breach_count"], 0)

    def test_destination_evaluate_endpoint(self) -> None:
        response = self.client.post(
            "/api/v1/security/destinations/evaluate",
            json={"destination_url": "https://kpriet.ac.in"},
        )
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertTrue(data["is_trusted"])
        self.assertEqual(data["category"], "COLLEGE_UNIVERSITY")


if __name__ == "__main__":
    unittest.main()
