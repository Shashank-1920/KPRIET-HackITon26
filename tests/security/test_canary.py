"""
S.H.A.D.E. — Unit Tests for Canary Honeytoken Generator and Detector
"""

import unittest

from security.canary.detector import CanaryDetector


class TestCanaryDetector(unittest.TestCase):
    """Test suite for Canary honeytoken generation, registry, and detection."""

    def setUp(self):
        self.detector = CanaryDetector()

    def test_generate_and_register_canary_api_key(self):
        token = self.detector.generate_api_key(tag="secret-payroll-db")
        self.assertEqual(token.tag, "secret-payroll-db")
        self.assertTrue(token.value.startswith("shade_cnry_"))
        self.assertTrue(self.detector.is_canary(token.value))
        self.assertEqual(self.detector.get_token(token.value), token)

    def test_generate_canary_email(self):
        token = self.detector.generate_email(tag="executive-leak-trap")
        self.assertEqual(token.tag, "executive-leak-trap")
        self.assertIn("@canary.shade.local", token.value)
        self.assertTrue(self.detector.is_canary(token.value))

    def test_scan_payload_detects_canary_leak(self):
        token = self.detector.generate_api_key(tag="core-vault-backup")
        payload = f"Confidential prompt instructions. Access key: {token.value}. Do not share."

        alerts = self.detector.scan_payload(payload)
        self.assertEqual(len(alerts), 1)
        alert = alerts[0]
        self.assertEqual(alert.attribution_tag, "core-vault-backup")
        self.assertEqual(alert.severity, "CRITICAL")
        self.assertEqual(alert.token_id, token.token_id)

    def test_clean_payload_has_no_canary_alerts(self):
        self.detector.generate_api_key(tag="internal-system")
        clean_text = "System backup completed successfully at 04:00 UTC."
        alerts = self.detector.scan_payload(clean_text)
        self.assertEqual(len(alerts), 0)


if __name__ == "__main__":
    unittest.main()
