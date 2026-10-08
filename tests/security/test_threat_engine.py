"""
S.H.A.D.E. — Unit Tests for ThreatEngine & Exposome Risk Analyzer
Validates integrated threat scoring, 12-char tokenization, destination trust integration, and canary triggers.
"""

import unittest

from security.threat_engine.engine import ThreatEngine
from security.threat_engine.severity import SeverityLevel
from security.validators.verhoeff import generate_check_digit


class TestThreatEngine(unittest.TestCase):
    """Test suite for integrated ThreatEngine and Exposome Risk calculations."""

    def setUp(self):
        self.engine = ThreatEngine()

    def test_clean_payload_evaluation(self):
        text = "Hello team, please find attached the weekly status update. All services normal."
        result = self.engine.evaluate(text)

        self.assertEqual(len(result.threats), 0)
        self.assertEqual(result.risk_assessment.exposome_threat_index, 0.0)
        self.assertEqual(result.risk_assessment.severity, SeverityLevel.INFO)
        self.assertTrue(result.safe_for_external_egress)
        self.assertFalse(result.requires_owner_gate)
        self.assertIsNone(result.destination_trust)

    def test_aadhaar_payload_evaluation(self):
        base = "45678901234"
        cd = generate_check_digit(base)
        valid_aadhaar = f"{base}{cd}"

        text = f"Verify beneficiary KYC with Aadhaar number {valid_aadhaar}."
        result = self.engine.evaluate(text)

        self.assertGreaterEqual(len(result.threats), 1)
        self.assertGreaterEqual(result.risk_assessment.exposome_threat_index, 40.0)
        self.assertTrue(result.requires_owner_gate)
        # Should be tokenized with 12-char token format (SHD_XXXXXXXX)
        self.assertIn("SHD_", result.tokenized_text)
        self.assertIn(valid_aadhaar, result.synthetic_mappings.values())

    def test_tc_sec_08_canary_breach_forces_catastrophic_index(self):
        """TC-SEC-08: Active canary honeytoken observed forces 100/100 score and BLOCK action."""
        canary = self.engine.generate_canary(tag="secret-executive-memo")
        payload = f"Leaked prompt contains key {canary.value} for immediate use."

        result = self.engine.evaluate(payload)

        # Canary breach forces 100/100 Exposome Threat Index
        self.assertEqual(result.risk_assessment.exposome_threat_index, 100.0)
        self.assertEqual(result.risk_assessment.severity, SeverityLevel.CRITICAL)
        self.assertFalse(result.safe_for_external_egress)
        self.assertEqual(result.risk_assessment.action_required, "BLOCK")

    def test_critical_secret_blocks_egress(self):
        payload = "API Secret Configuration: AKIAIOSFODNN7EXAMPLE for AWS access."
        result = self.engine.evaluate(payload)

        self.assertGreaterEqual(result.risk_assessment.exposome_threat_index, 50.0)
        self.assertFalse(result.safe_for_external_egress)
        self.assertEqual(result.risk_assessment.action_required, "BLOCK")

    def test_destination_trust_integration(self):
        """Verify destination trust dossier is populated when destination_url is provided."""
        text = "Submitting official verification dossier."
        result = self.engine.evaluate(text, destination_url="https://uidai.gov.in/portal")

        self.assertIsNotNone(result.destination_trust)
        self.assertTrue(result.destination_trust.is_trusted)
        self.assertEqual(result.destination_trust.category, "GOVERNMENT_PORTAL")
        self.assertEqual(result.destination_trust.hostname, "uidai.gov.in")

    def test_untrusted_destination_integration(self):
        text = "Submitting official verification dossier."
        result = self.engine.evaluate(text, destination_url="https://pastebin.com/raw/1234")

        self.assertIsNotNone(result.destination_trust)
        self.assertFalse(result.destination_trust.is_trusted)
        self.assertEqual(result.destination_trust.category, "UNTRUSTED")

    def test_upi_and_vehicle_plate_threat_evaluation(self):
        text = "Fleet vehicle TN01AB1234 driver UPI refund to driver@okhdfcbank."
        result = self.engine.evaluate(text)

        types_found = {t.threat_type.value for t in result.threats}
        self.assertIn("VEHICLE_PLATE_EXPOSURE", types_found)
        self.assertIn("UPI_EXPOSURE", types_found)
        self.assertGreater(result.risk_assessment.exposome_threat_index, 20.0)
        self.assertIn("SHD_", result.tokenized_text)


if __name__ == "__main__":
    unittest.main()
