"""
S.H.A.D.E. — Unit Tests for Deterministic Regex DLP & Tokenization
Validates 12-character synthetic tokens, token reuse, UPI, vehicle plates, and URL secrets.
"""

import re
import unittest

from security.dlp.patterns import (
    calculate_shannon_entropy,
    generate_synthetic_token,
    mask_sensitive_url,
    validate_luhn,
)
from security.dlp.regex_detector import RegexDLPDetector
from security.validators.verhoeff import generate_check_digit


class TestDLPDetector(unittest.TestCase):
    """Test suite for RegexDLPDetector, patterns, and synthetic tokenization."""

    def setUp(self):
        self.detector = RegexDLPDetector()

    def test_shannon_entropy(self):
        # Repetitive string has low entropy
        low_entropy = calculate_shannon_entropy("aaaaaaaaaaaaaaaa")
        self.assertAlmostEqual(low_entropy, 0.0)

        # High entropy hex/base64 random key
        high_entropy = calculate_shannon_entropy("4f8a9e2b1c7d3e0f9a8b7c6d5e4f3a2b")
        self.assertGreater(high_entropy, 3.5)

    def test_tc_sec_01_synthetic_token_12_char_format(self):
        """TC-SEC-01: Assert token length == 12, starts with SHD_, and remaining 8 chars are hex."""
        token = generate_synthetic_token("AADHAAR", "234567890123")
        self.assertEqual(len(token), 12)
        self.assertTrue(token.startswith("SHD_"))
        hex_suffix = token[4:]
        self.assertEqual(len(hex_suffix), 8)
        self.assertTrue(bool(re.fullmatch(r"[0-9A-F]{8}", hex_suffix)))

    def test_tc_sec_02_deterministic_token_reuse(self):
        """TC-SEC-02: Exact same sensitive value intercepted repeatedly reuses identical token."""
        aadhaar_val = "266853339452"
        token1 = self.detector._get_or_create_token("AADHAAR", aadhaar_val)
        token2 = self.detector._get_or_create_token("AADHAAR", aadhaar_val)
        self.assertEqual(token1, token2)

        # In-payload repetition
        text = f"First mention {aadhaar_val} and duplicate mention {aadhaar_val} in same text."
        result = self.detector.scan(text)
        tokens_found = [f.synthetic_token for f in result.findings if f.raw_value == aadhaar_val]
        self.assertEqual(len(tokens_found), 2)
        self.assertEqual(tokens_found[0], tokens_found[1])
        # Mapping table should store single unique mapping for this token
        self.assertEqual(len(result.synthetic_mappings), 1)

    def test_different_values_produce_distinct_tokens(self):
        token1 = self.detector._get_or_create_token("AADHAAR", "266853339452")
        token2 = self.detector._get_or_create_token("AADHAAR", "987654321010")
        self.assertNotEqual(token1, token2)

    def test_luhn_card_validation(self):
        # Known valid test Visa number
        self.assertTrue(validate_luhn("4532015112830366"))
        # Invalid card number
        self.assertFalse(validate_luhn("4532015112830367"))

    def test_aadhaar_interception_and_tokenization(self):
        base = "34567890123"
        cd = generate_check_digit(base)
        valid_aadhaar = f"{base}{cd}"

        text = f"Customer identity verified with Aadhaar {valid_aadhaar}. Please process."
        result = self.detector.scan(text)

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.data_type, "AADHAAR")
        self.assertEqual(finding.raw_value, valid_aadhaar)
        self.assertTrue(finding.masked_value.startswith("XXXXXXXX"))
        self.assertEqual(len(finding.synthetic_token), 12)
        self.assertTrue(finding.synthetic_token.startswith("SHD_"))
        self.assertIn(finding.synthetic_token, result.tokenized_text)
        self.assertIn(finding.synthetic_token, result.synthetic_mappings)
        self.assertEqual(result.synthetic_mappings[finding.synthetic_token], valid_aadhaar)

    def test_pan_card_detection(self):
        text = "Tax deduction receipt for PAN ABCDE1234F submitted."
        result = self.detector.scan(text)

        self.assertEqual(len(result.findings), 1)
        finding = result.findings[0]
        self.assertEqual(finding.data_type, "PAN")
        self.assertEqual(finding.raw_value, "ABCDE1234F")
        self.assertEqual(finding.masked_value, "A*****F")

    def test_tc_sec_03_vehicle_plate_detection(self):
        """TC-SEC-03: Indian vehicle plate detection (TN01AB1234, DL3CA1234)."""
        text = "Vehicle parked at slot 4: TN01AB1234 and escort car DL3CA1234."
        result = self.detector.scan(text)

        plate_findings = [f for f in result.findings if f.data_type == "VEHICLE_PLATE"]
        self.assertEqual(len(plate_findings), 2)
        self.assertEqual(plate_findings[0].raw_value, "TN01AB1234")
        self.assertEqual(plate_findings[0].masked_value, "TN01****1234")
        self.assertEqual(plate_findings[1].raw_value, "DL3CA1234")

    def test_tc_sec_04_upi_detection(self):
        """TC-SEC-04: UPI ID detection (alice@okhdfcbank, mobile@upi)."""
        text = "Please send payment to alice@okhdfcbank or merchant mobile@upi."
        result = self.detector.scan(text)

        upi_findings = [f for f in result.findings if f.data_type == "UPI_ID"]
        self.assertEqual(len(upi_findings), 2)
        self.assertEqual(upi_findings[0].raw_value, "alice@okhdfcbank")
        self.assertEqual(upi_findings[0].masked_value, "a***@okhdfcbank")
        self.assertEqual(upi_findings[1].raw_value, "mobile@upi")
        self.assertEqual(upi_findings[1].masked_value, "m***@upi")

    def test_normal_email_not_falsely_classified_as_upi(self):
        """Negative test: Normal email should be classified as EMAIL, not UPI."""
        text = "Contact support at info@example.com for inquiries."
        result = self.detector.scan(text)

        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].data_type, "EMAIL")
        self.assertEqual(result.findings[0].raw_value, "info@example.com")

    def test_generic_number_not_classified_as_vehicle_plate(self):
        """Negative test: Random alphanumeric string without Indian state code is rejected."""
        text = "Invoice code XX01AB1234 and serial 1234567890."
        result = self.detector.scan(text)
        vehicle_findings = [f for f in result.findings if f.data_type == "VEHICLE_PLATE"]
        self.assertEqual(len(vehicle_findings), 0)

    def test_url_containing_secret_detection(self):
        """Requirement 4: Detect and mask URLs with embedded secret query parameters."""
        text = "Callback: https://api.internal.com/v1/auth?token=ghp_secretKey123456789&user=john"
        result = self.detector.scan(text)

        url_findings = [f for f in result.findings if f.data_type == "URL_SECRET"]
        self.assertEqual(len(url_findings), 1)
        finding = url_findings[0]
        self.assertIn("token=", finding.raw_value)
        # Secret portion is masked, base URL preserved
        self.assertIn("https://api.internal.com/v1/auth", finding.masked_value)
        self.assertIn("token=[REDACTED_SECRET]", finding.masked_value)
        self.assertNotIn("ghp_secretKey123456789", finding.masked_value)

    def test_safe_url_not_marked_as_secret(self):
        """Negative test: Safe URLs without secret query parameters are not flagged."""
        text = "Visit https://example.com/docs/intro?topic=privacy&page=2 for details."
        result = self.detector.scan(text)
        url_findings = [f for f in result.findings if f.data_type == "URL_SECRET"]
        self.assertEqual(len(url_findings), 0)

    def test_api_keys_detection(self):
        text = (
            "Deploy config: AWS_KEY=AKIAIOSFODNN7EXAMPLE and "
            "GH_TOKEN=ghp_1234567890abcdefghijklmnopqrstuvwxyz12"
        )
        result = self.detector.scan(text)

        data_types = [f.data_type for f in result.findings]
        self.assertIn("API_KEY_AWS", data_types)
        self.assertIn("API_KEY_GITHUB", data_types)
        self.assertTrue(result.has_secrets)

    def test_clean_text_returns_empty_findings(self):
        clean_text = "The system operational status is nominal. Memory utilization is 42%."
        result = self.detector.scan(clean_text)
        self.assertEqual(len(result.findings), 0)
        self.assertFalse(result.has_pii)
        self.assertFalse(result.has_secrets)
        self.assertEqual(result.tokenized_text, clean_text)


if __name__ == "__main__":
    unittest.main()
