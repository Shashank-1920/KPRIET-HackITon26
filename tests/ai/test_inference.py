"""Unit tests for inference handler and offline fallback (Member 3)."""

import unittest

from ai.models.inference_handler import (
    MaskedPromptConstructor,
    OfflineModelFallback,
    RawPIILeakException,
)

class TestMaskedPromptConstructor(unittest.TestCase):
    def setUp(self):
        self.constructor = MaskedPromptConstructor()

    def test_masked_payload_passes(self):
        payload = "Process this synthetic customer: <SYN_AADHAAR_7F29>."
        res = self.constructor.validate_and_prepare(payload)
        self.assertEqual(res, payload)
        tokens = self.constructor.extract_synthetic_tokens(payload)
        self.assertIn("<SYN_AADHAAR_7F29>", tokens)

    def test_raw_aadhaar_violates_invariant(self):
        # Raw Aadhaar: 12-digit pattern
        payload = "Process customer with raw Aadhaar 5432 9876 1234 please."
        with self.assertRaises(RawPIILeakException):
            self.constructor.validate_and_prepare(payload)

    def test_raw_pan_violates_invariant(self):
        # Raw PAN: 5 letters, 4 digits, 1 letter
        payload = "Customer PAN is ABCDE1234F"
        with self.assertRaises(RawPIILeakException):
            self.constructor.validate_and_prepare(payload)


class TestOfflineModelFallback(unittest.TestCase):
    def setUp(self):
        self.fallback = OfflineModelFallback()

    def test_token_preservation_in_completion(self):
        prompt = "Write code connecting with API key <SYN_API_KEY_0042>"
        response = self.fallback.generate(prompt)
        self.assertIn("<SYN_API_KEY_0042>", response)
        self.assertIn("CLIENT_SECRET", response)

    def test_streaming_generation(self):
        prompt = "Verify user <SYN_AADHAAR_7F29> for KYC"
        chunks = list(self.fallback.stream(prompt, chunk_size=3))
        self.assertGreater(len(chunks), 1)
        full_text = "".join(chunks)
        self.assertIn("<SYN_AADHAAR_7F29>", full_text)


if __name__ == "__main__":
    unittest.main()
