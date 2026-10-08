"""
S.H.A.D.E. — Unit Tests for HIBP k-Anonymity Client
"""

import hashlib
import unittest

from security.hibp.client import HIBPClient


class TestHIBPClient(unittest.TestCase):
    """Test suite for HaveIBeenPwned k-anonymity client."""

    def setUp(self):
        # Initialize client with offline cache enabled for air-gapped deterministic tests
        self.client = HIBPClient(enable_offline_cache=True)

    def test_kanonymity_hash_invariants(self):
        password = "password"
        # Full SHA-1 of 'password' is 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
        expected_sha1 = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        self.assertEqual(expected_sha1, "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8")

        result = self.client.check_password(password)
        # Prefix must be strictly 5 chars
        self.assertEqual(result.sha1_prefix, "5BAA6")
        self.assertEqual(len(result.sha1_prefix), 5)
        self.assertTrue(result.is_breached)
        self.assertGreater(result.breach_count, 1000)

    def test_known_breached_password(self):
        # '123456' is in offline cache
        res = self.client.check_password("123456")
        self.assertTrue(res.is_breached)
        self.assertEqual(res.sha1_prefix, "7C4A8")
        self.assertGreater(res.breach_count, 10000000)

    def test_unbreached_or_offline_fallback(self):
        # Unlikely password not in offline cache
        super_rare_password = "xK9!mQ2#zL8$wP5*vN3^"
        res = self.client.check_password(super_rare_password)
        # Even if network fails or offline, prefix is calculated correctly and handled safely
        self.assertEqual(len(res.sha1_prefix), 5)
        # Should not throw exception


if __name__ == "__main__":
    unittest.main()
