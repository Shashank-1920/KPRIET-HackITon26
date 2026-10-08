"""
S.H.A.D.E. — Unit Tests for Trusted Destination Policy Evaluator
Validates government and academic domain policies, subdomain boundaries, and anti-spoofing logic.
"""

import unittest

from security.threat_engine.trusted_destinations import TrustedDestinationEvaluator


class TestTrustedDestinationEvaluator(unittest.TestCase):
    """Test suite for domain trust policy, suffix verification, and anti-spoofing controls."""

    def setUp(self):
        self.evaluator = TrustedDestinationEvaluator()

    def test_tc_sec_05_government_destination_trusted(self):
        """TC-SEC-05: https://uidai.gov.in is verified as trusted government portal."""
        res = self.evaluator.is_trusted_destination("https://uidai.gov.in")
        self.assertTrue(res.is_trusted)
        self.assertEqual(res.category, "GOVERNMENT_PORTAL")
        self.assertEqual(res.hostname, "uidai.gov.in")

        # Subdomain of nic.in
        res2 = self.evaluator.is_trusted_destination("https://services.india.nic.in/portal")
        self.assertTrue(res2.is_trusted)
        self.assertEqual(res2.category, "GOVERNMENT_PORTAL")

    def test_tc_sec_06_academic_destination_trusted(self):
        """TC-SEC-06: https://kpriet.ac.in is verified as trusted academic institution."""
        res = self.evaluator.is_trusted_destination("https://kpriet.ac.in")
        self.assertTrue(res.is_trusted)
        self.assertEqual(res.category, "COLLEGE_UNIVERSITY")
        self.assertEqual(res.hostname, "kpriet.ac.in")

        # University .edu domain
        res2 = self.evaluator.is_trusted_destination("https://mit.edu/admissions")
        self.assertTrue(res2.is_trusted)
        self.assertEqual(res2.category, "COLLEGE_UNIVERSITY")

    def test_tc_sec_07_public_destination_untrusted(self):
        """TC-SEC-07: Publicly accessible site (https://pastebin.com) is untrusted by default."""
        res = self.evaluator.is_trusted_destination("https://pastebin.com")
        self.assertFalse(res.is_trusted)
        self.assertEqual(res.category, "UNTRUSTED")

    def test_negative_anti_spoofing_domain_boundaries(self):
        """Security invariant: evilgov.in and sub-string tricks must NOT be trusted."""
        # 1. evilgov.in (contains 'gov.in' but is not a subdomain of gov.in)
        res1 = self.evaluator.is_trusted_destination("https://evilgov.in")
        self.assertFalse(res1.is_trusted)
        self.assertEqual(res1.category, "UNTRUSTED")

        # 2. fakeac.in.example.com (contains 'ac.in' as middle label)
        res2 = self.evaluator.is_trusted_destination("https://fakeac.in.example.com")
        self.assertFalse(res2.is_trusted)
        self.assertEqual(res2.category, "UNTRUSTED")

        # 3. example.gov.in.evil.com (contains 'gov.in' in subdomain, but root is evil.com)
        res3 = self.evaluator.is_trusted_destination("https://example.gov.in.evil.com")
        self.assertFalse(res3.is_trusted)
        self.assertEqual(res3.category, "UNTRUSTED")

        # 4. evilnic.in
        res4 = self.evaluator.is_trusted_destination("https://evilnic.in/login")
        self.assertFalse(res4.is_trusted)

    def test_destination_normalization_schemes_and_ports(self):
        # Raw domain without scheme
        res1 = self.evaluator.is_trusted_destination("uidai.gov.in")
        self.assertTrue(res1.is_trusted)
        self.assertEqual(res1.hostname, "uidai.gov.in")

        # Port number handling
        res2 = self.evaluator.is_trusted_destination("https://kpriet.ac.in:8080/erp")
        self.assertTrue(res2.is_trusted)
        self.assertEqual(res2.hostname, "kpriet.ac.in")

        # Uppercase and trailing root dot
        res3 = self.evaluator.is_trusted_destination("HTTPS://UIDAI.GOV.IN./portal")
        self.assertTrue(res3.is_trusted)
        self.assertEqual(res3.hostname, "uidai.gov.in")

    def test_malformed_destinations_fail_safe(self):
        # Empty string
        res1 = self.evaluator.is_trusted_destination("")
        self.assertFalse(res1.is_trusted)
        self.assertEqual(res1.category, "MALFORMED")

        # Invalid destination with spaces
        res2 = self.evaluator.is_trusted_destination("not a valid url destination")
        self.assertFalse(res2.is_trusted)
        self.assertEqual(res2.category, "MALFORMED")


if __name__ == "__main__":
    unittest.main()
