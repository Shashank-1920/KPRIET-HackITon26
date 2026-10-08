"""
Unit tests for S.H.A.D.E. Credential Breach Radar (XposedOrNot Client).
"""

import unittest

from security.breach_radar.client import (
    BreachRadarCheckResult,
    EmailBreachCheckResult,
    XposedOrNotClient,
)


class TestBreachRadarClient(unittest.TestCase):
    """Test cases for XposedOrNot breach radar client."""

    def setUp(self) -> None:
        self.client = XposedOrNotClient(enable_offline_cache=True)

    def test_empty_password_fails_safe(self) -> None:
        res = self.client.check_password("")
        self.assertFalse(res.is_breached)
        self.assertEqual(res.breach_count, 0)
        self.assertIn("Empty", res.error or "")

    def test_offline_cached_password_breach(self) -> None:
        res = self.client.check_password("password")
        self.assertTrue(res.is_breached)
        self.assertGreater(res.breach_count, 0)
        self.assertEqual(len(res.hash_prefix), 10)

    def test_unbreached_password_offline_fallback(self) -> None:
        # Complex unbreached random password
        res = self.client.check_password("UnBr3@ch4bl3_P@ss_2026_xYz")
        # In offline dictionary or live NotFound, breach_count must be 0
        self.assertFalse(res.is_breached)
        self.assertEqual(res.breach_count, 0)

    def test_empty_email_fails_safe(self) -> None:
        res = self.client.check_email("")
        self.assertFalse(res.is_breached)
        self.assertEqual(res.breaches_count, 0)

    def test_cached_email_breach(self) -> None:
        res = self.client.check_email("test@example.com")
        self.assertTrue(res.is_breached)
        self.assertGreater(res.breaches_count, 0)
        self.assertIn("Ticketfly", res.breaches)


if __name__ == "__main__":
    unittest.main()
