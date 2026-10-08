"""Unit tests for DPDP Act 2023 Section 12 legal notice generator (Member 3)."""

import unittest

from ai.legal.dpdp_generator import (
    DPDPNoticeGenerator,
    ErasureNoticeRequest,
    TakedownNoticeRecord,
)

class TestDPDPNoticeGenerator(unittest.TestCase):
    def setUp(self):
        self.generator = DPDPNoticeGenerator()

    def test_fiduciary_registry_listing(self):
        fiduciaries = self.generator.list_fiduciaries()
        self.assertGreaterEqual(len(fiduciaries), 5)
        phonepe = self.generator.get_fiduciary("phonepe")
        self.assertIsNotNone(phonepe)
        self.assertEqual(phonepe["dpo_email"], "grievance@phonepe.com")

    def test_generate_erasure_notice(self):
        req = ErasureNoticeRequest(
            applicant_name="Shashank",
            applicant_email="shashank@example.com",
            identifier="+91 98765 43210",
            fiduciary_id="phonepe",
            data_categories=["Bank Account Records", "Transaction History", "Device ID"],
            erasure_reason="User closed account; consent withdrawn.",
        )
        record: TakedownNoticeRecord = self.generator.generate_notice(req)

        # Validate schema compliance with TAKEDOWN_NOTICES
        self.assertIsNotNone(record.notice_id)
        self.assertTrue(record.tracking_reference.startswith("SHADE-DPDP-2026-"))
        self.assertEqual(record.fiduciary_name, "PhonePe Private Limited")
        self.assertEqual(record.dpo_email, "grievance@phonepe.com")
        self.assertEqual(record.legal_basis, "DPDP Act 2023 Section 12(1) & Section 12(3)")
        self.assertEqual(record.status, "READY_FOR_DISPATCH")

        # Validate statutory legal provisions
        self.assertIn("Section 12(1)", record.notice_body_markdown)
        self.assertIn("Section 12(3)", record.notice_body_markdown)
        self.assertIn("Section 33 and the Schedule", record.notice_body_markdown)
        self.assertIn("250 Crore", record.notice_body_markdown)
        self.assertIn("Bank Account Records", record.notice_body_markdown)

        # Validate mailto link
        self.assertTrue(record.mailto_uri.startswith("mailto:grievance@phonepe.com?"))

    def test_unlisted_custom_fiduciary_fallback(self):
        req = ErasureNoticeRequest(
            applicant_name="Dev User",
            applicant_email="dev@example.com",
            identifier="test-user-id",
            fiduciary_id="customstartup",
            data_categories=["Log Telemetry"],
        )
        record = self.generator.generate_notice(req)
        self.assertEqual(record.dpo_email, "grievance@customstartup.com")
        self.assertEqual(record.fiduciary_name, "CUSTOMSTARTUP")


if __name__ == "__main__":
    unittest.main()
