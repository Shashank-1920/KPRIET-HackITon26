"""Unit tests verifying CheckList Section 18, 19, 20 & 21 compliance (Member 3)."""

from datetime import datetime, timedelta, timezone
import unittest

from ai.analysis.risk_scoring import (
    ExposureReport,
    ExposureRiskEngine,
    ExposureTargetType,
    RiskClassification,
)
from ai.legal.followup_generator import (
    CaseStatus,
    ErasureWorkflowEngine,
    InvestigationCaseRecord,
)

class TestExposureRiskEngine(unittest.TestCase):
    def setUp(self):
        self.engine = ExposureRiskEngine()

    def test_no_exposure_score_zero(self):
        # Section 19: No exposure -> 0
        rep = self.engine.evaluate_exposure(
            organization="Clean System",
            data_type="NONE",
            target_type=ExposureTargetType.NO_EXPOSURE,
            evidence_source="HIBP / Radar Scan",
        )
        self.assertEqual(rep.risk_score, 0)
        self.assertEqual(rep.risk_classification, RiskClassification.ZERO)
        self.assertFalse(rep.requires_statutory_erasure)

    def test_low_risk_website_classification(self):
        # Section 19: Low-risk website -> LOW
        rep = self.engine.evaluate_exposure(
            organization="Public Hobby Forum",
            data_type="EMAIL",
            target_type=ExposureTargetType.LOW_RISK_FORUM,
            evidence_source="Pastebin dump",
            months_ago=38.0,  # Old leak
        )
        self.assertEqual(rep.risk_classification, RiskClassification.LOW)
        self.assertLess(rep.risk_score, 40)

    def test_private_organization_classification(self):
        # Section 19: Private organization -> MEDIUM
        rep = self.engine.evaluate_exposure(
            organization="Zomato / Delivery App",
            data_type="PHONE",
            target_type=ExposureTargetType.PRIVATE_COMMERCIAL,
            evidence_source="Historical dark-web aggregator",
            months_ago=8.0,
        )
        self.assertEqual(rep.risk_classification, RiskClassification.MEDIUM)
        self.assertTrue(rep.requires_statutory_erasure)

    def test_public_organization_classification(self):
        # Section 19: Public organization / Critical Infra -> CRITICAL
        rep = self.engine.evaluate_exposure(
            organization="National Telecom / Bank Gateway",
            data_type="AADHAAR",
            target_type=ExposureTargetType.PUBLIC_CRITICAL,
            evidence_source="Verified regulatory breach disclosure",
            months_ago=2.0,
        )
        self.assertEqual(rep.risk_classification, RiskClassification.CRITICAL)
        self.assertGreaterEqual(rep.risk_score, 70)
        self.assertTrue(rep.requires_statutory_erasure)

    def test_section_18_evidence_invariant(self):
        # Section 18: Distinguishes available evidence from unsupported assumptions
        unverified_rep = self.engine.evaluate_exposure(
            organization="Fintech App",
            data_type="PAN",
            target_type=ExposureTargetType.PRIVATE_COMMERCIAL,
            evidence_source="Unconfirmed forum post",
            has_verified_evidence=False,
            source_responsible="Anonymous hacker tag",
        )
        self.assertFalse(unverified_rep.is_supported_by_evidence)
        self.assertIn("Section 18 Evidence Invariant", unverified_rep.investigation_notes)


class TestErasureWorkflowEngine(unittest.TestCase):
    def setUp(self):
        self.workflow = ErasureWorkflowEngine()

    def test_initialize_case_7_day_deadline(self):
        # Section 20 & 21: Case ID, 7-day deadline monitoring
        start_dt = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
        case: InvestigationCaseRecord = self.workflow.initialize_case(
            organization="PhonePe",
            data_type="UPI_TRANSACTIONS",
            evidence_source="Verified log disclosure",
            risk_score=78,
            risk_level="CRITICAL",
            initial_notice_body="Statutory Notice Under Section 12...",
            request_date=start_dt,
        )

        self.assertTrue(case.case_id.startswith("SHD-CASE-2026-"))
        self.assertEqual(case.status, CaseStatus.DEADLINE_MONITORED)
        self.assertFalse(case.is_deadline_lapsed)
        self.assertFalse(case.has_deletion_evidence)  # Sec 20 invariant

        # Verify exactly 7-day statutory deadline
        expected_deadline = start_dt + timedelta(days=7)
        self.assertEqual(
            case.statutory_deadline_7d,
            expected_deadline.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

    def test_deadline_lapse_and_followup_generation(self):
        # Section 20: 7-Day Deadline Lapses -> Follow-up request generated
        start_dt = datetime(2026, 10, 1, 10, 0, 0, tzinfo=timezone.utc)
        case = self.workflow.initialize_case(
            organization="PhonePe",
            data_type="UPI_TRANSACTIONS",
            evidence_source="Verified disclosure",
            risk_score=78,
            risk_level="CRITICAL",
            initial_notice_body="Original Section 12 Requisition...",
            request_date=start_dt,
        )

        # Check at Day 8 (deadline lapsed)
        day_8 = start_dt + timedelta(days=8)
        is_lapsed = self.workflow.check_deadline_status(case, current_dt=day_8)
        self.assertTrue(is_lapsed)
        self.assertEqual(case.status, CaseStatus.DEADLINE_LAPSED)

        # Generate statutory follow-up escalation
        followup = self.workflow.generate_statutory_followup(
            case=case,
            dpo_email="grievance@phonepe.com",
            applicant_name="Shashank",
            identifier="+91 98765 43210",
        )

        self.assertEqual(case.status, CaseStatus.FOLLOWUP_SENT)
        self.assertIn("STATUTORY ESCALATION NOTICE", followup.body_markdown)
        self.assertIn("Rs. 50 Crore", followup.body_markdown)
        self.assertIn("seven (7) day response window has expired", followup.body_markdown)
        self.assertTrue(followup.mailto_uri.startswith("mailto:grievance@phonepe.com?"))
        self.assertEqual(len(case.follow_up_notices), 1)


if __name__ == "__main__":
    unittest.main()
