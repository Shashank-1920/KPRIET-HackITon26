"""S.H.A.D.E. 7-Day Erasure Workflow & Case Record Engine (Member 3).

Fulfills Section 20 & Section 21 of the Master Requirements (CheckList):
- Tracks 7-day statutory deadline from initial request dispatch.
- Compiles statutory follow-up escalation notices when fiduciaries fail to respond.
- Produces investigation records matching the Section 21 Case Record schema.
"""

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import secrets
import urllib.parse
import uuid

class CaseStatus(str, Enum):
    REQUEST_PREPARED = "REQUEST_PREPARED"
    DISPATCHED_BY_USER = "DISPATCHED_BY_USER"
    DEADLINE_MONITORED = "DEADLINE_MONITORED"
    DEADLINE_LAPSED = "DEADLINE_LAPSED"
    FOLLOWUP_SENT = "FOLLOWUP_SENT"
    CONFIRMED_ERASED = "CONFIRMED_ERASED"

@dataclass
class InvestigationCaseRecord:
    """Formal investigation record fulfilling Section 21 of CheckList."""
    case_id: str
    organization_platform: str
    affected_data_type: str
    discovery_date: str
    evidence_source: str
    risk_score: int                     # 0 - 100
    risk_level: str                     # LOW | MEDIUM | CRITICAL
    initial_request_body: str
    initial_request_date: str
    statutory_deadline_7d: str          # 7 days from request date
    is_deadline_lapsed: bool
    status: CaseStatus
    organization_response: Optional[str] = None
    follow_up_notices: List[Dict[str, Any]] = field(default_factory=list)
    source_person_info: str = "Unidentified or distinct from established facts (Sec 18/21 Invariant)"
    has_deletion_evidence: bool = False # Sec 20 invariant: True ONLY if evidence exists

    def to_dict(self) -> Dict[str, Any]:
        return {
            "case_id": self.case_id,
            "organization_platform": self.organization_platform,
            "affected_data_type": self.affected_data_type,
            "discovery_date": self.discovery_date,
            "evidence_source": self.evidence_source,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "initial_request_body": self.initial_request_body,
            "initial_request_date": self.initial_request_date,
            "statutory_deadline_7d": self.statutory_deadline_7d,
            "is_deadline_lapsed": self.is_deadline_lapsed,
            "status": self.status.value,
            "organization_response": self.organization_response,
            "follow_up_notices": self.follow_up_notices,
            "source_person_info": self.source_person_info,
            "has_deletion_evidence": self.has_deletion_evidence,
        }

@dataclass
class StatutoryFollowUpNotice:
    """Escalated notice sent after 7-day statutory deadline lapses."""
    followup_reference: str
    case_id: str
    organization: str
    dpo_email: str
    subject: str
    body_markdown: str
    mailto_uri: str
    generated_at: str

class ErasureWorkflowEngine:
    """Orchestrates 7-day monitored erasure lifecycle per Section 20."""

    @staticmethod
    def calculate_deadline(start_dt: datetime) -> datetime:
        return start_dt + timedelta(days=7)

    def initialize_case(
        self,
        organization: str,
        data_type: str,
        evidence_source: str,
        risk_score: int,
        risk_level: str,
        initial_notice_body: str,
        request_date: Optional[datetime] = None,
        source_person: Optional[str] = None,
    ) -> InvestigationCaseRecord:
        """Creates a Section 21 Case Record initialized with 7-day deadline."""
        start_dt = request_date or datetime.now(timezone.utc)
        deadline_dt = self.calculate_deadline(start_dt)
        case_id = f"SHD-CASE-2026-{secrets.token_hex(3).upper()}"

        start_str = start_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        deadline_str = deadline_dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        person_info = (
            f"Documented actor mention: '{source_person}' (Subject to evidentiary corroboration)"
            if source_person
            else "Perpetrator / source entity unidentified in available dump records."
        )

        return InvestigationCaseRecord(
            case_id=case_id,
            organization_platform=organization,
            affected_data_type=data_type,
            discovery_date=start_str,
            evidence_source=evidence_source,
            risk_score=risk_score,
            risk_level=risk_level,
            initial_request_body=initial_notice_body,
            initial_request_date=start_str,
            statutory_deadline_7d=deadline_str,
            is_deadline_lapsed=False,
            status=CaseStatus.DEADLINE_MONITORED,
            source_person_info=person_info,
            has_deletion_evidence=False,
        )

    def check_deadline_status(
        self,
        case: InvestigationCaseRecord,
        current_dt: Optional[datetime] = None,
    ) -> bool:
        """Checks if the 7-day monitored statutory deadline has expired."""
        now = current_dt or datetime.now(timezone.utc)
        deadline = datetime.strptime(case.statutory_deadline_7d, "%Y-%m-%d %H:%M:%S UTC").replace(
            tzinfo=timezone.utc
        )
        lapsed = now >= deadline
        case.is_deadline_lapsed = lapsed
        if lapsed and case.status == CaseStatus.DEADLINE_MONITORED:
            case.status = CaseStatus.DEADLINE_LAPSED
        return lapsed

    def generate_statutory_followup(
        self,
        case: InvestigationCaseRecord,
        dpo_email: str,
        applicant_name: str,
        identifier: str,
    ) -> StatutoryFollowUpNotice:
        """Synthesizes formal Section 12 follow-up escalation after 7-day lapse."""
        ref_id = f"SHADE-ESC-7D-{secrets.token_hex(3).upper()}"
        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S UTC")
        date_display = now_dt.strftime("%d %B %Y")

        subject = f"URGENT: STATUTORY FOLLOW-UP NOTICE - FAILURE TO COMPLY WITH DPDP SECTION 12 REQUISITION [{case.case_id}]"

        body = (
            f"# STATUTORY ESCALATION NOTICE: NON-COMPLIANCE REMINDER\n"
            f"**UNDER SECTION 12(1), 12(3) & SECTION 33 OF THE DIGITAL PERSONAL DATA PROTECTION ACT, 2023**\n\n"
            f"---\n\n"
            f"- **Escalation Tracking**: `{ref_id}`\n"
            f"- **Associated Case ID**: `{case.case_id}`\n"
            f"- **Original Notice Date**: `{case.initial_request_date}`\n"
            f"- **7-Day Monitored Deadline**: `{case.statutory_deadline_7d}`\n"
            f"- **Notice Date**: {date_display}\n\n"
            f"**TO:**\n"
            f"Data Protection Officer / Grievance Redressal Authority\n"
            f"**{case.organization_platform}**\n"
            f"Email: `{dpo_email}`\n\n"
            f"**FROM:**\n"
            f"Data Principal: **{applicant_name}**\n"
            f"Account Identifier: `{identifier}`\n\n"
            f"---\n\n"
            f"### 1. RECITATION OF LAPSED 7-DAY STATUTORY TIMELINE\n"
            f"On {case.initial_request_date}, I formally served a statutory requisition under Section 12 of "
            f"the Digital Personal Data Protection Act, 2023, demanding the complete erasure of my personal data "
            f"({case.affected_data_type}).\n\n"
            f"As of this date ({now_str}), the mandatory seven (7) day response window has expired without "
            f"confirmation of erasure or written justification of statutory retention.\n\n"
            f"### 2. FORMAL DEFAULT & NOTICE OF INTENT TO ESCALATE\n"
            f"Under Section 12(3) of the DPDP Act 2023, failure by a Data Fiduciary to address a Data Principal's "
            f"requisition constitutes an actionable statutory default.\n\n"
            f"Take notice that if confirmation of complete erasure is not provided within forty-eight (48) hours of this "
            f"escalation notice, I reserve the right to lodge a formal complaint before the **Data Protection Board of India (DPBI)** "
            f"under Section 33 and the Schedule to the Act, which prescribes penalties of up to **Rs. 50 Crore** for "
            f"non-fulfillment of obligations to Data Principals.\n\n"
            f"### 3. MANDATORY CONFIRMATION REQUIRED\n"
            f"Furnish immediate written certification confirming the purge of my {case.affected_data_type} records.\n\n"
            f"Yours faithfully,\n\n"
            f"**{applicant_name}**\n"
            f"Data Principal under DPDP Act, 2023\n"
            f"Case Reference: `{case.case_id}`\n"
            f"*Generated via S.H.A.D.E. Sovereign Personal Security Operations Center*\n"
        )

        params = {"subject": subject, "body": body}
        encoded = urllib.parse.urlencode(params, quote_via=urllib.parse.quote)
        mailto_uri = f"mailto:{dpo_email}?{encoded}"

        # Update case record
        case.status = CaseStatus.FOLLOWUP_SENT
        case.follow_up_notices.append({
            "followup_reference": ref_id,
            "dispatched_at": now_str,
            "subject": subject,
            "status": "DISPATCHED",
        })

        return StatutoryFollowUpNotice(
            followup_reference=ref_id,
            case_id=case.case_id,
            organization=case.organization_platform,
            dpo_email=dpo_email,
            subject=subject,
            body_markdown=body,
            mailto_uri=mailto_uri,
            generated_at=now_str,
        )
