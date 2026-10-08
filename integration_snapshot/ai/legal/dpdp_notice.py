"""
S.H.A.D.E. — DPDP Act 2023 Section 12 Statutory Notice Generator
Role: Member 3 — AI/ML + Legal Notice Synthesis

Generates formal data erasure demands under Section 12 of the
Digital Personal Data Protection Act (DPDP Act), 2023 (India).
Specifies the statutory 7-day compliance window and preserves audit trails.
"""

from datetime import datetime, timezone, timedelta
from typing import Dict, Optional


def generate_dpdp_erasure_notice(
    organization: str,
    data_type: str,
    evidence_summary: str,
    case_ref: str,
    deadline_days: int = 7,
    recipient_email: Optional[str] = None,
) -> Dict[str, str]:
    """
    Generate a formal DPDP Act 2023 Section 12 Right to Erasure statutory notice.
    Returns subject, body, and metadata.
    """
    now = datetime.now(timezone.utc)
    deadline = now + timedelta(days=deadline_days)
    formatted_now = now.strftime("%d %B %Y")
    formatted_deadline = deadline.strftime("%d %B %Y")

    subject = f"FORMAL STATUTORY NOTICE: Right to Erasure under Section 12, DPDP Act 2023 [Ref: {case_ref}]"

    body = f"""DATE: {formatted_now}

TO:
Data Protection Officer / Grievance Officer
{organization}
Email: {recipient_email or 'privacy-grievance@' + organization.lower().replace(' ', '') + '.com'}

SUBJECT: DEMAND FOR ERASURE OF PERSONAL DATA PURSUANT TO SECTION 12 OF THE DIGITAL PERSONAL DATA PROTECTION ACT, 2023
CASE REFERENCE: {case_ref}

Dear Sir / Madam,

1. STATUTORY NOTICE & IDENTIFICATION
This is a formal communication served pursuant to Section 12(1) of the Digital Personal Data Protection Act, 2023 (DPDP Act), under which a Data Principal has the right to the correction, completion, updating, and ERASURE of their personal data.

2. DETAILS OF DATA COMPROMISE / EXPOSURE
It has been verified through cryptographic breach telemetry that sensitive personal data of the Data Principal has been unlawfully retained, exposed, or published without consent:
- Category of Personal Data: {data_type}
- Target Platform / Entity: {organization}
- Evidence Summary: {evidence_summary}

3. STATUTORY REQUISITIONS
Pursuant to Section 12(3) of the DPDP Act, 2023, you are hereby called upon to:
  a. Permanently ERASE and purge all instances of the specified personal data from your active databases, backups, server logs, cache stores, and downstream processors.
  b. Cease and desist from any further processing, dissemination, or transfer of the said personal data.
  c. Provide written confirmation of complete erasure to the Data Principal within the statutory deadline.

4. COMPLIANCE DEADLINE
Under applicable standards, you are required to comply and respond to this statutory grievance within seven (7) days of receipt:
MANDATORY COMPLIANCE DEADLINE: {formatted_deadline} (23:59 IST)

5. RESERVATION OF RIGHTS
Failure to comply with this notice within the stipulated 7-day period will compel the Data Principal to escalate this matter to the Data Protection Board of India (DPBI) for penal adjudication under the provisions of the DPDP Act, 2023.

Yours faithfully,
Data Principal (Protected by S.H.A.D.E. Personal Defense System)
"""

    return {
        "subject": subject,
        "body": body,
        "deadline_date": deadline.isoformat(),
        "case_ref": case_ref,
        "organization": organization,
        "statute": "DPDP Act 2023, Section 12",
    }
