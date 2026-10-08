"""Legal engineering package for S.H.A.D.E. AI module."""

from ai.legal.dpdp_generator import (
    DPDPNoticeGenerator,
    ErasureNoticeRequest,
    TakedownNoticeRecord,
)
from ai.legal.followup_generator import (
    CaseStatus,
    ErasureWorkflowEngine,
    InvestigationCaseRecord,
    StatutoryFollowUpNotice,
)

__all__ = [
    "DPDPNoticeGenerator",
    "ErasureNoticeRequest",
    "TakedownNoticeRecord",
    "ErasureWorkflowEngine",
    "InvestigationCaseRecord",
    "StatutoryFollowUpNotice",
    "CaseStatus",
]
