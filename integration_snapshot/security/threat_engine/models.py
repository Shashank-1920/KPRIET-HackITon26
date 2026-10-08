"""
S.H.A.D.E. — Threat Engine Data Models
Pydantic v2 data models for threat items, risk breakdowns, assessments, and evaluation results.
"""

from datetime import datetime, timezone
from pathlib import Path
import sys
from typing import Any, Optional
import uuid

# Ensure repository root is in sys.path for direct script execution and IDE analysis
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

# pyrefly: ignore [missing-import]
from pydantic import BaseModel, Field

try:
    from security.threat_engine.severity import SeverityLevel
    from security.threat_engine.threat_types import ThreatType
except (ImportError, ModuleNotFoundError):
    from .severity import SeverityLevel
    from .threat_types import ThreatType


def _generate_uuid() -> str:
    """Generate a random UUID string."""
    return str(uuid.uuid4())


def _generate_iso_timestamp() -> str:
    """Generate current UTC ISO-8601 timestamp."""
    return datetime.now(timezone.utc).isoformat()


class ThreatItem(BaseModel):
    """Represents a discrete security threat or finding."""

    # Required fields without defaults placed first
    threat_type: ThreatType
    severity: SeverityLevel
    title: str
    description: str
    masked_evidence: str

    # Optional fields with defaults placed after required fields
    threat_id: str = Field(default_factory=_generate_uuid)
    synthetic_token: Optional[str] = None
    confidence: float = 1.0
    metadata: dict[str, Any] = Field(default_factory=dict)


class RiskBreakdown(BaseModel):
    """Granular subscore breakdown comprising the 0–100 Exposome Threat Index."""

    pii_subscore: float = Field(ge=0.0, le=100.0, default=0.0)
    secrets_subscore: float = Field(ge=0.0, le=100.0, default=0.0)
    breach_subscore: float = Field(ge=0.0, le=100.0, default=0.0)
    canary_subscore: float = Field(ge=0.0, le=100.0, default=0.0)
    volume_penalty: float = Field(ge=0.0, le=100.0, default=0.0)
    exposome_threat_index: float = Field(ge=0.0, le=100.0, default=0.0)


class RiskAssessment(BaseModel):
    """Evaluated risk posture for a given inspection target."""

    # Required fields without defaults placed first
    exposome_threat_index: float = Field(ge=0.0, le=100.0)
    severity: SeverityLevel
    breakdown: RiskBreakdown
    summary: str

    # Optional fields with defaults
    mitigations: list[str] = Field(default_factory=list)
    requires_owner_approval: bool = False
    action_required: str = "ALLOW"  # ALLOW, TOKENIZE_AND_GATE, BLOCK


class DestinationTrustDossier(BaseModel):
    """Destination domain trust evaluation metadata."""

    destination: str
    hostname: str
    is_trusted: bool
    category: str
    policy_reason: str


class ThreatEvaluationResult(BaseModel):
    """Unified result output from ThreatEngine."""

    # Required fields without defaults placed first
    risk_assessment: RiskAssessment

    # Optional fields with defaults placed after required fields
    scan_id: str = Field(default_factory=_generate_uuid)
    timestamp: str = Field(default_factory=_generate_iso_timestamp)
    original_length: int = 0
    tokenized_text: str = ""
    masked_text: str = ""
    threats: list[ThreatItem] = Field(default_factory=list)
    synthetic_mappings: dict[str, str] = Field(default_factory=dict)
    destination_trust: Optional[DestinationTrustDossier] = None
    safe_for_external_egress: bool = True
    requires_owner_gate: bool = False


if __name__ == "__main__":
    # Self-test when executed directly
    sample_threat = ThreatItem(
        threat_type=ThreatType.AADHAAR_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        title="Sample Aadhaar",
        description="Self test threat item",
        masked_evidence="XXXXXXXX1234",
    )
    breakdown = RiskBreakdown(pii_subscore=45.0, exposome_threat_index=45.0)
    assessment = RiskAssessment(
        exposome_threat_index=45.0,
        severity=SeverityLevel.MEDIUM,
        breakdown=breakdown,
        summary="Self test assessment",
        requires_owner_approval=True,
        action_required="TOKENIZE_AND_GATE",
    )
    eval_result = ThreatEvaluationResult(risk_assessment=assessment)
    print("models.py validated successfully:")
    print(eval_result.model_dump_json(indent=2))
