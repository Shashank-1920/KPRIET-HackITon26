"""S.H.A.D.E. Exposure Risk Engine & Classification (Member 3).

Fulfills Section 18 & Section 19 of the Master Requirements (CheckList):
- Generates 0-100 numeric risk scores.
- Enforces statutory business classifications: 0, LOW, MEDIUM, CRITICAL.
- Produces evidence-backed exposure assessment dossiers.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

class ExposureTargetType(str, Enum):
    PUBLIC_CRITICAL = "PUBLIC"          # Public / Govt / Financial / Telecom -> CRITICAL
    PRIVATE_COMMERCIAL = "PRIVATE"      # Private org (e.g. e-commerce, aggregators) -> MEDIUM
    LOW_RISK_FORUM = "LOW_RISK"         # Low-risk websites / public forums -> LOW
    NO_EXPOSURE = "NONE"                # Clean footprint -> 0

class RiskClassification(str, Enum):
    ZERO = "0"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    CRITICAL = "CRITICAL"

@dataclass
class ExposureReport:
    """Formal exposure record fulfilling Section 18 & 19 of CheckList."""
    risk_score: int                     # 0 to 100
    risk_classification: RiskClassification
    organization_platform: str
    affected_data_type: str             # e.g., "PASSWORD", "AADHAAR", "PAN", "PHONE", "EMAIL"
    target_type: ExposureTargetType
    discovery_date: str
    evidence_source: str
    is_supported_by_evidence: bool      # Strictly distinguishes fact from assumption (Sec 18)
    investigation_notes: str
    requires_statutory_erasure: bool    # True if score >= 40 (MEDIUM/CRITICAL)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "risk_score": self.risk_score,
            "risk_classification": self.risk_classification.value,
            "organization_platform": self.organization_platform,
            "affected_data_type": self.affected_data_type,
            "target_type": self.target_type.value,
            "discovery_date": self.discovery_date,
            "evidence_source": self.evidence_source,
            "is_supported_by_evidence": self.is_supported_by_evidence,
            "investigation_notes": self.investigation_notes,
            "requires_statutory_erasure": self.requires_statutory_erasure,
        }

class ExposureRiskEngine:
    """Deterministic 0-100 Exposure Risk Engine owned by Member 3."""

    # Base severity weights (0 - 45) based on data sensitivity
    DATA_SEVERITY_WEIGHTS = {
        "PASSWORD": 45,
        "AADHAAR": 40,
        "GOVT_ID": 40,
        "BANK_ACCOUNT": 38,
        "PAN": 35,
        "API_KEY": 35,
        "PHONE": 20,
        "VEHICLE_PLATE": 18,
        "EMAIL": 10,
        "GENERAL_IDENTIFIER": 8,
    }

    # Recency multipliers based on exposure age in months
    @staticmethod
    def get_recency_multiplier(months_ago: float) -> float:
        if months_ago <= 12:
            return 1.0     # Fresh breach (high urgency)
        elif months_ago <= 36:
            return 0.7     # 1 - 3 years ago
        else:
            return 0.4     # > 3 years historical leak

    def calculate_score(
        self,
        data_type: str,
        target_type: ExposureTargetType,
        is_plaintext: bool = True,
        months_ago: float = 6.0,
        has_verified_evidence: bool = True,
    ) -> int:
        """Calculates a deterministic 0-100 risk score per Section 19."""
        if target_type == ExposureTargetType.NO_EXPOSURE:
            return 0

        norm_data_type = data_type.upper().strip()
        base_weight = self.DATA_SEVERITY_WEIGHTS.get(norm_data_type, 15)

        # Plaintext vs hashed/masked penalty
        exposure_intensity = 1.0 if is_plaintext else 0.55
        recency_factor = self.get_recency_multiplier(months_ago)

        # Organization type multiplier
        if target_type == ExposureTargetType.PUBLIC_CRITICAL:
            org_multiplier = 1.45   # Critical public infrastructure / banks
        elif target_type == ExposureTargetType.PRIVATE_COMMERCIAL:
            org_multiplier = 1.15   # Commercial private fiduciary
        else:
            org_multiplier = 0.75   # Low-risk forum / casual site

        raw_score = (base_weight * 1.5) * exposure_intensity * recency_factor * org_multiplier

        # Evidence dampener: if evidence is unverified/rumor, scale down to prevent false certainty
        if not has_verified_evidence:
            raw_score *= 0.65

        # Bound to integer 0 - 100
        bounded_score = int(min(100, max(0, round(raw_score))))
        return bounded_score

    def classify_risk(
        self,
        score: int,
        target_type: ExposureTargetType,
    ) -> RiskClassification:
        """Assigns the business classification specified in Section 19 of CheckList."""
        if score == 0 or target_type == ExposureTargetType.NO_EXPOSURE:
            return RiskClassification.ZERO
        elif target_type == ExposureTargetType.PUBLIC_CRITICAL or score >= 70:
            return RiskClassification.CRITICAL
        elif target_type == ExposureTargetType.PRIVATE_COMMERCIAL or score >= 40:
            return RiskClassification.MEDIUM
        else:
            return RiskClassification.LOW

    def evaluate_exposure(
        self,
        organization: str,
        data_type: str,
        target_type: ExposureTargetType,
        evidence_source: str,
        is_plaintext: bool = True,
        months_ago: float = 6.0,
        has_verified_evidence: bool = True,
        source_responsible: Optional[str] = None,
    ) -> ExposureReport:
        """Compiles a complete exposure audit record fulfilling Section 18 & 19."""
        score = self.calculate_score(
            data_type=data_type,
            target_type=target_type,
            is_plaintext=is_plaintext,
            months_ago=months_ago,
            has_verified_evidence=has_verified_evidence,
        )

        classification = self.classify_risk(score, target_type)
        now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

        # Section 18 Evidence Invariant note
        if source_responsible and has_verified_evidence:
            investigation_notes = (
                f"Verified breach archive attributed to: {source_responsible}. "
                f"Source verified via cryptographic dump hash or certified registry."
            )
        elif source_responsible and not has_verified_evidence:
            investigation_notes = (
                f"Unverified attribution mention: '{source_responsible}'. "
                f"Per S.H.A.D.E. Section 18 Evidence Invariant, attribution remains unconfirmed."
            )
        else:
            investigation_notes = (
                "Entity exposure documented. Responsible actor or exfiltration vector unidentified."
            )

        # Requires statutory erasure if classified as MEDIUM or CRITICAL
        requires_erasure = classification in [RiskClassification.MEDIUM, RiskClassification.CRITICAL]

        return ExposureReport(
            risk_score=score,
            risk_classification=classification,
            organization_platform=organization,
            affected_data_type=data_type.upper(),
            target_type=target_type,
            discovery_date=now_str,
            evidence_source=evidence_source,
            is_supported_by_evidence=has_verified_evidence,
            investigation_notes=investigation_notes,
            requires_statutory_erasure=requires_erasure,
        )
