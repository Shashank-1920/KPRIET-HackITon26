"""
S.H.A.D.E. — Exposome Threat Index & Risk Analyzer
Calculates the centralized 0–100 Exposome Threat Index based on detected
PII exposure, compromised credentials, API secrets, and canary breaches.
"""

from typing import Sequence

from security.threat_engine.models import (
    RiskAssessment,
    RiskBreakdown,
    ThreatItem,
)
from security.threat_engine.severity import SeverityLevel, score_to_severity
from security.threat_engine.threat_types import ThreatType


class RiskAnalyzer:
    """
    Evaluates cumulative exposome risk vectors and synthesizes a calibrated
    0–100 threat index with actionable mitigation recommendations.
    """

    def analyze(self, threats: Sequence[ThreatItem]) -> RiskAssessment:
        """
        Compute Exposome Threat Index from a collection of threat items.
        """
        if not threats:
            return RiskAssessment(
                exposome_threat_index=0.0,
                severity=SeverityLevel.INFO,
                breakdown=RiskBreakdown(),
                summary="No security threats or PII detected. Payload is clean for egress.",
                mitigations=[],
                requires_owner_approval=False,
                action_required="ALLOW",
            )

        pii_raw = 0.0
        secrets_raw = 0.0
        breach_raw = 0.0
        canary_raw = 0.0
        mitigations: list[str] = []

        has_canary = False
        has_critical_secret = False
        has_aadhaar_or_pan = False

        for t in threats:
            # 1. Canary breaches take absolute precedence
            if t.threat_type == ThreatType.CANARY_BREACH:
                has_canary = True
                canary_raw = 100.0
                mitigations.append(
                    f"CRITICAL: Isolate host and revoke compromised decoy credential [{t.masked_evidence}]."
                )

            # 2. Cryptographic secrets and API tokens
            elif t.threat_type == ThreatType.PRIVATE_KEY_EXPOSURE:
                has_critical_secret = True
                secrets_raw += 75.0
                mitigations.append("BLOCK egress: Rotate private cryptographic key immediately.")
            elif t.threat_type == ThreatType.API_KEY_EXPOSURE:
                has_critical_secret = True
                secrets_raw += 50.0
                mitigations.append("BLOCK egress: Invalidate and rotate exposed cloud API key.")
            elif t.threat_type == ThreatType.HIGH_ENTROPY_SECRET:
                secrets_raw += 35.0
                mitigations.append("TOKENIZE secret into local encrypted vault before outbound transmission.")
            elif t.threat_type == ThreatType.URL_SECRET_EXPOSURE:
                has_critical_secret = True
                secrets_raw += 45.0
                mitigations.append("Sanitize URL query string: Embedded secret detected in parameter.")

            # 3. National Identity & Financial PII
            elif t.threat_type == ThreatType.AADHAAR_EXPOSURE:
                has_aadhaar_or_pan = True
                pii_raw += 45.0
                mitigations.append("ENFORCE UIDAI compliance: Replace real Aadhaar with synthetic token.")
            elif t.threat_type == ThreatType.PAN_EXPOSURE:
                has_aadhaar_or_pan = True
                pii_raw += 35.0
                mitigations.append("ENFORCE DPDP Act: Synthetic tokenization required for PAN card.")
            elif t.threat_type == ThreatType.CREDIT_CARD_EXPOSURE:
                pii_raw += 55.0
                mitigations.append("BLOCK egress: PCI-DSS violation. Plaintext payment card must not leave host.")
            elif t.threat_type == ThreatType.UPI_EXPOSURE:
                pii_raw += 25.0
                mitigations.append("Tokenize UPI payment address to prevent financial tracking.")
            elif t.threat_type == ThreatType.VEHICLE_PLATE_EXPOSURE:
                pii_raw += 20.0
                mitigations.append("Tokenize Indian vehicle registration plate to prevent identity profiling.")
            elif t.threat_type == ThreatType.PII_EXPOSURE:
                pii_raw += 15.0
                mitigations.append("Redact or tokenize contact identifiers.")

            # 4. Breached passwords
            elif t.threat_type == ThreatType.BREACHED_PASSWORD:
                breach_raw += 45.0
                mitigations.append("Prompt owner to update password (verified compromised in public breaches).")

        # Cap subscores to 100
        pii_subscore = min(100.0, pii_raw)
        secrets_subscore = min(100.0, secrets_raw)
        breach_subscore = min(100.0, breach_raw)
        canary_subscore = min(100.0, canary_raw)

        # Volume penalty for high finding density (up to +15 pts)
        volume_penalty = min(15.0, max(0.0, (len(threats) - 1) * 3.5))

        # Composite score calculation
        if has_canary:
            exposome_index = 100.0
        elif has_critical_secret:
            base = max(secrets_subscore, 75.0)
            exposome_index = min(100.0, base + (pii_subscore * 0.2) + volume_penalty)
        else:
            weighted = (
                (secrets_subscore * 0.50)
                + (pii_subscore * 0.40)
                + (breach_subscore * 0.10)
                + volume_penalty
            )
            # Ensure high single findings reflect accurately
            max_single = max(secrets_subscore, pii_subscore, breach_subscore)
            exposome_index = min(100.0, max(weighted, max_single))

        # Round to 1 decimal place
        exposome_index = round(exposome_index, 1)
        severity = score_to_severity(exposome_index)

        # Decision logic for action and owner approval gate
        if has_canary or has_critical_secret or exposome_index >= 80.0:
            action = "BLOCK"
            requires_approval = True
        elif has_aadhaar_or_pan or exposome_index >= 40.0:
            action = "TOKENIZE_AND_GATE"
            requires_approval = True
        elif exposome_index >= 20.0:
            action = "TOKENIZE"
            requires_approval = False
        else:
            action = "ALLOW"
            requires_approval = False

        summary = (
            f"Exposome Threat Index evaluated at {exposome_index}/100 ({severity.value}). "
            f"Detected {len(threats)} finding(s). Action: {action}."
        )

        breakdown = RiskBreakdown(
            pii_subscore=round(pii_subscore, 1),
            secrets_subscore=round(secrets_subscore, 1),
            breach_subscore=round(breach_subscore, 1),
            canary_subscore=round(canary_subscore, 1),
            volume_penalty=round(volume_penalty, 1),
            exposome_threat_index=exposome_index,
        )

        return RiskAssessment(
            exposome_threat_index=exposome_index,
            severity=severity,
            breakdown=breakdown,
            summary=summary,
            mitigations=mitigations,
            requires_owner_approval=requires_approval,
            action_required=action,
        )
