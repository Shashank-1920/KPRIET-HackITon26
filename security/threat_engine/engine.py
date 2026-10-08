"""
S.H.A.D.E. — Threat Engine Orchestrator
Master coordinator for Security & Threat Evaluation (Member 2 Workstream).
Evaluates outbound payloads, performs synthetic tokenization, assesses risk scores,
and enforces device-local privacy boundaries.
"""

from pathlib import Path
import sys
from typing import Any, Optional

# Ensure repository root is on sys.path for direct script execution and IDE analysis
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from security.canary.detector import CanaryDetector, CanaryToken
from security.dlp.regex_detector import RegexDLPDetector
from security.hibp.client import HIBPClient
from security.threat_engine.models import (
    DestinationTrustDossier,
    RiskAssessment,
    ThreatEvaluationResult,
    ThreatItem,
)
from security.threat_engine.risk_analyzer import RiskAnalyzer
from security.threat_engine.threat_detector import ThreatDetector
from security.threat_engine.threat_rules import ThreatRuleEngine
from security.threat_engine.trusted_destinations import (
    DestinationTrustResult,
    TrustedDestinationEvaluator,
)


class ThreatEngine:
    """
    Central Threat & Risk Engine for S.H.A.D.E.
    Integrates DLP Regex scanning, Verhoeff checksums, Canary honeytokens,
    HIBP k-anonymity radar, trusted destination policy, and the 0–100 Exposome Threat Index.
    """

    def __init__(
        self,
        dlp_detector: Optional[RegexDLPDetector] = None,
        canary_detector: Optional[CanaryDetector] = None,
        hibp_client: Optional[HIBPClient] = None,
        risk_analyzer: Optional[RiskAnalyzer] = None,
        rule_engine: Optional[ThreatRuleEngine] = None,
        trusted_evaluator: Optional[TrustedDestinationEvaluator] = None,
    ) -> None:
        self.canary_detector = canary_detector or CanaryDetector()
        self.dlp_detector = dlp_detector or RegexDLPDetector()
        self.hibp_client = hibp_client or HIBPClient()
        self.threat_detector = ThreatDetector(
            dlp_detector=self.dlp_detector,
            canary_detector=self.canary_detector,
            hibp_client=self.hibp_client,
        )
        self.risk_analyzer = risk_analyzer or RiskAnalyzer()
        self.rule_engine = rule_engine or ThreatRuleEngine()
        self.trusted_evaluator = trusted_evaluator or TrustedDestinationEvaluator()

    def evaluate(
        self,
        text: str,
        password_candidates: Optional[list[str]] = None,
        destination_url: Optional[str] = None,
        context: Optional[dict[str, Any]] = None,
    ) -> ThreatEvaluationResult:
        """
        Evaluate an outbound or inbound text payload for security threats.

        1. Scans for Canary honeytokens and DLP PII/Secrets.
        2. Validates mathematical checksums (Verhoeff for Aadhaar, Luhn for Cards).
        3. Generates 12-character synthetic placeholders (SHD_XXXXXXXX).
        4. Evaluates destination domain against verified trust policies if provided.
        5. Calculates the centralized 0–100 Exposome Threat Index.
        6. Returns structured evaluation result for Backend Vault & UI HUD.
        """
        threats, dlp_result = self.threat_detector.detect(
            text=text,
            password_candidates=password_candidates,
        )

        risk_assessment = self.risk_analyzer.analyze(threats)

        # External egress criteria: safe ONLY if no unmasked PII/secrets or canaries
        safe_egress = (
            risk_assessment.exposome_threat_index < 25.0
            and not dlp_result.has_secrets
            and not any(t.threat_type.value == "CANARY_BREACH" for t in threats)
        )

        # Destination trust evaluation
        dest_dossier: Optional[DestinationTrustDossier] = None
        if destination_url:
            trust_res = self.trusted_evaluator.is_trusted_destination(destination_url)
            dest_dossier = DestinationTrustDossier(
                destination=trust_res.destination,
                hostname=trust_res.hostname,
                is_trusted=trust_res.is_trusted,
                category=trust_res.category,
                policy_reason=trust_res.policy_reason,
            )

        return ThreatEvaluationResult(
            original_length=len(text) if text else 0,
            tokenized_text=dlp_result.tokenized_text,
            masked_text=dlp_result.masked_text,
            threats=threats,
            risk_assessment=risk_assessment,
            synthetic_mappings=dlp_result.synthetic_mappings,
            destination_trust=dest_dossier,
            safe_for_external_egress=safe_egress,
            requires_owner_gate=risk_assessment.requires_owner_approval,
        )

    def is_trusted_destination(self, destination: str) -> DestinationTrustResult:
        """Convenience method to evaluate destination trust policy."""
        return self.trusted_evaluator.is_trusted_destination(destination)

    def generate_canary(
        self, tag: str, token_type: str = "API_KEY", description: str = ""
    ) -> CanaryToken:
        """Convenience method to register a new honeytoken."""
        token_type_upper = token_type.upper()
        if token_type_upper == "EMAIL":
            return self.canary_detector.generate_email(tag=tag, description=description)
        if token_type_upper in ("DB", "DATABASE", "DB_URI"):
            return self.canary_detector.generate_db_uri(tag=tag, description=description)
        return self.canary_detector.generate_api_key(tag=tag, description=description)

    def check_password_breach(self, password: str):
        """Convenience method to check password exposure via k-anonymity."""
        return self.hibp_client.check_password(password)

    def tokenize_only(self, text: str) -> tuple[str, dict[str, str]]:
        """Perform DLP tokenization without full threat reporting."""
        return self.dlp_detector.tokenize(text)

    def mask_only(self, text: str) -> str:
        """Perform DLP masking without full threat reporting."""
        return self.dlp_detector.mask(text)
