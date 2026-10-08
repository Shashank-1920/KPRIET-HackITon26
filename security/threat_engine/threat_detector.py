"""
S.H.A.D.E. — Threat Detector
Coordinates DLP, Canary honeytoken inspection, and breach radar verification
into structured ThreatItem detections.
"""

from pathlib import Path
import sys
from typing import Optional

# Ensure repository root is on sys.path for direct script execution and IDE analysis
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from security.canary.detector import CanaryDetector
from security.dlp.regex_detector import DLPFinding, DLPScanResult, RegexDLPDetector
from security.hibp.client import HIBPClient
from security.threat_engine.models import ThreatItem
from security.threat_engine.severity import SeverityLevel
from security.threat_engine.threat_types import ThreatType, THREAT_DESCRIPTIONS


class ThreatDetector:
    """
    Multifaceted security detector aggregating DLP regex parsing,
    canary honeytoken triggers, and HIBP k-anonymity breach signals.
    """

    def __init__(
        self,
        dlp_detector: Optional[RegexDLPDetector] = None,
        canary_detector: Optional[CanaryDetector] = None,
        hibp_client: Optional[HIBPClient] = None,
    ) -> None:
        self.dlp = dlp_detector or RegexDLPDetector()
        self.canary = canary_detector or CanaryDetector()
        self.hibp = hibp_client or HIBPClient()

    def _dlp_finding_to_threat(self, finding: DLPFinding) -> ThreatItem:
        """Convert a raw DLP finding to a typed ThreatItem."""
        data_type = finding.data_type

        if data_type == "AADHAAR":
            ttype = ThreatType.AADHAAR_EXPOSURE
            sev = SeverityLevel.CRITICAL
            title = "Aadhaar Identity Number Exposed"
        elif data_type == "PAN":
            ttype = ThreatType.PAN_EXPOSURE
            sev = SeverityLevel.HIGH
            title = "Indian PAN Card Number Exposed"
        elif data_type == "CREDIT_CARD":
            ttype = ThreatType.CREDIT_CARD_EXPOSURE
            sev = SeverityLevel.CRITICAL
            title = "Payment Card Number Exposed"
        elif data_type.startswith("API_KEY_"):
            ttype = ThreatType.API_KEY_EXPOSURE
            sev = SeverityLevel.CRITICAL
            title = f"{data_type.replace('_', ' ')} Exposed"
        elif data_type == "PRIVATE_KEY":
            ttype = ThreatType.PRIVATE_KEY_EXPOSURE
            sev = SeverityLevel.CRITICAL
            title = "Private Cryptographic Key Exposed"
        elif data_type == "UPI_ID":
            ttype = ThreatType.UPI_EXPOSURE
            sev = SeverityLevel.MEDIUM
            title = "UPI Payment Address Exposed"
        elif data_type == "VEHICLE_PLATE":
            ttype = ThreatType.VEHICLE_PLATE_EXPOSURE
            sev = SeverityLevel.MEDIUM
            title = "Indian Vehicle Number Plate Exposed"
        elif data_type == "URL_SECRET":
            ttype = ThreatType.URL_SECRET_EXPOSURE
            sev = SeverityLevel.HIGH
            title = "URL with Embedded Secret Exposed"
        elif data_type in ("HIGH_ENTROPY_SECRET", "URI_PASSWORD", "JWT_TOKEN"):
            ttype = ThreatType.HIGH_ENTROPY_SECRET
            sev = SeverityLevel.HIGH
            title = "High-Entropy Credential Exposed"
        else:
            ttype = ThreatType.PII_EXPOSURE
            sev = SeverityLevel.MEDIUM
            title = f"{data_type.title()} PII Detected"

        return ThreatItem(
            threat_type=ttype,
            severity=sev,
            title=title,
            description=THREAT_DESCRIPTIONS.get(ttype, "Sensitive element identified in input."),
            masked_evidence=finding.masked_value,
            synthetic_token=finding.synthetic_token,
            confidence=finding.confidence,
            metadata={
                "data_type": data_type,
                "start": finding.start,
                "end": finding.end,
                "entropy": finding.entropy,
            },
        )

    def detect(
        self,
        text: str,
        password_candidates: Optional[list[str]] = None,
    ) -> tuple[list[ThreatItem], DLPScanResult]:
        """
        Execute detection sweep across text and optional password candidates.
        """
        threats: list[ThreatItem] = []

        # 1. Canary honeytoken detection (highest priority breach attribution)
        canary_alerts = self.canary.scan_payload(text)
        for alert in canary_alerts:
            threats.append(
                ThreatItem(
                    threat_type=ThreatType.CANARY_BREACH,
                    severity=SeverityLevel.CRITICAL,
                    title="Canary Honeytoken Breach",
                    description=alert.message,
                    masked_evidence=alert.observed_value_masked,
                    confidence=1.0,
                    metadata={
                        "token_id": alert.token_id,
                        "attribution_tag": alert.attribution_tag,
                    },
                )
            )

        # 2. Deterministic Regex DLP detection
        dlp_result = self.dlp.scan(text)
        for finding in dlp_result.findings:
            threats.append(self._dlp_finding_to_threat(finding))

        # 3. HIBP breach verification on candidate passwords if provided
        if password_candidates:
            for pwd in password_candidates:
                hibp_res = self.hibp.check_password(pwd)
                if hibp_res.is_breached:
                    masked = pwd[0] + "***" if len(pwd) > 1 else "***"
                    threats.append(
                        ThreatItem(
                            threat_type=ThreatType.BREACHED_PASSWORD,
                            severity=SeverityLevel.HIGH,
                            title="Known Breached Password",
                            description=(
                                f"Password appeared in {hibp_res.breach_count:,} public data breaches."
                            ),
                            masked_evidence=masked,
                            confidence=1.0,
                            metadata={
                                "sha1_prefix": hibp_res.sha1_prefix,
                                "breach_count": hibp_res.breach_count,
                            },
                        )
                    )

        return threats, dlp_result
