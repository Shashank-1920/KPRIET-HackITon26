"""
S.H.A.D.E. — Security, Threat Engine & Risk Analysis Module
Workstream: Member 2 (`member-2/security`)

Core Responsibilities:
- Deterministic Data Loss Prevention (DLP) regex suite and 12-char synthetic tokenization (SHD_XXXXXXXX)
- UIDAI Indian Aadhaar Dihedral D5 Verhoeff checksum algorithm
- Indian PAN, UPI, Vehicle registration plates, Credit Card (Luhn), and secret detection
- URL sensitive query parameter detection and sanitization
- Trusted Destination Policy evaluation (*.gov.in, *.nic.in, *.ac.in, *.edu)
- Canary Honeytoken generation and breach attribution
- HaveIBeenPwned Passwords API v3 k-anonymity client
- Centralized 0–100 Exposome Threat Index risk calculator
"""

from security.canary.detector import (
    CanaryAlert,
    CanaryDetector,
    CanaryToken,
)
from security.dlp.patterns import (
    calculate_shannon_entropy,
    generate_synthetic_token,
    mask_sensitive_url,
    validate_luhn,
)
from security.dlp.regex_detector import (
    DLPFinding,
    DLPScanResult,
    RegexDLPDetector,
)
from security.breach_radar.client import (
    BreachRadarCheckResult,
    EmailBreachCheckResult,
    XposedOrNotClient,
)
from security.hibp.client import (
    HIBPCheckResult,
    HIBPClient,
)
from security.threat_engine.engine import ThreatEngine
from security.threat_engine.models import (
    DestinationTrustDossier,
    RiskAssessment,
    RiskBreakdown,
    ThreatEvaluationResult,
    ThreatItem,
)
from security.threat_engine.risk_analyzer import RiskAnalyzer
from security.threat_engine.severity import SeverityLevel
from security.threat_engine.threat_detector import ThreatDetector
from security.threat_engine.threat_types import ThreatType
from security.threat_engine.trusted_destinations import (
    DestinationTrustResult,
    TrustedDestinationEvaluator,
)
from security.validators.verhoeff import (
    generate_check_digit,
    is_valid_aadhaar,
    validate_verhoeff,
)

__version__ = "1.1.0"

__all__ = [
    # Threat Engine & Policy
    "ThreatEngine",
    "ThreatDetector",
    "RiskAnalyzer",
    "ThreatType",
    "SeverityLevel",
    "ThreatItem",
    "RiskAssessment",
    "RiskBreakdown",
    "DestinationTrustDossier",
    "DestinationTrustResult",
    "TrustedDestinationEvaluator",
    "ThreatEvaluationResult",
    # DLP
    "RegexDLPDetector",
    "DLPFinding",
    "DLPScanResult",
    "generate_synthetic_token",
    "calculate_shannon_entropy",
    "validate_luhn",
    "mask_sensitive_url",
    # Validators
    "validate_verhoeff",
    "generate_check_digit",
    "is_valid_aadhaar",
    # Canary
    "CanaryDetector",
    "CanaryToken",
    "CanaryAlert",
    # HIBP & Breach Radar
    "HIBPClient",
    "HIBPCheckResult",
    "XposedOrNotClient",
    "BreachRadarCheckResult",
    "EmailBreachCheckResult",
]
