"""
S.H.A.D.E. — Threat Engine Package
Orchestrates threat detection, rule evaluation, trusted destination policy, and Exposome Risk Analysis.
"""

from security.threat_engine.engine import ThreatEngine
from security.threat_engine.models import (
    DestinationTrustDossier,
    RiskAssessment,
    RiskBreakdown,
    ThreatEvaluationResult,
    ThreatItem,
)
from security.threat_engine.risk_analyzer import RiskAnalyzer
from security.threat_engine.severity import (
    SeverityLevel,
    score_to_severity,
    severity_to_base_weight,
)
from security.threat_engine.threat_detector import ThreatDetector
from security.threat_engine.threat_rules import (
    DEFAULT_THREAT_RULES,
    ThreatRule,
    ThreatRuleEngine,
)
from security.threat_engine.threat_types import ThreatType
from security.threat_engine.trusted_destinations import (
    DestinationTrustResult,
    TrustedDestinationEvaluator,
)

__all__ = [
    "ThreatEngine",
    "ThreatDetector",
    "RiskAnalyzer",
    "ThreatRuleEngine",
    "ThreatRule",
    "DEFAULT_THREAT_RULES",
    "ThreatType",
    "SeverityLevel",
    "ThreatItem",
    "RiskBreakdown",
    "RiskAssessment",
    "DestinationTrustDossier",
    "DestinationTrustResult",
    "TrustedDestinationEvaluator",
    "ThreatEvaluationResult",
    "score_to_severity",
    "severity_to_base_weight",
]
