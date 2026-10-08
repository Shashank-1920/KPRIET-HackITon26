"""
S.H.A.D.E. — Threat Detection Rules Engine
Deterministic rule definitions that classify findings into threat items and actions.
"""

from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from security.threat_engine.severity import SeverityLevel
from security.threat_engine.threat_types import ThreatType


@dataclass(frozen=True)
class ThreatRule:
    """Definition of a declarative threat detection rule."""

    rule_id: str
    name: str
    threat_type: ThreatType
    severity: SeverityLevel
    base_weight: float
    description: str
    action: str  # BLOCK, TOKENIZE, WARN, AUDIT


# Predefined baseline rules conforming to S.H.A.D.E. specification
DEFAULT_THREAT_RULES: list[ThreatRule] = [
    ThreatRule(
        rule_id="SHADE-RULE-001",
        name="Aadhaar Verhoeff Verified Exposure",
        threat_type=ThreatType.AADHAAR_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        base_weight=45.0,
        description="Verified Indian Aadhaar 12-digit number identified. Requires tokenization and owner consent.",
        action="TOKENIZE",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-002",
        name="PAN Card Identifier Exposure",
        threat_type=ThreatType.PAN_EXPOSURE,
        severity=SeverityLevel.HIGH,
        base_weight=30.0,
        description="Indian Permanent Account Number (PAN) identified in outbound payload.",
        action="TOKENIZE",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-003",
        name="Credit Card (Luhn Validated) Exposure",
        threat_type=ThreatType.CREDIT_CARD_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        base_weight=50.0,
        description="Payment card number validated with Luhn algorithm detected.",
        action="BLOCK",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-004",
        name="Cloud / Service API Key Plaintext Leak",
        threat_type=ThreatType.API_KEY_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        base_weight=45.0,
        description="Live cloud platform API key (AWS, GitHub, Google, OpenAI, Slack) detected in plaintext.",
        action="BLOCK",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-005",
        name="Cryptographic Private Key Block Exposure",
        threat_type=ThreatType.PRIVATE_KEY_EXPOSURE,
        severity=SeverityLevel.CRITICAL,
        base_weight=60.0,
        description="Asymmetric private key (RSA/EC/OpenSSH) exposed in payload.",
        action="BLOCK",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-006",
        name="High-Entropy Credential Assignment",
        threat_type=ThreatType.HIGH_ENTROPY_SECRET,
        severity=SeverityLevel.HIGH,
        base_weight=35.0,
        description="High Shannon entropy secret or token assignment detected in code or message.",
        action="TOKENIZE",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-007",
        name="Canary Honeytoken Breach Triggered",
        threat_type=ThreatType.CANARY_BREACH,
        severity=SeverityLevel.CRITICAL,
        base_weight=100.0,
        description="Decoy canary credential triggered! High confidence internal or prompt leakage confirmed.",
        action="BLOCK",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-008",
        name="Confirmed Breached Password Exposure",
        threat_type=ThreatType.BREACHED_PASSWORD,
        severity=SeverityLevel.HIGH,
        base_weight=40.0,
        description="Password confirmed compromised in prior public data breaches via HIBP radar.",
        action="WARN",
    ),
    ThreatRule(
        rule_id="SHADE-RULE-009",
        name="General PII Density Accumulation",
        threat_type=ThreatType.PII_EXPOSURE,
        severity=SeverityLevel.MEDIUM,
        base_weight=15.0,
        description="General contact PII (Email, Phone, Passport, Driving Licence) identified.",
        action="TOKENIZE",
    ),
]


class ThreatRuleEngine:
    """Evaluates rules against security findings and triggers actions."""

    def __init__(self, rules: Optional[list[ThreatRule]] = None) -> None:
        self._rules = {r.rule_id: r for r in (rules or DEFAULT_THREAT_RULES)}
        self._type_to_rules: dict[ThreatType, list[ThreatRule]] = {}
        for r in self._rules.values():
            self._type_to_rules.setdefault(r.threat_type, []).append(r)

    def get_rule_for_threat_type(self, threat_type: ThreatType) -> Optional[ThreatRule]:
        """Find highest priority rule for given threat type."""
        rules = self._type_to_rules.get(threat_type, [])
        if not rules:
            return None
        # Return rule with highest base_weight
        return max(rules, key=lambda r: r.base_weight)

    def list_rules(self) -> list[ThreatRule]:
        """Return all registered rules."""
        return list(self._rules.values())
