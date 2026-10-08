"""
S.H.A.D.E. — Threat Engine Threat Types
Defines canonical classification types for security detections, risks, and events.
"""

from enum import Enum


class ThreatType(str, Enum):
    """Categorical classification of detected threats."""

    AADHAAR_EXPOSURE = "AADHAAR_EXPOSURE"
    PAN_EXPOSURE = "PAN_EXPOSURE"
    PII_EXPOSURE = "PII_EXPOSURE"
    UPI_EXPOSURE = "UPI_EXPOSURE"
    VEHICLE_PLATE_EXPOSURE = "VEHICLE_PLATE_EXPOSURE"
    CREDIT_CARD_EXPOSURE = "CREDIT_CARD_EXPOSURE"
    API_KEY_EXPOSURE = "API_KEY_EXPOSURE"
    PRIVATE_KEY_EXPOSURE = "PRIVATE_KEY_EXPOSURE"
    URL_SECRET_EXPOSURE = "URL_SECRET_EXPOSURE"
    HIGH_ENTROPY_SECRET = "HIGH_ENTROPY_SECRET"
    CREDENTIAL_LEAK = "CREDENTIAL_LEAK"
    BREACHED_PASSWORD = "BREACHED_PASSWORD"
    CANARY_BREACH = "CANARY_BREACH"
    DATA_EXFILTRATION = "DATA_EXFILTRATION"
    SUSPICIOUS_TRANSFER = "SUSPICIOUS_TRANSFER"
    POLICY_VIOLATION = "POLICY_VIOLATION"


# Human-friendly, evidence-based descriptions for alert generation
# Maintains strict evidence integrity: no assumptions of legal liability without forensic proof.
THREAT_DESCRIPTIONS: dict[ThreatType, str] = {
    ThreatType.AADHAAR_EXPOSURE: "Verified 12-digit Indian Aadhaar number detected in payload.",
    ThreatType.PAN_EXPOSURE: "Indian Permanent Account Number (PAN) detected in payload.",
    ThreatType.PII_EXPOSURE: "Personally Identifiable Information (PII) identified in payload.",
    ThreatType.UPI_EXPOSURE: "Unified Payments Interface (UPI) virtual payment address detected.",
    ThreatType.VEHICLE_PLATE_EXPOSURE: "Indian vehicle registration number plate detected in payload.",
    ThreatType.CREDIT_CARD_EXPOSURE: "Valid payment card number (Luhn verified) detected in payload.",
    ThreatType.API_KEY_EXPOSURE: "Cloud or platform API key token exposed in plaintext.",
    ThreatType.PRIVATE_KEY_EXPOSURE: "Asymmetric private cryptographic key block exposed.",
    ThreatType.URL_SECRET_EXPOSURE: "URL query parameter containing embedded secret or token detected.",
    ThreatType.HIGH_ENTROPY_SECRET: "High-entropy credential or secret assignment detected.",
    ThreatType.CREDENTIAL_LEAK: "Username and password credential pair detected.",
    ThreatType.BREACHED_PASSWORD: "Password confirmed compromised via HIBP k-anonymity radar.",
    ThreatType.CANARY_BREACH: "Unique canary honeytoken identifier observed outside expected context.",
    ThreatType.DATA_EXFILTRATION: "High-density sensitive data egress attempt detected.",
    ThreatType.SUSPICIOUS_TRANSFER: "Suspicious unauthorized data movement across security boundary.",
    ThreatType.POLICY_VIOLATION: "Egress violates device-local security baseline policy.",
}
