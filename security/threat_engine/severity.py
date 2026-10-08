"""
S.H.A.D.E. — Threat Severity Classifications
Defines severity levels, base numerical weights, and mapping helpers.
"""

from enum import Enum
from typing import Final


class SeverityLevel(str, Enum):
    """Normalized threat and vulnerability severity levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


_SEVERITY_WEIGHTS: Final[dict[SeverityLevel, float]] = {
    SeverityLevel.CRITICAL: 1.00,
    SeverityLevel.HIGH: 0.75,
    SeverityLevel.MEDIUM: 0.45,
    SeverityLevel.LOW: 0.20,
    SeverityLevel.INFO: 0.00,
}


def severity_to_base_weight(severity: SeverityLevel | str) -> float:
    """Return normalized decimal impact weight (0.0 to 1.0) for a severity level."""
    if isinstance(severity, str):
        try:
            severity = SeverityLevel(severity.upper())
        except ValueError:
            return 0.20
    return _SEVERITY_WEIGHTS.get(severity, 0.20)


def score_to_severity(score: float) -> SeverityLevel:
    """
    Map an Exposome Threat Index score (0 to 100) to a qualitative severity level.

    Calibrated semantics per S.H.A.D.E. Product Requirements:
        0       -> INFO (No Exposure)
        1–24    -> LOW
        25–49   -> MEDIUM
        50–79   -> HIGH
        80–100  -> CRITICAL
    """
    if score >= 80.0:
        return SeverityLevel.CRITICAL
    if score >= 50.0:
        return SeverityLevel.HIGH
    if score >= 25.0:
        return SeverityLevel.MEDIUM
    if score >= 1.0:
        return SeverityLevel.LOW
    return SeverityLevel.INFO
