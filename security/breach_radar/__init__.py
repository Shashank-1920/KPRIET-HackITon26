"""
S.H.A.D.E. — Credential Breach Radar Package
Powered by XposedOrNot.
"""

from security.breach_radar.client import (
    BreachRadarCheckResult,
    EmailBreachCheckResult,
    XposedOrNotClient,
)

__all__ = [
    "XposedOrNotClient",
    "BreachRadarCheckResult",
    "EmailBreachCheckResult",
]
