"""
S.H.A.D.E. — Voice & Ambient Interaction Integration Contract
Role: Voice Integration / Planned Audio Interface

INVARIANTS:
- Voice is an ambient notification & query interface ONLY.
- Voice is NEVER permitted to authorize rehydration, release real secrets,
  or bypass biometric/PIN authorization requirements.
- All high-risk actions require interactive owner verification.
"""

from dataclasses import dataclass
from typing import Optional


@dataclass
class VoiceCommand:
    raw_transcript: str
    intent: str
    confidence: float
    parameters: dict


class VoiceInteractionHandler:
    """
    Handles ambient voice commands and dispatches them to standard backend APIs.
    Disallows authorization bypasses.
    """

    ALLOWED_INTENTS = {
        "CHECK_THREAT_STATUS": "/api/v1/risk/status",
        "RUN_EXPOSURE_SCAN": "/api/v1/exposure/search",
        "LIST_CASES": "/api/v1/cases/",
        "AUDIT_SUMMARY": "/api/v1/audit/logs",
    }

    BLOCKED_INTENTS = {
        "AUTHORIZE_REHYDRATION": "Voice authorization is strictly prohibited by security policy. Biometric or PIN required.",
        "EXPOSE_VALUE": "Direct voice release of vault values is disallowed.",
        "DELETE_VAULT": "Destructive operations require physical interaction.",
    }

    def process_transcript(self, transcript: str) -> dict:
        clean = (transcript or "").strip().lower()

        # Enforce security boundary
        for blocked_keyword, message in self.BLOCKED_INTENTS.items():
            if any(k in clean for k in ["authorize", "approve", "release", "reveal password", "show aadhaar"]):
                return {
                    "status": "BLOCKED",
                    "reason": "SECURITY_POLICY_VIOLATION",
                    "message": "Sensitive actions cannot be authorized via voice. Biometric/PIN assertion required.",
                }

        # Safe informational intents
        if "threat" in clean or "risk" in clean or "status" in clean:
            return {
                "status": "DISPATCHED",
                "intent": "CHECK_THREAT_STATUS",
                "route": self.ALLOWED_INTENTS["CHECK_THREAT_STATUS"],
            }
        elif "scan" in clean or "exposure" in clean or "leak" in clean:
            return {
                "status": "DISPATCHED",
                "intent": "RUN_EXPOSURE_SCAN",
                "route": self.ALLOWED_INTENTS["RUN_EXPOSURE_SCAN"],
            }
        elif "case" in clean or "erasure" in clean:
            return {
                "status": "DISPATCHED",
                "intent": "LIST_CASES",
                "route": self.ALLOWED_INTENTS["LIST_CASES"],
            }

        return {
            "status": "UNKNOWN_COMMAND",
            "message": "Command not recognized. Please use dashboard controls.",
        }
