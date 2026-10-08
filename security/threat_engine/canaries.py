"""
S.H.A.D.E. — Canary Honey-Token Generator
Role: Member 2 — Security & Threat Engine

Generates cryptographic honey-tokens for verifiable data leak attribution.
If an attacker or external system leaks a canary token, S.H.A.D.E. can verify
the attribution signature deterministically.
"""

import hmac
import hashlib
import secrets
from typing import Dict, Tuple


class CanaryGenerator:
    """Generates and verifies canary tokens for breach leak attribution."""

    def __init__(self, master_secret: bytes = b"shade_canary_attribution_v1"):
        self.master_secret = master_secret

    def generate_canary(self, intended_recipient: str, canary_type: str = "API_KEY") -> Tuple[str, str]:
        """
        Generate a synthetic canary token bound to a specific recipient/channel.
        Returns (canary_token, canary_id).
        """
        canary_id = secrets.token_hex(6)
        sig = hmac.new(
            self.master_secret,
            f"{canary_id}:{intended_recipient}:{canary_type}".encode("utf-8"),
            hashlib.sha256
        ).hexdigest()[:8]

        if canary_type == "API_KEY":
            token = f"sk-canary-{canary_id}-{sig}"
        else:
            token = f"CANARY_{canary_id}_{sig}"

        return token, canary_id

    def verify_canary_attribution(self, token: str, intended_recipient: str, canary_type: str = "API_KEY") -> bool:
        """Verify whether a leaked token matches the intended attribution signature."""
        try:
            parts = token.split("-") if "-" in token else token.split("_")
            if len(parts) < 3:
                return False
            canary_id = parts[-2]
            provided_sig = parts[-1]
            expected_sig = hmac.new(
                self.master_secret,
                f"{canary_id}:{intended_recipient}:{canary_type}".encode("utf-8"),
                hashlib.sha256
            ).hexdigest()[:8]
            return hmac.compare_digest(provided_sig, expected_sig)
        except Exception:
            return False
