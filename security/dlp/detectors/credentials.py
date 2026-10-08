"""
S.H.A.D.E. — Credentials, API Keys & Passwords DLP Detector
Role: Member 2 — Security & DLP Engine

Detects API keys, access/secret tokens, and passwords.
"""

import math
import re
from typing import List

from security.dlp.detectors.base import BaseDetector, DetectionResult

_PATTERNS = [
    # OpenAI API Key
    (re.compile(r"\b(sk-(?:proj-|admin-|live-)?[a-zA-Z0-9_-]{24,})\b"), "API_KEY", "OpenAI API Key signature", 1.0),
    # AWS Access Key ID
    (re.compile(r"\b(AKIA[0-9A-Z]{16})\b"), "API_KEY", "AWS Access Key ID format", 1.0),
    # AWS Secret Access Key prefix or context
    (re.compile(r"(?:aws_secret_access_key|secret_key|secret_access_key)\s*[:=]\s*([A-Za-z0-9/+=]{40})", re.IGNORECASE), "API_KEY", "AWS Secret Access Key", 1.0),
    # GitHub Personal Access Token
    (re.compile(r"\b(gh[pousr]_[0-9a-zA-Z]{36,255})\b"), "API_KEY", "GitHub Access Token format", 1.0),
    # Google API Key
    (re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b"), "API_KEY", "Google Cloud API Key format", 1.0),
    # Slack Token
    (re.compile(r"\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b"), "API_KEY", "Slack Token format", 1.0),
    # Explicit Password assignments
    (re.compile(r"(?:password|passwd|pwd)\s*[:=]\s*([^\s]{6,128})", re.IGNORECASE), "PASSWORD", "Explicit password assignment", 0.95),
]


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy to detect high-entropy secrets."""
    if not data:
        return 0.0
    entropy = 0.0
    for x in set(data):
        p_x = float(data.count(x)) / len(data)
        if p_x > 0:
            entropy += - p_x * math.log2(p_x)
    return entropy


class CredentialsDetector(BaseDetector):
    def detect(self, text: str) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        if not text:
            return results

        # 1. Check known signature patterns
        for regex, data_type, reason, confidence in _PATTERNS:
            for match in regex.finditer(text):
                val = match.group(1)
                results.append(
                    DetectionResult(
                        data_type=data_type,
                        confidence=confidence,
                        raw_match=val,
                        normalized_value=val,
                        reason=reason,
                        metadata={"masked": f"{val[:3]}...{val[-3:]}" if len(val) > 6 else "******"},
                    )
                )

        # 2. Check high-entropy tokens if no signature matched and text is a single token
        tokens = text.strip().split()
        if len(tokens) == 1 and not results:
            token = tokens[0]
            if len(token) >= 32 and re.match(r"^[A-Za-z0-9_\-+/=]+$", token):
                entropy = _shannon_entropy(token)
                if entropy >= 3.8:
                    results.append(
                        DetectionResult(
                            data_type="API_KEY",
                            confidence=0.88,
                            raw_match=token,
                            normalized_value=token,
                            reason=f"High entropy secret string (entropy: {entropy:.2f})",
                            metadata={"entropy": entropy, "masked": f"{token[:4]}...{token[-4:]}"},
                        )
                    )

        return results
