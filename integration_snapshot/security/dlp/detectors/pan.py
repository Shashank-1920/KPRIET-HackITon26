"""
S.H.A.D.E. — Permanent Account Number (PAN) DLP Detector
Role: Member 2 — Security & DLP Engine

Validates Indian Income Tax PAN structure: [A-Z]{5}[0-9]{4}[A-Z]{1}.
"""

import re
from typing import List

from security.dlp.detectors.base import BaseDetector, DetectionResult

_PAN_REGEX = re.compile(r"\b([A-Z]{5}[0-9]{4}[A-Z]{1})\b")
_VALID_4TH_CHARS = set("CPHFATBLJG")


class PANDetector(BaseDetector):
    def detect(self, text: str) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        if not text:
            return results

        for match in _PAN_REGEX.finditer(text):
            raw = match.group(1)
            char_4 = raw[3]
            confidence = 1.0 if char_4 in _VALID_4TH_CHARS else 0.85
            results.append(
                DetectionResult(
                    data_type="PAN",
                    confidence=confidence,
                    raw_match=raw,
                    normalized_value=raw,
                    reason=f"Matches Indian PAN pattern with entity indicator '{char_4}'",
                    metadata={"masked": f"{raw[:2]}XXXXX{raw[-2:]}"},
                )
            )
        return results
