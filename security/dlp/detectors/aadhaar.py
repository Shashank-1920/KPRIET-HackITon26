"""
S.H.A.D.E. — Aadhaar Number DLP Detector
Role: Member 2 — Security & DLP Engine

Detects 12-digit Indian Aadhaar numbers formatted with or without spaces/hyphens,
and verifies using the Dihedral Group D5 Verhoeff algorithm.
"""

import re
from typing import List

from security.dlp.detectors.base import BaseDetector, DetectionResult
from security.validators.verhoeff import validate_aadhaar_number

# Aadhaar pattern: 12 digits, optional space or dash every 4 digits, starting with [2-9]
_AADHAAR_REGEX = re.compile(r"\b([2-9][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4})\b")


class AadhaarDetector(BaseDetector):
    def detect(self, text: str) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        if not text:
            return results

        for match in _AADHAAR_REGEX.finditer(text):
            raw = match.group(1)
            digits_only = "".join(c for c in raw if c.isdigit())
            if len(digits_only) == 12 and validate_aadhaar_number(digits_only):
                results.append(
                    DetectionResult(
                        data_type="AADHAAR",
                        confidence=1.0,
                        raw_match=raw,
                        normalized_value=digits_only,
                        reason="12-digit format passed Verhoeff Dihedral D5 checksum",
                        metadata={"masked": f"XXXX-XXXX-{digits_only[-4:]}"},
                    )
                )
        return results
