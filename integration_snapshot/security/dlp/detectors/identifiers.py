"""
S.H.A.D.E. — Sensitive Identifiers DLP Detector
Role: Member 2 — Security & DLP Engine

Detects:
- Mobile numbers
- Email addresses
- Credit / Debit cards (with Luhn validation)
- Vehicle registration number plates
- UPI IDs
- URLs containing secrets
"""

import re
from typing import List

from security.dlp.detectors.base import BaseDetector, DetectionResult
from security.validators.luhn import validate_luhn

# Indian vehicle registration: 2 state letters, 1-2 RTO digits, 1-3 series letters, 4 vehicle digits
_VEHICLE_PLATE_REGEX = re.compile(
    r"\b([A-Z]{2}[ -]?[0-9]{1,2}[ -]?[A-Z]{1,3}[ -]?[0-9]{4})\b",
    re.IGNORECASE
)

# Indian mobile: starting with 6-9, optionally prefixed by +91 or 0
_MOBILE_REGEX = re.compile(
    r"(?:\+91[ -]?|0)?([6-9][0-9]{4}[ -]?[0-9]{5})\b"
)

# Email address
_EMAIL_REGEX = re.compile(
    r"\b([a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+)\b"
)

# Credit / Debit card: 13-19 digits, optionally spaced or hyphenated
_CARD_REGEX = re.compile(
    r"\b([3-6][0-9]{3}[ -]?[0-9]{4}[ -]?[0-9]{4}[ -]?[0-9]{1,4})\b"
)

# UPI ID
_UPI_REGEX = re.compile(
    r"\b([a-zA-Z0-9.\-_]{2,256}@(?!gmail|yahoo|outlook|hotmail|icloud|proton)[a-zA-Z]{2,64})\b",
    re.IGNORECASE
)

# URL containing secret parameters
_SECRET_URL_REGEX = re.compile(
    r"\b(https?://[^\s]+[?&](?:token|api_key|apikey|secret|key|access_token|auth|password)=([^\s&]+)[^\s]*)\b",
    re.IGNORECASE
)


class IdentifiersDetector(BaseDetector):
    def detect(self, text: str) -> List[DetectionResult]:
        results: List[DetectionResult] = []
        if not text:
            return results

        # 1. URLs containing secrets
        for match in _SECRET_URL_REGEX.finditer(text):
            full_url = match.group(1)
            results.append(
                DetectionResult(
                    data_type="URL_WITH_SECRET",
                    confidence=1.0,
                    raw_match=full_url,
                    normalized_value=full_url,
                    reason="URL exposes sensitive authentication token or secret in query parameters",
                    metadata={"url_masked": full_url.split("?")[0] + "?[REDACTED]"},
                )
            )

        # 2. Credit / Debit card (validated via Luhn)
        for match in _CARD_REGEX.finditer(text):
            raw = match.group(1)
            digits = "".join(c for c in raw if c.isdigit())
            if 13 <= len(digits) <= 19 and validate_luhn(digits):
                results.append(
                    DetectionResult(
                        data_type="CREDIT_CARD",
                        confidence=1.0,
                        raw_match=raw,
                        normalized_value=digits,
                        reason="Passes Luhn Mod-10 payment card checksum",
                        metadata={"masked": f"XXXX-XXXX-XXXX-{digits[-4:]}"},
                    )
                )

        # 3. UPI ID (checked before email to prioritize UPI handles)
        for match in _UPI_REGEX.finditer(text):
            raw = match.group(1)
            results.append(
                DetectionResult(
                    data_type="UPI_ID",
                    confidence=0.95,
                    raw_match=raw,
                    normalized_value=raw.lower(),
                    reason="Matches Indian UPI Virtual Payment Address (VPA) format",
                    metadata={"masked": f"{raw[:2]}***@{raw.split('@')[1]}"},
                )
            )

        # 4. Vehicle Registration Plate
        for match in _VEHICLE_PLATE_REGEX.finditer(text):
            raw = match.group(1).upper()
            clean = re.sub(r"[ -]", "", raw)
            # Only consider valid length for Indian number plates (8-10 chars)
            if 8 <= len(clean) <= 10:
                results.append(
                    DetectionResult(
                        data_type="VEHICLE_PLATE",
                        confidence=0.90,
                        raw_match=raw,
                        normalized_value=clean,
                        reason="Matches Indian motor vehicle registration plate format",
                        metadata={"masked": f"{clean[:2]}**{clean[-4:]}"},
                    )
                )

        # 5. Mobile Numbers
        for match in _MOBILE_REGEX.finditer(text):
            raw = match.group(1)
            digits = "".join(c for c in raw if c.isdigit())
            if len(digits) == 10:
                results.append(
                    DetectionResult(
                        data_type="MOBILE",
                        confidence=0.92,
                        raw_match=raw,
                        normalized_value=digits,
                        reason="Matches 10-digit mobile phone number standard",
                        metadata={"masked": f"+91 {digits[:2]}******{digits[-2:]}"},
                    )
                )

        # 6. Email Addresses
        for match in _EMAIL_REGEX.finditer(text):
            raw = match.group(1)
            # Avoid duplicate if already marked as UPI
            if not any(r.data_type == "UPI_ID" and r.raw_match == raw for r in results):
                results.append(
                    DetectionResult(
                        data_type="EMAIL",
                        confidence=0.95,
                        raw_match=raw,
                        normalized_value=raw.lower(),
                        reason="Standard RFC 5322 email address format",
                        metadata={"masked": f"{raw[:2]}***@{raw.split('@')[1]}"},
                    )
                )

        return results
