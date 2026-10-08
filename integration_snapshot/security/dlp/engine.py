"""
S.H.A.D.E. — Data Loss Prevention (DLP) Inspection Engine
Role: Member 2 — Security & DLP Engine

Orchestrates all deterministic detectors according to S.H.A.D.E. product requirements.
Invariants:
- Normal / general text is ignored (returns None).
- High-priority detection of credentials, Aadhaar, PAN, payment cards, UPI, mobile, plates.
- Deterministic execution without AI dependencies.
- No direct database access; results are returned to the caller / backend integration layer.
"""

import logging
from typing import List, Optional

from security.dlp.detectors.base import DetectionResult
from security.dlp.detectors.aadhaar import AadhaarDetector
from security.dlp.detectors.pan import PANDetector
from security.dlp.detectors.credentials import CredentialsDetector
from security.dlp.detectors.identifiers import IdentifiersDetector

logger = logging.getLogger(__name__)


class DLPEngine:
    """Master DLP inspection engine coordinating all deterministic detectors."""

    def __init__(self):
        # Order of precedence for evaluation
        self.detectors = [
            CredentialsDetector(),  # Check explicit secrets, API keys, passwords first
            AadhaarDetector(),      # Verhoeff-validated government ID
            PANDetector(),          # Indian PAN format
            IdentifiersDetector(),  # Cards, UPI, plates, mobile, email, secret URLs
        ]

    def inspect(self, content: str) -> Optional[DetectionResult]:
        """
        Inspect clipboard or input content.
        Returns the most relevant DetectionResult if sensitive, or None if normal text.
        """
        if not content or not content.strip():
            return None

        clean_text = content.strip()

        # Gather all detections
        all_results: List[DetectionResult] = []
        for detector in self.detectors:
            try:
                results = detector.detect(clean_text)
                if results:
                    all_results.extend(results)
            except Exception as e:
                logger.warning("[DLPEngine] Detector exception: %s", type(e).__name__)

        if not all_results:
            return None

        # Sort results by confidence descending, then by specific high-priority data types
        type_priority = {
            "API_KEY": 10,
            "PASSWORD": 9,
            "URL_WITH_SECRET": 8,
            "AADHAAR": 7,
            "PAN": 6,
            "CREDIT_CARD": 5,
            "UPI_ID": 4,
            "VEHICLE_PLATE": 3,
            "MOBILE": 2,
            "EMAIL": 1,
        }

        all_results.sort(
            key=lambda r: (r.confidence, type_priority.get(r.data_type, 0)),
            reverse=True,
        )

        top_match = all_results[0]
        logger.info(
            "[DLPEngine] Sensitive data identified: type=%s confidence=%.2f reason=%s",
            top_match.data_type,
            top_match.confidence,
            top_match.reason,
        )
        return top_match
