"""
S.H.A.D.E. — DLP Detectors Suite
Role: Member 2 — Security & DLP Engine
"""

from security.dlp.detectors.base import BaseDetector, DetectionResult
from security.dlp.detectors.aadhaar import AadhaarDetector
from security.dlp.detectors.pan import PANDetector
from security.dlp.detectors.credentials import CredentialsDetector
from security.dlp.detectors.identifiers import IdentifiersDetector

__all__ = [
    "BaseDetector",
    "DetectionResult",
    "AadhaarDetector",
    "PANDetector",
    "CredentialsDetector",
    "IdentifiersDetector",
]
