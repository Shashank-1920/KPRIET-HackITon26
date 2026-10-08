"""
S.H.A.D.E. — Base DLP Detector Abstraction & Detection Result
Role: Member 2 — Security & DLP Engine
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class DetectionResult:
    """Standardized detection result returned by Member 2's DLP engine."""
    data_type: str
    confidence: float
    raw_match: str
    normalized_value: str
    reason: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class BaseDetector(ABC):
    """Abstract base class for all deterministic DLP detectors."""

    @abstractmethod
    def detect(self, text: str) -> List[DetectionResult]:
        """Inspect text and return zero or more detection results."""
