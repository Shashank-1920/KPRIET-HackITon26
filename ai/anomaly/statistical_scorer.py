"""S.H.A.D.E. Statistical Anomaly & Outlier Scoring Module.

Calculates Z-score deviations, Shannon entropy, and token frequency
anomalies on pre-masked payloads in < 1ms.
"""

from dataclasses import dataclass
from typing import Dict, List, Optional
import collections
import math

@dataclass
class StatisticalScore:
    """Statistical evaluation metrics for prompt payloads."""
    char_length: int
    token_count: int
    shannon_entropy: float
    length_z_score: float
    entropy_z_score: float
    is_outlier: bool
    outlier_reasons: List[str]

    def to_dict(self) -> Dict[str, object]:
        return {
            "char_length": self.char_length,
            "token_count": self.token_count,
            "shannon_entropy": round(self.shannon_entropy, 3),
            "length_z_score": round(self.length_z_score, 2),
            "entropy_z_score": round(self.entropy_z_score, 2),
            "is_outlier": self.is_outlier,
            "outlier_reasons": self.outlier_reasons,
        }

class StatisticalScorer:
    """Z-score and Shannon entropy detector for prompt payload characteristics."""

    def __init__(
        self,
        mean_length: float = 180.0,
        std_length: float = 120.0,
        mean_entropy: float = 4.2,
        std_entropy: float = 0.6,
        z_threshold: float = 2.5,
    ):
        self.mean_length = mean_length
        self.std_length = std_length
        self.mean_entropy = mean_entropy
        self.std_entropy = std_entropy
        self.z_threshold = z_threshold

    @staticmethod
    def calculate_shannon_entropy(text: str) -> float:
        """Computes the Shannon entropy in bits per character."""
        if not text:
            return 0.0
        counts = collections.Counter(text)
        total_len = len(text)
        entropy = 0.0
        for count in counts.values():
            prob = count / total_len
            entropy -= prob * math.log2(prob)
        return entropy

    def evaluate(self, text: str) -> StatisticalScore:
        """Evaluates statistical anomalies on the provided text."""
        char_len = len(text)
        tokens = text.split()
        token_count = len(tokens)
        entropy = self.calculate_shannon_entropy(text)

        # Z-scores
        length_z = (char_len - self.mean_length) / self.std_length if self.std_length > 0 else 0.0
        entropy_z = (entropy - self.mean_entropy) / self.std_entropy if self.std_entropy > 0 else 0.0

        outlier_reasons: List[str] = []
        is_outlier = False

        if abs(length_z) >= self.z_threshold:
            is_outlier = True
            direction = "excessively long" if length_z > 0 else "extremely short"
            outlier_reasons.append(f"Prompt length is {direction} (Z-score: {length_z:.2f})")

        if abs(entropy_z) >= self.z_threshold:
            is_outlier = True
            direction = "abnormally high entropy (possible encrypted/obfuscated payload)" if entropy_z > 0 else "abnormally low entropy (repetitive buffer stuffing)"
            outlier_reasons.append(f"Prompt entropy is {direction} (Z-score: {entropy_z:.2f})")

        return StatisticalScore(
            char_length=char_len,
            token_count=token_count,
            shannon_entropy=entropy,
            length_z_score=length_z,
            entropy_z_score=entropy_z,
            is_outlier=is_outlier,
            outlier_reasons=outlier_reasons,
        )
