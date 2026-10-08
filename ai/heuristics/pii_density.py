"""Heuristic evaluator for PII token density in pre-masked payloads."""

from dataclasses import dataclass
from typing import Dict, List
import re

@dataclass
class PIIDensityReport:
    total_tokens: int
    pii_token_count: int
    pii_density_ratio: float
    detected_placeholders: List[str]
    is_dense_spike: bool

    def to_dict(self) -> Dict[str, object]:
        return {
            "total_tokens": self.total_tokens,
            "pii_token_count": self.pii_token_count,
            "pii_density_ratio": round(self.pii_density_ratio, 3),
            "detected_placeholders": self.detected_placeholders,
            "is_dense_spike": self.is_dense_spike,
        }

class PIIDensityEvaluator:
    """Evaluates synthetic token concentration to flag PII exfiltration or bulk extraction spikes."""

    def __init__(self, spike_threshold: float = 0.20, count_spike_threshold: int = 5):
        self.spike_threshold = spike_threshold
        self.count_spike_threshold = count_spike_threshold
        self._syn_pattern = re.compile(r"<SYN_[A-Z0-9_]+>", re.IGNORECASE)

    def evaluate(self, pre_masked_text: str) -> PIIDensityReport:
        """Calculates the synthetic token density of a pre-masked payload."""
        words = pre_masked_text.split()
        total_tokens = len(words)
        matches = self._syn_pattern.findall(pre_masked_text)
        pii_count = len(matches)

        density = (pii_count / total_tokens) if total_tokens > 0 else 0.0
        is_spike = (
            (density >= self.spike_threshold and pii_count >= 2)
            or (pii_count >= self.count_spike_threshold)
        )

        return PIIDensityReport(
            total_tokens=total_tokens,
            pii_token_count=pii_count,
            pii_density_ratio=density,
            detected_placeholders=matches,
            is_dense_spike=is_spike,
        )
