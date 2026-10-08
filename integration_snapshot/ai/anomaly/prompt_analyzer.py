"""
S.H.A.D.E. — AI Prompt & PII Density Anomaly Analyzer
Role: Member 3 — AI/ML + Anomaly Analysis

Evaluates:
- Synthetic token density in outbound prompts
- High-risk prompt injection keywords
- Statistical length outliers
"""

import re
from dataclasses import dataclass
from typing import Dict, List

from ai.anomaly.entropy import calculate_entropy


@dataclass
class AnomalyAnalysisResult:
    anomaly_score: float  # 0.0 to 1.0
    is_anomalous: bool
    synthetic_tokens_found: int
    pii_density: float
    entropy: float
    detected_indicators: List[str]


class PromptAnomalyAnalyzer:
    """Analyzes text prompts for anomalous PII leakage risk and prompt anomalies."""

    _INJECTION_PATTERNS = [
        re.compile(r"ignore\s+previous\s+instructions", re.IGNORECASE),
        re.compile(r"system\s+prompt\s+override", re.IGNORECASE),
        re.compile(r"reveal\s+all\s+secrets", re.IGNORECASE),
        re.compile(r"dump\s+database", re.IGNORECASE),
    ]

    def analyze(self, text: str) -> AnomalyAnalysisResult:
        if not text:
            return AnomalyAnalysisResult(
                anomaly_score=0.0,
                is_anomalous=False,
                synthetic_tokens_found=0,
                pii_density=0.0,
                entropy=0.0,
                detected_indicators=[],
            )

        indicators = []
        tokens = text.split()
        total_tokens = max(1, len(tokens))

        # Check for synthetic tokens (SHD_XXXXXXXX or <SYN_...>)
        synthetic_matches = re.findall(r"\bSHD_[A-Z0-9]{8}\b|<SYN_[A-Z_]+_[A-Z0-9]+>", text)
        synthetic_count = len(synthetic_matches)
        pii_density = synthetic_count / total_tokens

        if pii_density > 0.4:
            indicators.append("HIGH_PII_TOKEN_DENSITY")

        # Check prompt injection markers
        for pat in self._INJECTION_PATTERNS:
            if pat.search(text):
                indicators.append(f"INJECTION_PATTERN:{pat.pattern}")

        # Check entropy
        entropy = calculate_entropy(text)
        if entropy > 5.5 and len(text) > 100:
            indicators.append("HIGH_ENTROPY_OBFUSCATION")

        # Compute anomaly score (0.0 to 1.0)
        score = min(1.0, (len(indicators) * 0.3) + (pii_density * 0.5))
        is_anomalous = score >= 0.5

        return AnomalyAnalysisResult(
            anomaly_score=round(score, 2),
            is_anomalous=is_anomalous,
            synthetic_tokens_found=synthetic_count,
            pii_density=round(pii_density, 3),
            entropy=round(entropy, 2),
            detected_indicators=indicators,
        )
