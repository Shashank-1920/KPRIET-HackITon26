"""S.H.A.D.E. Explainable Behavioral Evaluation & Anomaly Scoring Pipeline.

Combines statistical Z-score outliers, prompt injection heuristics, and PII
density spikes into a single explainable assessment.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List

from ai.anomaly.statistical_scorer import StatisticalScore, StatisticalScorer
from ai.heuristics.pii_density import PIIDensityEvaluator, PIIDensityReport
from ai.heuristics.prompt_injection import HeuristicFinding, PromptInjectionFilter

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MODERATE = "MODERATE"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class TriageRecommendation(str, Enum):
    ALLOW = "ALLOW"
    FLAG = "FLAG"
    BLOCK = "BLOCK"

@dataclass
class AnomalyEvaluationReport:
    """Explainable anomaly evaluation dossier for pre-masked payloads."""
    threat_level: ThreatLevel
    composite_risk_score: float  # Normalized 0.0 to 1.0
    triage_recommendation: TriageRecommendation
    is_anomalous: bool
    explainable_factors: List[str] = field(default_factory=list)
    statistical_metrics: Dict[str, Any] = field(default_factory=dict)
    pii_metrics: Dict[str, Any] = field(default_factory=dict)
    heuristic_findings: List[Dict[str, Any]] = field(default_factory=list)
    is_advisory_only: bool = True  # Strict Architecture Invariant

    def to_dict(self) -> Dict[str, Any]:
        return {
            "threat_level": self.threat_level.value,
            "composite_risk_score": round(self.composite_risk_score, 3),
            "triage_recommendation": self.triage_recommendation.value,
            "is_anomalous": self.is_anomalous,
            "explainable_factors": self.explainable_factors,
            "statistical_metrics": self.statistical_metrics,
            "pii_metrics": self.pii_metrics,
            "heuristic_findings": self.heuristic_findings,
            "is_advisory_only": self.is_advisory_only,
        }

class AnomalyEvaluator:
    """Unified behavioral and statistical anomaly pipeline."""

    def __init__(
        self,
        stat_scorer: StatisticalScorer = None,
        injection_filter: PromptInjectionFilter = None,
        pii_evaluator: PIIDensityEvaluator = None,
        flag_threshold: float = 0.35,
        block_threshold: float = 0.70,
    ):
        self.stat_scorer = stat_scorer or StatisticalScorer()
        self.injection_filter = injection_filter or PromptInjectionFilter()
        self.pii_evaluator = pii_evaluator or PIIDensityEvaluator()
        self.flag_threshold = flag_threshold
        self.block_threshold = block_threshold

    def evaluate_payload(self, pre_masked_text: str) -> AnomalyEvaluationReport:
        """Executes full explainable evaluation on a pre-masked payload."""
        if not pre_masked_text or not pre_masked_text.strip():
            return AnomalyEvaluationReport(
                threat_level=ThreatLevel.LOW,
                composite_risk_score=0.0,
                triage_recommendation=TriageRecommendation.ALLOW,
                is_anomalous=False,
                explainable_factors=["Empty prompt evaluated as safe."],
            )

        # 1. Statistical evaluation
        stat_result: StatisticalScore = self.stat_scorer.evaluate(pre_masked_text)

        # 2. PII density evaluation
        pii_result: PIIDensityReport = self.pii_evaluator.evaluate(pre_masked_text)

        # 3. Prompt injection & adversarial heuristic scan
        findings, has_obfuscation, decoded_payloads = self.injection_filter.inspect(
            pre_masked_text
        )

        # 4. Composite Scoring
        explainable_factors: List[str] = []
        score_accumulator = 0.0

        # Heuristic rules score
        if findings:
            heuristic_weight = sum(f.severity_weight for f in findings)
            score_accumulator += heuristic_weight
            for f in findings:
                explainable_factors.append(f"[{f.category}] {f.rule_name}: {f.description}")

        # Obfuscation penalty
        if has_obfuscation:
            score_accumulator += 0.25
            explainable_factors.append(
                f"Obfuscation Detected: Found {len(decoded_payloads)} Base64 encoded payload(s)."
            )

        # Statistical outlier score
        if stat_result.is_outlier:
            score_accumulator += 0.20
            explainable_factors.extend(stat_result.outlier_reasons)

        # PII density spike score
        if pii_result.is_dense_spike:
            score_accumulator += 0.25
            explainable_factors.append(
                f"High PII Density Spike: {pii_result.pii_token_count} synthetic tokens detected ({pii_result.pii_density_ratio:.1%} of prompt)."
            )

        # Normalize score 0.0 - 1.0
        composite_score = min(1.0, score_accumulator)

        # Determine Threat Level and Triage
        if composite_score >= self.block_threshold:
            threat_level = ThreatLevel.CRITICAL if composite_score >= 0.85 else ThreatLevel.HIGH
            triage = TriageRecommendation.BLOCK
            is_anomalous = True
        elif composite_score >= self.flag_threshold:
            threat_level = ThreatLevel.MODERATE
            triage = TriageRecommendation.FLAG
            is_anomalous = True
        else:
            threat_level = ThreatLevel.LOW
            triage = TriageRecommendation.ALLOW
            is_anomalous = False

        if not explainable_factors:
            explainable_factors.append("Payload within nominal entropy and pattern distributions.")

        return AnomalyEvaluationReport(
            threat_level=threat_level,
            composite_risk_score=composite_score,
            triage_recommendation=triage,
            is_anomalous=is_anomalous,
            explainable_factors=explainable_factors,
            statistical_metrics=stat_result.to_dict(),
            pii_metrics=pii_result.to_dict(),
            heuristic_findings=[
                {
                    "rule_id": f.rule_id,
                    "rule_name": f.rule_name,
                    "category": f.category,
                    "weight": f.severity_weight,
                    "matched": f.matched_snippet,
                }
                for f in findings
            ],
            is_advisory_only=True,
        )
