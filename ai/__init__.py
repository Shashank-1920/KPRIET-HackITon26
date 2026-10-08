"""S.H.A.D.E. AI & Anomaly Analysis Module (Member 3).

Provides statistical outlier scoring, prompt injection filtering, explainable
behavioral assessments, statutory DPDP Act 2023 Section 12 notice synthesis,
and multi-tier model routing (Gemini Flash, Ollama, Offline Fallback).
"""

from ai.analysis.evaluator import (
    AnomalyEvaluationReport,
    AnomalyEvaluator,
    ThreatLevel,
    TriageRecommendation,
)
from ai.anomaly.statistical_scorer import StatisticalScore, StatisticalScorer
from ai.heuristics.pii_density import PIIDensityEvaluator, PIIDensityReport
from ai.heuristics.prompt_injection import HeuristicFinding, PromptInjectionFilter
from ai.legal.dpdp_generator import (
    DPDPNoticeGenerator,
    ErasureNoticeRequest,
    TakedownNoticeRecord,
)
from ai.models.inference_handler import (
    MaskedPromptConstructor,
    OfflineModelFallback,
    RawPIILeakException,
    UnifiedModelRouter,
)

__all__ = [
    "StatisticalScorer",
    "StatisticalScore",
    "PromptInjectionFilter",
    "HeuristicFinding",
    "PIIDensityEvaluator",
    "PIIDensityReport",
    "AnomalyEvaluator",
    "AnomalyEvaluationReport",
    "ThreatLevel",
    "TriageRecommendation",
    "DPDPNoticeGenerator",
    "ErasureNoticeRequest",
    "TakedownNoticeRecord",
    "MaskedPromptConstructor",
    "OfflineModelFallback",
    "RawPIILeakException",
    "UnifiedModelRouter",
]
