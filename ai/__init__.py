"""S.H.A.D.E. AI & Anomaly Analysis Module (Member 3).

Provides:
- Statistical outlier scoring & Shannon entropy (Section 13)
- Prompt injection & jailbreak filtering (Section 13)
- 0-100 Exposure Risk Engine & classifications: 0, LOW, MEDIUM, CRITICAL (Section 18 & 19)
- DPDP Act 2023 Section 12 notice synthesis (Section 20)
- 7-Day Deadline Monitor & Case Investigation Records (Section 20 & 21)
- Multi-tier model routing (Gemini Flash, Ollama, Offline Fallback)
"""

from ai.analysis.evaluator import (
    AnomalyEvaluationReport,
    AnomalyEvaluator,
    ThreatLevel,
    TriageRecommendation,
)
from ai.analysis.risk_scoring import (
    ExposureReport,
    ExposureRiskEngine,
    ExposureTargetType,
    RiskClassification,
)
from ai.anomaly.statistical_scorer import StatisticalScore, StatisticalScorer
from ai.heuristics.pii_density import PIIDensityEvaluator, PIIDensityReport
from ai.heuristics.prompt_injection import HeuristicFinding, PromptInjectionFilter
from ai.legal.dpdp_generator import (
    DPDPNoticeGenerator,
    ErasureNoticeRequest,
    TakedownNoticeRecord,
)
from ai.legal.followup_generator import (
    CaseStatus,
    ErasureWorkflowEngine,
    InvestigationCaseRecord,
    StatutoryFollowUpNotice,
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
    "ExposureRiskEngine",
    "ExposureReport",
    "ExposureTargetType",
    "RiskClassification",
    "DPDPNoticeGenerator",
    "ErasureNoticeRequest",
    "TakedownNoticeRecord",
    "ErasureWorkflowEngine",
    "InvestigationCaseRecord",
    "StatutoryFollowUpNotice",
    "CaseStatus",
    "MaskedPromptConstructor",
    "OfflineModelFallback",
    "RawPIILeakException",
    "UnifiedModelRouter",
]
