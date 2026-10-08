# S.H.A.D.E. — AI/ML & Anomaly Analysis Module
**Ownership**: Member 3 (`member-3/ai`)  
**Role**: "AI/ML + Detection + Anomaly Analysis"

---

## Scope of Responsibility
- Statistical outlier detection and prompt length/frequency anomaly scoring (`anomaly/`)
- Heuristic PII density and prompt injection analysis (`heuristics/`)
- Explainable score justifications and telemetry metadata (`analysis/`)
- Indian DPDP Act 2023 Section 12 legal notice generation templates (`templates/`)
- Masked prompt construction for Google Gemini 2.5 Flash / local Ollama inference

## Boundary Invariants
- **No Raw PII in AI Pipelines**: AI models must operate strictly on pre-masked payloads (`<SYN_AADHAAR_xxxx>`). Raw Aadhaar, PAN, or credentials must never enter prompt templates.
- **Explainability Standard**: Every anomaly score must provide human-readable heuristic factors (e.g., Z-score deviation, prompt entropy).
- **Advisory Role**: AI analysis is advisory and cannot independently authorize high-risk actions.
