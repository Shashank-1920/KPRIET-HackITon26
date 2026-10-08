# S.H.A.D.E.
### Synthetic Host for Anonymization, Detection & Enforcement
*Personal Autonomous Counter-Intelligence & Security Operations Center (SOC)*

[![Architecture Status](https://img.shields.io/badge/Architecture-Approved-00e5ff?style=flat-square)](docs/architecture/ARCHITECTURE.md)
[![Workflow](https://img.shields.io/badge/Git%20Workflow-4--Member%20Decoupled-34d399?style=flat-square)](docs/architecture/REPOSITORY_STRUCTURE.md)
[![Target Stack](https://img.shields.io/badge/Stack-FastAPI%20%7C%20React%2019%20%7C%20PostgreSQL-38bdf8?style=flat-square)](docs/architecture/ARCHITECTURE.md)

---

## 1. Overview
**S.H.A.D.E.** transforms defensive cybersecurity from passive compliance into an edge-first active defense operations center. It provides:
1. **Real-Time DLP**: Deterministic interception of Aadhaar (Verhoeff checksum verified), PAN cards, and credentials before they leave the host to cloud LLMs.
2. **Breach Radar**: Privacy-preserving k-anonymity checks (SHA-1 hash prefix only) against public exposure datasets.
3. **Decoy Canaries**: Cryptographically attributed honeytoken credentials that provide mathematical leak attribution when third-party fiduciaries are breached.
4. **Statutory Takedown**: Automated drafting of Indian DPDP Act 2023 Section 12 data erasure notices with verified legal clauses.
5. **Cyber War-Room HUD**: Reactive React 19 interface with SVG 0–100 Exposome Threat Index gauge and offline failover resilience.

---

## 2. Four-Member Team Division & Ownership

| Workstream | Owner | Primary Git Branch | Directory Ownership | Core Responsibilities |
| :--- | :--- | :--- | :--- | :--- |
| **Member 1** | Architecture Lead | `member-1/backend` | `backend/`, `docs/`, `docker-compose.yml` | Core architecture, FastAPI runtime, PostgreSQL schemas, Pydantic contracts, integration. |
| **Member 2** | Security Lead | `member-2/security` | `security/`, `tests/security/` | Deterministic DLP regex, Verhoeff checksums, Canary generator, HIBP client, risk matrix. |
| **Member 3** | AI / Anomaly Lead | `member-3/ai` | `ai/`, `tests/ai/` | Statistical anomaly detection (Z-score), PII density heuristics, DPDP Section 12 notice generator. |
| **Member 4** | Frontend / UX Lead | `member-4/frontend` | `frontend/`, `voice/`, `tests/frontend/` | React 19 War-Room HUD, SVG threat gauge, live sandbox, voice daemon HUD. |

---

## 3. Repository Architecture

```
KPRIET-HackITon26/
├── backend/                         # Member 1: Core FastAPI, DB sessions, models, and schemas
├── security/                        # Member 2: DLP regex, Verhoeff validator, canaries, and HIBP client
├── ai/                              # Member 3: Anomaly scoring, explainable heuristics, and DPDP templates
├── frontend/                        # Member 4: React 19 Cyber War-Room HUD and SVG threat meter
├── voice/                           # Planned: Ambient offline voice listener and TTS status briefings
├── tests/                           # Shared: Decoupled unit, security, and integration test suites
├── docs/                            # Shared: Master system architecture and technical blueprints
├── scripts/                         # Shared: Developer setup scripts and offline demo datasets
├── .env.example                     # Sanitized configuration template
├── .gitignore                       # Git exclusion rules
├── docker-compose.yml               # Multi-container deployment specification
└── README.md                        # Master project documentation (this file)
```

---

## 4. Key Documentation Links
- **[Master System Architecture (ARCHITECTURE.md)](docs/architecture/ARCHITECTURE.md)**: 34-section secure design blueprint, sequence diagrams, ER diagrams, and API contracts.
- **[Repository Structure & Module Ownership (REPOSITORY_STRUCTURE.md)](docs/architecture/REPOSITORY_STRUCTURE.md)**: Strict module boundaries, dependency rules, and Git collaboration workflows.
- **[Visual Architecture Diagram (repository_architecture.svg)](docs/architecture/diagrams/repository_architecture.svg)**: High-resolution SVG topology of workstream boundaries.

---

## 5. Development & Git Workflow Rules
- **No Direct Push to `main`**: All work is developed and committed on dedicated member branches (`member-1/backend`, `member-2/security`, etc.).
- **Inspect Before Editing**: Always verify git status and existing implementations before modifying files.
- **Zero Plaintext Secrets**: Never commit `.env`, private keys, passwords, or tokens.
- **Deterministic-First Authority**: AI/ML models never make independent security authorization decisions.
- **Fail-Safe Offline Mode**: Cloud API integrations maintain instant local mock fallbacks for hackathon demo resilience.
