# S.H.A.D.E.
### Synthetic Host for Anonymization, Detection & Enforcement
*Personal Autonomous Counter-Intelligence & Security Operations Center (SOC)*

[![Architecture Status](https://img.shields.io/badge/Architecture-Local--First%20Encrypted-00e5ff?style=flat-square)](docs/architecture/ARCHITECTURE.md)
[![Privacy Model](https://img.shields.io/badge/Privacy-Device--Local%20Vault-34d399?style=flat-square)](docs/architecture/ARCHITECTURE.md)
[![Target Stack](https://img.shields.io/badge/Stack-FastAPI%20%7C%20React%2019%20%7C%20Encrypted%20SQLite-38bdf8?style=flat-square)](docs/architecture/ARCHITECTURE.md)

---

## 1. Overview
**S.H.A.D.E.** is a **local-first, privacy-first, device-local, security-first** personal security operations center. It establishes the owner's personal device as the sole authoritative repository for sensitive identity data and cryptographic mappings.

### Core Philosophy: Real Data Stays Local
1. **Real-Time DLP**: Intercepts outbound sensitive data (Aadhaar with Verhoeff verification, PAN cards, API keys) at the host boundary.
2. **Synthetic Tokenization**: Replaces sensitive data with local synthetic placeholders (`<SYN_AADHAAR_xxxx>`). External services and cloud LLMs receive **only** synthetic representations.
3. **Local Encrypted Vault**: Stores the mapping between synthetic tokens and encrypted real data inside a device-local encrypted SQLite database (e.g. SQLCipher) with keys managed by the OS keystore (`SecureKeyStore`).
4. **Owner Authorization & Local Rehydration**: Rehydrating synthetic tokens back into real data occurs strictly on the local device and requires explicit owner permission.
5. **Breach Radar & Honeytokens**: Privacy-preserving k-anonymity password breach lookups (SHA-1 prefix only) and trackable decoy canary credentials.
6. **Statutory Takedown**: Automated drafting of Indian DPDP Act 2023 Section 12 erasure requisitions.

---

## 2. Four-Member Team Division & Ownership

| Workstream | Owner | Primary Git Branch | Directory Ownership | Core Responsibilities |
| :--- | :--- | :--- | :--- | :--- |
| **Member 1** | Architecture & Backend Lead | `member-1/backend` | `backend/`, `docs/`, `docker-compose.yml` | Core architecture, FastAPI runtime, local encrypted database, `SecureKeyStore` abstraction, owner permission gate, integration. |
| **Member 2** | Security & Threat Lead | `member-2/security` | `security/`, `tests/security/` | Deterministic DLP regex, Verhoeff checksums, Canary honeytokens, HIBP k-anonymity client, risk matrix. |
| **Member 3** | AI & Anomaly Lead | `member-3/ai` | `ai/`, `tests/ai/` | Statistical anomaly detection (Z-score), PII density heuristics, DPDP Section 12 notice generator (operates strictly on masked payloads). |
| **Member 4** | Frontend & UX Lead | `member-4/frontend` | `frontend/`, `voice/`, `tests/frontend/` | React 19 War-Room HUD, SVG threat gauge, live sandbox, owner permission approval modal, voice HUD. |

---

## 3. Repository Architecture

```
KPRIET-HackITon26/
├── backend/                         # Member 1: FastAPI, Local Encrypted Vault, KeyStore, Permissions
├── security/                        # Member 2: DLP regex, Verhoeff validator, canaries, and HIBP client
├── ai/                              # Member 3: Anomaly scoring, explainable heuristics, and DPDP templates
├── frontend/                        # Member 4: React 19 Cyber War-Room HUD, Threat Meter, Approval Modal
├── voice/                           # Planned: Ambient offline voice listener and TTS status briefings
├── tests/                           # Shared: Decoupled unit, security, and integration test suites
├── docs/                            # Shared: Master system architecture and technical blueprints
├── scripts/                         # Shared: Developer setup scripts and offline demo datasets
├── .env.example                     # Sanitized configuration template
├── .gitignore                       # Git exclusion rules
├── docker-compose.yml               # Multi-container local deployment specification
└── README.md                        # Master project documentation (this file)
```

---

## 4. Key Documentation Links
- **[Master Product Requirements (PRODUCT_REQUIREMENTS.md)](docs/PRODUCT_REQUIREMENTS.md)**: Master functional requirements, sensitive data scope, clipboard protection (CTRL+C), 12-char synthetic token rules, and 7-day erasure workflow.
- **[Master System Architecture (ARCHITECTURE.md)](docs/architecture/ARCHITECTURE.md)**: Comprehensive local-first system blueprint, SQLCipher data vault, sequence diagrams, ER diagrams, and API contracts.
- **[Repository Structure & Module Ownership (REPOSITORY_STRUCTURE.md)](docs/architecture/REPOSITORY_STRUCTURE.md)**: Strict module boundaries, dependency rules, and Git collaboration workflows.
- **[Visual Architecture Diagram (repository_architecture.svg)](docs/architecture/diagrams/repository_architecture.svg)**: High-resolution SVG topology of workstream boundaries and local vault flow.

---

## 5. Real-World Integration Status

| Integration | Category / Mechanism | Status | Verified? | External / Environment Requirement |
| :--- | :--- | :--- | :--- | :--- |
| **Windows OS Clipboard Hook** | Win32 ctypes `user32`/`kernel32` sequence listener & atomic replacement | **IMPLEMENTED + VERIFIED** | **YES** | Windows OS (tested live on Win32 host). Cross-platform fallback available via `MemoryClipboardProvider`. |
| **Platform Biometrics** | Windows Hello / WebAuthn / FIDO2 Level 2 & TPM cryptographic assertion verification (Ed25519 & ECDSA P-256) | **IMPLEMENTED + REQUIRES LOCAL HARDWARE** | **YES (Cryptographic contract verified)** | Physical platform authenticator touch / biometric sensor required for human presence assertions; Argon2id PIN fallback is 100% operational. |
| **Statutory SMTP Legal Delivery** | Python MIME `smtplib` provider with STARTTLS / SSL & dev-simulation mode | **IMPLEMENTED + REQUIRES CONFIGURATION** | **YES (Dev simulation & contracts verified)** | Requires outbound SMTP credentials (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`) for live external transmission; safely runs in simulated dev mode by default. |
| **Breach Coverage (Passwords)** | NIST / Cloudflare SHA-1 prefix k-anonymity API (`api.pwnedpasswords.com`) | **IMPLEMENTED + VERIFIED** | **YES** | Outbound HTTPS connectivity (password never leaves machine; offline fallback supported). |
| **Breach Coverage (Email Accounts)** | Commercial HIBP v3 Breached Account API | **IMPLEMENTED + REQUIRES EXTERNAL PROVIDER** | **YES (Capability scoped & gated)** | Requires commercial `HIBP_API_KEY` environment variable. |
| **Breach Coverage (National IDs / Aadhaar / PAN)** | Public Consumer Breach Querying | **NOT SUPPORTED** | **N/A** | **Statutorily and technically unsupported**: No lawful public consumer query API exists for Indian national identity numbers. |

