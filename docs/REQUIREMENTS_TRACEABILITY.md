# S.H.A.D.E. — Master Requirements Traceability Matrix
**Document Version**: 2.0.0  
**Baseline**: PRODUCT_REQUIREMENTS.md (Locked Master Specification)  
**Verification Date**: October 2026  

---

## Traceability Matrix

| ID | Locked Product Requirement | Owner Module | Implementation Reference | Verification Test | Status |
|:---|:---|:---|:---|:---|:---|
| **REQ-01** | Local-First & Privacy-First Architecture | Member 1 (Backend) | [`backend/app/database/encrypted_sqlite.py`](file:///backend/app/database/encrypted_sqlite.py) | `test_encrypted_database_storage_at_rest`, `test_offline_vault_encryption_decryption` | **IMPLEMENTED** |
| **REQ-02** | Team Ownership Boundaries & Contracts | All Members | [`docs/INTEGRATION_CONTRACTS.md`](file:///docs/INTEGRATION_CONTRACTS.md) | `test_architectural_database_isolation` | **IMPLEMENTED** |
| **REQ-03** | Sensitive Identifiers & Credentials Scope | Member 2 (Security) | [`security/dlp/detectors/`](file:///security/dlp/detectors/) | `test_aadhaar_detector`, `test_pan_detector`, `test_credentials_detector`, `test_identifiers_detector` | **IMPLEMENTED** |
| **REQ-04** | Clipboard Ctrl+C Interception & Passthrough | Member 2 (Security) | [`security/dlp/clipboard_guard.py`](file:///security/dlp/clipboard_guard.py), [`backend/app/api/v1/clipboard.py`](file:///backend/app/api/v1/clipboard.py) | `test_flow_1_clipboard_dlp_and_token_reuse`, `test_clipboard_guard_passthrough_vs_tokenization` | **IMPLEMENTED** |
| **REQ-05** | Offline Core Security Operation | All Members | [`backend/app/database/session.py`](file:///backend/app/database/session.py), [`security/dlp/engine.py`](file:///security/dlp/engine.py) | `test_offline_vault_encryption_decryption`, `test_ai_risk_engine_offline_graceful` | **IMPLEMENTED** |
| **REQ-06** | Local Password Protection | Member 2 (Security) | [`security/dlp/detectors/credentials.py`](file:///security/dlp/detectors/credentials.py) | `test_credentials_detector` | **IMPLEMENTED** |
| **REQ-07** | 12-Character Non-Reversible Synthetic Tokens | Member 1 (Backend) | [`backend/app/services/token_service.py`](file:///backend/app/services/token_service.py) | `test_token_length_exactly_12`, `test_token_format`, `test_duplicate_sensitive_value_reuses_token` | **IMPLEMENTED** |
| **REQ-08** | Device-Local Encrypted SQLite Vault | Member 1 (Backend) | [`backend/app/database/encrypted_sqlite.py`](file:///backend/app/database/encrypted_sqlite.py), [`backend/app/core/keystore.py`](file:///backend/app/core/keystore.py) | `test_encrypted_database_storage_at_rest`, `test_decrypt_wrong_key_fails` | **IMPLEMENTED** |
| **REQ-09** | Device Uniqueness & Non-Restorable Vault | Member 1 (Backend) | [`backend/app/api/v1/auth.py`](file:///backend/app/api/v1/auth.py), [`backend/app/api/dependencies.py`](file:///backend/app/api/dependencies.py) | `test_device_binding`, `test_device_mismatch_header_rejected` | **IMPLEMENTED** |
| **REQ-10** | Owner Registration with Verified Mobile OTP | Member 1 (Backend) | [`backend/app/services/otp_provider.py`](file:///backend/app/services/otp_provider.py), [`backend/app/api/v1/auth.py`](file:///backend/app/api/v1/auth.py) | `test_owner_registration_sends_otp`, `test_otp_verification_success`, `test_otp_brute_force_lockout` | **IMPLEMENTED** |
| **REQ-11** | Interactive Owner Authorization Gate | Member 1 (Backend) | [`backend/app/services/authorization_service.py`](file:///backend/app/services/authorization_service.py), [`backend/app/services/auth_provider.py`](file:///backend/app/services/auth_provider.py) | `test_authorization_bypass_prevention`, `test_pin_assertion_argon2_and_lockout` | **IMPLEMENTED** |
| **REQ-12** | Authorization Lifetime (Invalidated on Deletion) | Member 1 (Backend) | [`backend/app/services/vault_service.py`](file:///backend/app/services/vault_service.py) | `test_authorization_invalidated_on_deletion`, `test_flow_3_rehydration_authorization_lifecycle` | **IMPLEMENTED** |
| **REQ-13** | Synthetic Representation vs Real Value Release | Member 1 & 4 | [`backend/app/api/v1/vault.py`](file:///backend/app/api/v1/vault.py), [`frontend/js/app.js`](file:///frontend/js/app.js) | `test_unauthorized_vault_retrieval_rejected`, `test_authorized_access_succeeds` | **IMPLEMENTED** |
| **REQ-14** | Extensible Destination Trust Policy | Member 1 (Backend) | [`backend/app/services/destination_trust.py`](file:///backend/app/services/destination_trust.py) | `test_destination_trust_evaluator_policy` | **IMPLEMENTED** |
| **REQ-15** | External AI Synthetic Protection Gate | Member 1 & 3 | [`backend/app/api/v1/rehydration.py`](file:///backend/app/api/v1/rehydration.py), [`ai/anomaly/prompt_analyzer.py`](file:///ai/anomaly/prompt_analyzer.py) | `test_rehydration_denied_keeps_synthetic`, `test_prompt_anomaly_analyzer` | **IMPLEMENTED** |
| **REQ-16** | Manual Privacy-Preserving Exposure Search | Member 2 & 1 | [`backend/app/api/v1/exposure.py`](file:///backend/app/api/v1/exposure.py), [`security/threat_engine/exposure_intelligence.py`](file:///security/threat_engine/exposure_intelligence.py) | `test_exposure_search_and_monitoring_cycle`, `test_flow_4_and_5_exposure_search_and_monitoring` | **IMPLEMENTED** |
| **REQ-17** | Scheduled Automatic Exposure Monitoring | Member 1 (Backend) | [`backend/app/services/monitoring_service.py`](file:///backend/app/services/monitoring_service.py) | `test_exposure_search_and_monitoring_cycle` | **IMPLEMENTED** |
| **REQ-18** | Attribution vs Evidence Distinction | Member 2 (Security) | [`security/threat_engine/exposure_intelligence.py`](file:///security/threat_engine/exposure_intelligence.py), [`backend/app/database/models.py`](file:///backend/app/database/models.py) | `test_flow_4_and_5_exposure_search_and_monitoring` | **IMPLEMENTED** |
| **REQ-19** | AI/ML 0–100 Risk Score Categories | Member 3 (AI/ML) | [`ai/risk_engine/engine.py`](file:///ai/risk_engine/engine.py) | `test_ai_risk_engine_category_semantics` | **IMPLEMENTED** |
| **REQ-20** | Statutory DPDP Act 7-Day Erasure Workflow | Member 1 & 3 | [`backend/app/api/v1/erasure.py`](file:///backend/app/api/v1/erasure.py), [`ai/legal/dpdp_notice.py`](file:///ai/legal/dpdp_notice.py) | `test_7_day_deadline_calculated`, `test_dpdp_notice_generator`, `test_flow_6_erasure_prepare_review_send_lifecycle` | **IMPLEMENTED** |
| **REQ-21** | Formal Case & Evidence Record Entity | Member 1 (Backend) | [`backend/app/api/v1/cases.py`](file:///backend/app/api/v1/cases.py), [`backend/app/database/models.py`](file:///backend/app/database/models.py) | `test_case_creation`, `test_case_and_erasure_cross_owner_isolation` | **IMPLEMENTED** |
| **REQ-22** | Local-First Cryptographic Decoupling Flow | All Members | [`backend/main.py`](file:///backend/main.py), [`security/dlp/clipboard_guard.py`](file:///security/dlp/clipboard_guard.py) | `test_flow_1_clipboard_dlp_and_token_reuse` | **IMPLEMENTED** |
| **REQ-23** | Module Communication via Central Backend | All Members | [`backend/app/api/v1/`](file:///backend/app/api/v1/) | `test_architectural_database_isolation` | **IMPLEMENTED** |
| **REQ-24** | Clear Team Boundaries & Ownership Discipline | All Members | [`backend/`](file:///backend/), [`security/`](file:///security/), [`ai/`](file:///ai/), [`frontend/`](file:///frontend/) | `test_architectural_database_isolation` | **IMPLEMENTED** |
| **REQ-25** | Database Security & Sanitized Audit Logging | Member 1 (Backend) | [`backend/app/core/logging.py`](file:///backend/app/core/logging.py) | `test_audit_logging_without_plaintext_secrets` | **IMPLEMENTED** |
| **REQ-26** | No Assumptions Rule (Strict Spec Adherence) | All Members | Locked Specifications in `docs/` | Codebase Audit | **IMPLEMENTED** |
| **REQ-27** | Safe Git Workflow & Linear Collaboration | All Members | Git commit history | `git status`, `git log` | **IMPLEMENTED** |
| **REQ-28** | Architecture Hierarchy of Priorities | All Members | Spec precedence strictly followed | Architecture reviews | **IMPLEMENTED** |
| **REQ-29** | Unified S.H.A.D.E. Application System | All Members | Unified FastAPI backend + Cyberpunk SPA HUD | End-to-End Suite (88/88 Passed) | **IMPLEMENTED** |

---

## Real-World Integration Status

| Integration | Mechanism / Class | Status | Verified? | External / Environment Requirement |
| :--- | :--- | :--- | :--- | :--- |
| **Windows OS Clipboard Hook** | `WindowsClipboardProvider` via `ctypes` user32/kernel32 sequence listener & atomic replacement | **IMPLEMENTED + VERIFIED** | **YES** | Windows OS (tested live on host). `MemoryClipboardProvider` provided for cross-platform fallback. |
| **Camera Optical Presence** | `CameraVerifier` via OpenCV DirectShow live frame capture, Haar face presence & clean release | **IMPLEMENTED + VERIFIED** | **YES (Tested on laptop camera index 0)** | Zero image persistence; truthfully distinguished from Windows Hello IR depth hardware (`is_windows_hello_hardware: False`). |
| **Platform Biometrics** | `PlatformBiometricProvider` supporting Windows Hello / WebAuthn / FIDO2 & TPM cryptographic assertion verification (Ed25519 & ECDSA P-256) | **IMPLEMENTED + REQUIRES LOCAL HARDWARE** | **YES (Cryptographic contract verified)** | Physical platform authenticator touch / biometric sensor required for human presence assertions; Argon2id PIN fallback is 100% operational. |
| **Statutory SMTP Legal Delivery** | `SMTPDeliveryProvider` supporting configurable STARTTLS / SSL & dev simulation | **IMPLEMENTED + REQUIRES CONFIGURATION** | **YES (Dev simulation & contracts verified)** | Outbound SMTP credentials (`SMTP_HOST`, `SMTP_USER`, `SMTP_PASSWORD`) required for live external dispatch; runs in simulated dev mode by default. |
| **Breach Coverage (Passwords)** | `HIBPPasswordExposureProvider` via NIST/Cloudflare SHA-1 prefix k-anonymity | **IMPLEMENTED + VERIFIED** | **YES** | Outbound HTTPS connectivity (password never leaves machine; offline fallback supported). |
| **Breach Coverage (Email Accounts)** | `HIBPEmailExposureProvider` via HIBP v3 Breached Account API | **IMPLEMENTED + REQUIRES EXTERNAL PROVIDER** | **YES (Capability scoped & gated)** | Requires commercial `HIBP_API_KEY` environment variable. |
| **Breach Coverage (National IDs / Aadhaar / PAN)** | Public Consumer Breach Querying | **NOT SUPPORTED** | **N/A** | **Statutorily and technically unsupported**: No lawful public consumer query API exists for Indian national identity numbers. |

---

## Status Classification
- **IMPLEMENTED + VERIFIED**: Fully implemented, connected, and verified by passing automated unit, negative, and integration tests.
- **IMPLEMENTED + REQUIRES LOCAL HARDWARE**: Cryptographic assertion verification implemented and tested; physical touch on hardware sensor required for live interactive attestation.
- **IMPLEMENTED + REQUIRES CONFIGURATION**: Production provider implemented and tested in simulation; external credentials required for live dispatch.
- **IMPLEMENTED + REQUIRES EXTERNAL PROVIDER**: Provider implemented; requires commercial external API subscription.
- **NOT SUPPORTED**: Category cannot be lawfully or technically queried through public consumer APIs.

