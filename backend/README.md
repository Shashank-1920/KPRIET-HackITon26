# S.H.A.D.E. — Backend & Core Architecture Module

**Ownership**: Member 1 (`member-1/backend`)  
**Role**: Core Architecture + Backend + Database + Integration  
**Status**: COMPLETE IMPLEMENTATION  

---

## 1. Overview & Architecture

The **S.H.A.D.E.** backend is the central integration backbone of the application. It enforces privacy boundaries, manages the local encrypted vault, and mediates all communication between the frontend, security/DLP engine, AI/ML engine, and OS key storage.

```
       Frontend (Member 4)
              ↕ (REST JSON / localhost:8000/api/v1)
       FastAPI Gateway (Member 1)
        ├── Auth & Device Binding (OTP, hardware fingerprint)
        ├── Clipboard Ingestion (/clipboard/submit)
        ├── Rehydration Flow (/rehydration/submit)
        ├── Authorization Gate (/authorization/request, approve, deny)
        ├── Exposure Persistence (/exposure/submit, /exposure/search)
        ├── Risk Persistence (/risk/submit, /risk/{id})
        ├── Case & Investigation Management (/cases)
        └── Statutory DPDP Erasure Tracking (/erasure)
              ↕
       Vault Service (AES-256-GCM + Token Service)
              ↕
       Device-Local Encrypted SQLite Vault (12 Entities)
              ↕
       SecureKeyStore (OS Keyring: DPAPI / Keychain / Secret Service)
```

---

## 2. Implemented Database Schema (12 Core Entities)

The local SQLite vault is encrypted and authoritative. Plaintext sensitive values are **never** stored directly. All 12 entities required by [PRODUCT_REQUIREMENTS.md](file:///c:/Users/HP/Desktop/New%20folder%20(2)/KPRIET-HackITon26/docs/PRODUCT_REQUIREMENTS.md) are fully implemented in [`models.py`](file:///c:/Users/HP/Desktop/New%20folder%20(2)/KPRIET-HackITon26/backend/app/database/models.py):

| Entity | Table Name | Purpose | Security Invariant |
|:---|:---|:---|:---|
| **1. Device** | `devices` | Bound physical device | One installation per device; hardware fingerprint hash. |
| **2. Owner** | `owners` | Registered owner | Mobile number stored only as SHA-256 `mobile_hash`. |
| **3. SensitiveValue** | `sensitive_values` | Encrypted sensitive data | Encrypted with AES-256-GCM (nonce + ciphertext + tag); indexed by one-way `lookup_hash`. |
| **4. SyntheticToken** | `synthetic_tokens` | Exactly 12-char placeholders | `SHD_XXXXXXXX` generated via CSPRNG (`secrets.token_hex`). Reused on duplicate input. |
| **5. Authorization** | `authorizations` | Access permissions | Explicit owner gate (`PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `REVOKED`). |
| **6. Session** | `sessions` | JWT-backed owner session | Device-bound sessions; supports validation and immediate revocation. |
| **7. Exposure** | `exposures` | Breach/leak records | Stores discovery source, organization, and evidence without raw PII. |
| **8. RiskResult** | `risk_results` | Exposome threat scoring | Consumes Member 3 risk scores (0–100) and classifications (`NONE`, `LOW`, `MEDIUM`, `CRITICAL`). |
| **9. Case** | `cases` | Investigation cases | Strictly separates confirmed `evidence` from `unsupported_notes`. |
| **10. ErasureRequest** | `erasure_requests` | DPDP Sec 12 takedowns | Enforces and tracks statutory 7-day deadlines. |
| **11. FollowUpRequest**| `follow_up_requests`| Post-deadline actions | Dispatched when organizations do not reply within 7 days. |
| **12. AuditEvent** | `audit_events` | Immutable security log | Strictly sanitized — prohibited from containing plaintext credentials or secrets. |
| **RehydrationRequest** | `rehydration_requests`| Token rehydration flow | Tracks active token resolution requests through owner authorization. |

---

## 3. Cryptography & Key Management

- **Vault Encryption**: AES-256-GCM authenticated encryption (`AESGCM` via Python `cryptography`).
  - Unique 12-byte random nonce per encryption call.
  - 16-byte authentication tag appended.
  - 32-byte key managed exclusively by `SecureKeyStore`.
- **Zero Plaintext Invariant**: Plaintext is decrypted only in-memory upon authorized request, returned directly, and never persisted or logged.
- **SecureKeyStore**:
  - Windows: DPAPI / Windows Credential Manager (via `keyring`)
  - macOS: Apple Keychain Services
  - Linux: Secret Service API / libsecret
  - Dev/CI Fallback: Ephemeral in-memory key or `SHADE_MASTER_ENCRYPTION_KEY` environment secret.

---

## 4. API Endpoints Reference (`/api/v1`)

### Authentication & Device Binding (`/auth`)
- `POST /api/v1/auth/register` — Submit mobile number, receive OTP.
- `POST /api/v1/auth/verify-otp` — Verify OTP (supports pluggable providers and `000000` dev mock).
- `POST /api/v1/auth/bind-device` — Bind vault to device hardware fingerprint.
- `GET /api/v1/auth/status` — Current registration and binding status.

### Device & Session (`/device`, `/session`)
- `GET /api/v1/device/status` — Device binding and vault lock/unlock status.
- `POST /api/v1/session/create` — Create JWT owner session.
- `POST /api/v1/session/validate` — Validate session token and device affinity.
- `POST /api/v1/session/revoke/{id}` — Revoke session.

### Vault Service (`/vault`)
- `POST /api/v1/vault/store` — Encrypt and store sensitive value (returns 12-char synthetic token).
- `GET /api/v1/vault/token/{token}` — Lookup token metadata without plaintext.
- `POST /api/v1/vault/retrieve` — Decrypt and retrieve value (requires `APPROVED` authorization ID).
- `DELETE /api/v1/vault/{id}` — Delete value (cascades to revoke all associated authorizations).
- `GET /api/v1/vault/` — List stored tokens and metadata (never returns plaintext).

### Clipboard & DLP Interception (`/clipboard`)
- `POST /api/v1/clipboard/submit` — Member 2 submits copied content; returns `PASSTHROUGH` if clean, or synthetic token if sensitive (`TOKENIZED` or `REUSED`).

### Owner Authorization Gate (`/authorization`)
- `POST /api/v1/authorization/request` — Request access for a synthetic token (`PENDING`).
- `POST /api/v1/authorization/approve/{id}` — Owner approves access (`BIOMETRIC` or `PIN`).
- `POST /api/v1/authorization/deny/{id}` — Owner denies access (`DENIED`).
- `GET /api/v1/authorization/{id}` — Check authorization state.

### Rehydration Flow (`/rehydration`)
- `POST /api/v1/rehydration/submit` — Detect tokens in text and trigger authorization.
- `POST /api/v1/rehydration/result/{id}` — Release real value if authorized; keep synthetic if denied.

### Exposure & Threat Persistence (`/exposure`)
- `POST /api/v1/exposure/submit` — Member 2 submits discovered breach record.
- `POST /api/v1/exposure/search` — Member 2 dispatches search query (hashed identifier).
- `GET /api/v1/exposure/` — List exposure records.
- `GET /api/v1/exposure/{id}` — Get single exposure.

### Risk Engine Integration (`/risk`)
- `POST /api/v1/risk/submit` — Member 3 submits computed risk score and classification.
- `GET /api/v1/risk/{exposure_id}` — Query latest risk analysis for an exposure.

### Cases & DPDP Erasure (`/cases`, `/erasure`)
- `POST /api/v1/cases/` — Create investigation case (separating confirmed evidence from unconfirmed notes).
- `GET /api/v1/cases/{id}` — Get case status and details.
- `POST /api/v1/erasure/` — Draft DPDP Section 12 erasure request.
- `POST /api/v1/erasure/{id}/send` — Mark sent and compute strict 7-day statutory deadline.
- `GET /api/v1/erasure/{id}/deadline` — Check days remaining and overdue state.
- `POST /api/v1/erasure/{id}/response` — Record organization response with verified evidence.
- `POST /api/v1/erasure/{id}/followup` — Create follow-up request for unresponsive entities.

---

## 5. Local Development & Testing

### Installation
```bash
# From workspace root
pip install -r backend/requirements.txt
```

### Running the Backend Locally
```bash
# Starts ASGI dev server on 127.0.0.1:8000
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
API Documentation (when `DEBUG=true`): `http://127.0.0.1:8000/api/v1/docs`

### Executing Tests
```bash
# Run backend test suite
python -m pytest tests/backend/ -v
```

---

## 6. Integration Contract Reference

For detailed integration guides and payload contracts for Member 2, Member 3, and Member 4, refer to:  
👉 **[docs/INTEGRATION_CONTRACTS.md](file:///c:/Users/HP/Desktop/New%20folder%20(2)/KPRIET-HackITon26/docs/INTEGRATION_CONTRACTS.md)**
