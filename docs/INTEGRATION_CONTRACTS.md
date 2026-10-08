# S.H.A.D.E. — Inter-Module Integration Contracts & API Specifications

**Document Version**: 2.0.0  
**Target Audience**: Member 2 (Security/DLP), Member 3 (AI/ML), Member 4 (Frontend/UX)  
**Author**: Member 1 (Core Architecture + Backend + Database + Integration)  
**Status**: APPROVED INTEGRATION SPECIFICATION  

---

## 1. Overview & Architectural Role of Backend

In accordance with [PRODUCT_REQUIREMENTS.md](PRODUCT_REQUIREMENTS.md) §23, **all major modules communicate through the backend/integration layer**.

```
    Frontend (Member 4)
           ↕ (HTTP JSON / WebSocket /api/v1)
    Backend Gateway (Member 1)
           ↕               ↕
   Security / DLP (M2)   AI / ML (M3)
           ↕
   Local Encrypted Vault (SQLite + AES-256-GCM / SQLCipher)
```

### Core Security & Privacy Invariants
1. **Local-First & Device-Authoritative**: Real sensitive data and synthetic token mappings reside exclusively on the owner's device inside the encrypted SQLite vault.
2. **Server-Side Enforcement**: `REQUEST ≠ AUTHORIZATION`. The backend never trusts a client-supplied flag such as `"auth_method": "BIOMETRIC"`. All approvals require cryptographically verified assertions.
3. **Owner & Device Isolation**: Every protected route enforces session and device attestation. No endpoint allows cross-owner access.
4. **Privacy Invariant**: Real sensitive values are never logged or exposed in standard API responses. All responses return synthetic tokens (`SHD_XXXXXXXX`), identifiers, or sanitized metadata.

---

## 2. Implementation Status Summary

| Contract | Implementation Status | Provider State | Description |
|:---|:---|:---|:---|
| **API Session Auth** | `IMPLEMENTED` | `PRODUCTION REQUIRED` | JWT with `jti`, device binding, fail-fast production config |
| **Device Attestation** | `IMPLEMENTED` | `DEV ONLY` (Dev Provider) / `PRODUCTION REQUIRED` (Platform TPM) | Verifies bound device hardware |
| **Owner Authorization** | `IMPLEMENTED` | `DEV ONLY` (Dev Mock) / `PRODUCTION REQUIRED` (Platform Hello/WebAuthn) | Challenge-response assertion gate + Argon2id PIN |
| **Keyed Lookup Hashing** | `IMPLEMENTED` | `PRODUCTION REQUIRED` | Keyed HMAC-SHA256 with separated key |
| **Full DB Encryption** | `IMPLEMENTED` | `PRODUCTION REQUIRED` | Encrypted at-rest vault file & SQLCipher PRAGMA hooks |
| **OTP Verification** | `IMPLEMENTED` | `DEV ONLY` (Mock) / `PRODUCTION REQUIRED` (Twilio/SMS) | 300s TTL, 3-attempt limit, brute-force lockout, verified ticket |
| **Clipboard / DLP** | `IMPLEMENTED` | `IMPLEMENTED` (Member 2 DLP Engine) | Sensitive content tokenization & passthrough |
| **Exposure Search** | `IMPLEMENTED` | `IMPLEMENTED` (Member 2 Threat Intel) | Normalized breach result persistence & k-anonymity |
| **Automatic Monitoring** | `IMPLEMENTED` | `IMPLEMENTED` (Scheduler + M2 Provider) | Background pass with offline resilience |
| **Destination Trust** | `IMPLEMENTED` | `PRODUCTION REQUIRED` (Configurable Policy) | Evaluates destination URL: `TRUSTED`, `NOT_TRUSTED`, `UNKNOWN` |
| **Statutory Erasure** | `IMPLEMENTED` | `IMPLEMENTED` (Member 3 DPDP Notice) | 7-day statutory deadline, user-review-before-send |
| **Risk Engine** | `IMPLEMENTED` | `IMPLEMENTED` (Member 3 AI Risk Engine) | Risk score (0-100) and category ingestion |
| **Frontend HUD** | `IMPLEMENTED` | `IMPLEMENTED` (Member 4 SPA Interface) | Cyberpunk dark HUD, sandbox, vault & erasure UI |

---

## 3. Authentication & Device Identity Contracts

### Contract 3.1: Session Authentication Contract
- **Headers Accepted**:
  - `Authorization: Bearer <jwt_access_token>`
  - `X-Session-Token: <jwt_access_token>`
  - `X-Device-Id: <device_id>` *(Optional device verification header)*
- **Validation**:
  - Validates JWT signature with `SHADE_JWT_SECRET` (obtained from SecureKeyStore).
  - Validates session is not revoked in the local vault database.
  - Validates session expiry (15-minute access token budget).
  - Validates session device matches the physical device binding.

### Contract 3.2: Device Attestation Contract
- **Interface**: `DeviceAttestationProvider`
- **Method**: `verify_device_binding(device, client_device_id, attestation_payload)`
- **Providers**:
  - `DevDeviceAttestationProvider`: `[DEVELOPMENT ONLY]` Verifies matching device ID on localhost.
  - `ProductionDeviceAttestationProvider`: `[PRODUCTION REQUIRED]` Verifies hardware platform assertion (TPM 2.0 / Windows Hello / Apple Secure Enclave).

---

## 4. Owner Authorization & Challenge-Response Contract

### Contract 4.1: Create Authentication Challenge
- **Endpoint**: `POST /api/v1/authorization/challenge/{authorization_id}`
- **Authentication**: Bearer Session Token
- **Response**:
```json
{
  "challenge_id": "3f9821a0-523e-4b2b-9801-abcdef012345",
  "owner_id": "45851a45-4502-4960-b2f8-1cf2f5223428",
  "action": "AUTHORIZE_SENSITIVE_VALUE",
  "resource_id": "a1002003-4455-6677-8899-aabbccddeeff",
  "nonce": "7d9b23f0a1c2e4b5d6e7f80912345678",
  "expires_at": "2026-10-08T22:30:00Z"
}
```

### Contract 4.2: Owner Approval via Verified Assertion
- **Endpoint**: `POST /api/v1/authorization/approve/{authorization_id}`
- **Authentication**: Bearer Session Token
- **Request (Biometric Assertion)**:
```json
{
  "authorization_id": "a1002003-4455-6677-8899-aabbccddeeff",
  "auth_method": "BIOMETRIC",
  "challenge_id": "3f9821a0-523e-4b2b-9801-abcdef012345",
  "assertion": {
    "challenge_id": "3f9821a0-523e-4b2b-9801-abcdef012345",
    "signature": "base64_platform_signature_over_nonce==",
    "verified": true
  }
}
```
- **Request (Device PIN Fallback)**:
```json
{
  "authorization_id": "a1002003-4455-6677-8899-aabbccddeeff",
  "auth_method": "PIN",
  "assertion": "OwnerPIN1234"
}
```
*Security Invariants*:
- The backend verifies PINs using Argon2id with an automatic 300-second lockout after 3 failed attempts.
- Raw biometric data and plaintext PINs are never stored or logged.

---

## 5. Integration Contract: Member 2 (Security + DLP + Threat Engine)

### Contract 5.1: Clipboard DLP Interception
- **Endpoint**: `POST /api/v1/clipboard/submit`
- **Authentication**: Bearer Session Token
- **Request**:
```json
{
  "content": "sample_api_key_998877665544332211aabbcc",
  "detected_type": "API_KEY",
  "detection_confidence": 0.98,
  "detection_metadata": {
    "detector": "regex_api_key",
    "entropy": 4.2
  }
}
```
- **Backend Behavior**:
  - If `detected_type` is `null`: Returns `{"action": "PASSTHROUGH", "is_sensitive": false}`.
  - If sensitive: Computes keyed HMAC-SHA256 lookup hash, encrypts with AES-256-GCM, returns synthetic token `SHD_XXXXXXXX`.

### Contract 5.2: Exposure Provider Interface (`ExposureProvider`)
- **Interface**: `ExposureProvider` (`[PRODUCTION REQUIRED]`)
- **Methods**:
  - `search(search_type: str, query_hash: str) -> List[NormalizedExposure]`
  - `is_available() -> bool`
- **Manual Search Endpoint**: `POST /api/v1/exposure/search`
- **Request**:
```json
{
  "search_type": "EMAIL",
  "search_value_hash": "keyed_hmac_hash_of_query_value"
}
```

---

## 6. Integration Contract: Member 3 (AI/ML + Risk Engine)

### Contract 6.1: Risk Scoring Ingestion & Provider Interface
- **Interface**: `RiskEngineProvider` (`[PRODUCTION REQUIRED]`)
- **Endpoint**: `POST /api/v1/risk/submit`
- **Request**:
```json
{
  "exposure_id": "8f3b2a1c-9901-44bb-9a11-ef892304859a",
  "risk_score": 85.5,
  "risk_level": "CRITICAL",
  "analysis_metadata": {
    "z_score": 2.45,
    "model_version": "v1.2-heuristics"
  }
}
```
*Categories*:
- `0`: No exposure
- `LOW`: Low-risk website
- `MEDIUM`: Private organization
- `CRITICAL`: Public / government organization

---

## 7. Destination Trust & Rehydration Contract

### Contract 7.1: Destination Trust Evaluator (`DestinationTrustEvaluator`)
- **Interface**: `DestinationTrustEvaluator`
- **Output States**: `TRUSTED`, `NOT_TRUSTED`, `UNKNOWN`
- **Invariant**: Unknown destinations are never automatically trusted.

### Contract 7.2: Rehydration Authorization & Release
- **Scan & Request**: `POST /api/v1/rehydration/submit`
  ```json
  {
    "content": "Using token: SHD_4A7F9B12",
    "requesting_component": "External AI / Browser",
    "destination_url": "https://gov-portal.internal/form",
    "is_external_ai": false
  }
  ```
- **Result Release**: `POST /api/v1/rehydration/result/{request_id}?authorization_id={auth_id}`
  - Returns `real_value` strictly when authorization is `APPROVED` and owner matches.

---

## 8. Statutory Erasure & 7-Day Deadline Workflow

1. **Create Draft**: `POST /api/v1/erasure/` (`status="DRAFT"`)
2. **User Explicitly Sends**: `POST /api/v1/erasure/{id}/send` (Starts 7-day statutory deadline, dispatches via configured SMTP or dev simulation)
3. **Deadline Status**: `GET /api/v1/erasure/{id}/deadline`
4. **Follow-Up Dispatch**: `POST /api/v1/erasure/{id}/followup` (Allowed after deadline passes without response)
5. **Record Evidence Response**: `POST /api/v1/erasure/{id}/response`

---

## 9. Real-World Camera & Optical Presence Contract

### Contract 9.1: Camera Hardware & Ephemeral Presence (`/api/v1/auth/camera`)
- **Status Endpoint**: `GET /api/v1/auth/camera/status`
  - Returns: `{ "camera_available": bool, "device_index": int, "resolution": [w, h], "is_windows_hello_hardware": false }`
  - Invariant: Optical webcam is truthfully distinguished from Windows Hello IR depth hardware.
- **Verification Endpoint**: `POST /api/v1/auth/camera/verify-presence`
  - Returns: `{ "verified": bool, "faces_detected": int, "processing_time_ms": float, "is_windows_hello_hardware": false }`
  - **Zero Disk Storage Invariant**: Biometric image frames are never saved to disk or database. Frames are processed ephemerally in RAM and released immediately via `cap.release()`.

---

## 10. Platform Biometric & Cryptographic Attestation Contract

### Contract 10.1: Cryptographic Assertion Gate (`/api/v1/authorization`)
- **Challenge Issuance**: `POST /api/v1/authorization/challenge/{id}`
  - Issues 60s single-use cryptographic challenge nonce.
- **Cryptographic Approval**: `POST /api/v1/authorization/approve/{id}`
  - Accepts `assertion`:
    - Ed25519 or ECDSA P-256 digital signature over `challenge_nonce`.
    - Includes `public_key` and `signature` (base64-encoded).
  - Anti-replay enforcement: Nonce cannot be reused.
  - Fallback: Argon2id owner PIN fallback with lockout protection.

---

## 11. External Breach Disclosure Contract

### Contract 11.1: Breach Provider Capabilities (`/api/v1/exposure/capabilities`)
- Returns truthfully scoped provider capabilities:
  - `PASSWORD`: k-anonymity SHA-1 prefixing (Cloudflare / NIST compliant).
  - `EMAIL`: HIBP v3 account API (requires configured API key).
  - `CANARY`: Local honeypot attribution provider.
  - `AADHAAR`, `PAN`, `DRIVING_LICENSE`, `CREDIT_CARD`: Explicitly reported as `UNSUPPORTED` (no lawful public breach lookup API exists).
