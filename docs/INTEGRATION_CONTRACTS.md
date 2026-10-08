# S.H.A.D.E. — Inter-Module Integration Contracts & API Specifications

**Document Version**: 1.0.0  
**Target Audience**: Member 2 (Security/DLP), Member 3 (AI/ML), Member 4 (Frontend/UX)  
**Author**: Member 1 (Core Architecture + Backend + Database + Integration)  
**Status**: APPROVED INTEGRATION SPECIFICATION  

---

## 1. Overview & Architectural Role of Backend

In accordance with [PRODUCT_REQUIREMENTS.md](file:///c:/Users/HP/Desktop/New%20folder%20(2)/KPRIET-HackITon26/docs/PRODUCT_REQUIREMENTS.md) §23, **all major modules communicate through the backend/integration layer**.

```
    Frontend (Member 4)
           ↕ (HTTP JSON / WebSocket /api/v1)
    Backend Gateway (Member 1)
           ↕               ↕
   Security / DLP (M2)   AI / ML (M3)
           ↕
   Local Encrypted Vault (SQLite + AES-256-GCM / SQLCipher)
```

- **Local-First & Device-Authoritative**: Real sensitive data and synthetic token mappings reside exclusively on the owner's device inside the encrypted SQLite vault.
- **Server-Side Enforcement**: `REQUEST ≠ AUTHORIZATION`. The backend never trusts a frontend-only authorization flag.
- **Privacy Invariant**: Real sensitive values are never logged or exposed in standard API responses. All responses return synthetic tokens (`SHD_XXXXXXXX`), identifiers, or sanitized metadata.

---

## 2. Integration Contract: Member 2 (Security + Threat Engine + DLP)

### Module Ownership Boundaries
- **Member 2 Owns**: Deterministic regex DLP detection, Verhoeff checksum algorithm, HIBP k-anonymity client, canary token emission logic, threat correlation.
- **Member 1 (Backend) Owns**: Ingestion endpoint, AES-256-GCM vault persistence, 12-character synthetic token issuance/reuse, exposure record persistence.

---

### Contract 2.1: Clipboard DLP Interception

Triggered upon user `CTRL+C`. After Member 2 inspects the clipboard content:

- **Endpoint**: `POST /api/v1/clipboard/submit`
- **Authentication**: Local process / Host origin (`127.0.0.1`)

#### Request Schema
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
*Note*: If Member 2 determines the content is clean/non-sensitive, pass `"detected_type": null`.

#### Backend Actions
1. If `detected_type` is `null`: Returns `action: "PASSTHROUGH"`, `is_sensitive: false`. Clipboard remains unchanged.
2. If `detected_type` is sensitive:
   - Computes SHA-256 `lookup_hash`.
   - If already present in vault: Reuses existing 12-char token (`action: "REUSED"`).
   - If new: Encrypts with AES-256-GCM, stores in vault, generates exactly 12-char token `SHD_XXXXXXXX` (`action: "TOKENIZED"`).

#### Success Response (Sensitive Detected)
```json
{
  "is_sensitive": true,
  "synthetic_token": "SHD_4A7F9B12",
  "data_type": "API_KEY",
  "action": "TOKENIZED"
}
```

#### Success Response (Normal Content — Passthrough)
```json
{
  "is_sensitive": false,
  "synthetic_token": null,
  "data_type": null,
  "action": "PASSTHROUGH"
}
```

---

### Contract 2.2: Exposure & Breach Record Ingestion

When Member 2's threat engine discovers a breach/leak (via HIBP k-anonymity, dark-web monitoring, etc.):

- **Endpoint**: `POST /api/v1/exposure/submit`

#### Request Schema
```json
{
  "sensitive_value_id": null,
  "data_type": "EMAIL",
  "organization": "Example Cloud Corp",
  "source_url": "https://breach-database.example.org",
  "evidence_summary": "Discovered in credential dump comprising 1.2M records.",
  "discovery_mode": "AUTOMATIC"
}
```

#### Success Response
```json
{
  "exposure_id": "8f3b2a1c-9901-44bb-9a11-ef892304859a",
  "status": "stored"
}
```

---

### Contract 2.3: Manual Exposure Search Dispatch

- **Endpoint**: `POST /api/v1/exposure/search`

#### Request Schema
```json
{
  "search_type": "EMAIL",
  "search_value_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}
```
*Rule*: Raw search values must never be sent in plaintext; pass only SHA-256 hashes or SHA-1 k-anonymity prefixes.

---

## 3. Integration Contract: Member 3 (AI/ML + Anomaly + Risk Engine)

### Module Ownership Boundaries
- **Member 3 Owns**: 0–100 Exposome Threat Index calculation, Z-score outlier analysis, PII density heuristics, DPDP Section 12 legal notice markdown generation.
- **Member 1 (Backend) Owns**: Ingestion and persistent storage of risk scores, case linkage, statutory deadline tracking.

---

### Contract 3.1: Submit Risk Analysis Result

- **Endpoint**: `POST /api/v1/risk/submit`

#### Request Schema
```json
{
  "exposure_id": "8f3b2a1c-9901-44bb-9a11-ef892304859a",
  "risk_score": 85.5,
  "risk_level": "CRITICAL",
  "analysis_metadata": {
    "heuristic_weights": {
      "pii_density": 0.8,
      "public_entity_multiplier": 1.5
    },
    "z_score": 2.45,
    "model_version": "v1.2-heuristics"
  }
}
```

#### Risk Level Constraints (PRODUCT_REQUIREMENTS.md §19)
- `NONE` (`0` score): No exposure detected.
- `LOW`: Low-risk website exposure.
- `MEDIUM`: Private organization exposure.
- `CRITICAL`: Public / government organization exposure.

#### Success Response
```json
{
  "risk_result_id": "c71e8a90-3342-41df-a567-91a0c8b671e2",
  "status": "stored"
}
```

---

### Contract 3.2: Query Latest Risk for Exposure

- **Endpoint**: `GET /api/v1/risk/{exposure_id}`

#### Response Schema
```json
{
  "id": "c71e8a90-3342-41df-a567-91a0c8b671e2",
  "exposure_id": "8f3b2a1c-9901-44bb-9a11-ef892304859a",
  "risk_score": 85.5,
  "risk_level": "CRITICAL",
  "scored_at": "2026-10-08T21:30:00Z",
  "scored_by": "member3-risk-engine"
}
```

---

## 4. Integration Contract: Member 4 (Frontend + UI/UX + War-Room HUD)

### Module Ownership Boundaries
- **Member 4 Owns**: Cyber War-Room HUD, Threat Gauge visualizations, Interactive Sandbox, Owner Approval Dialog, Takedown Generator view.
- **Member 1 (Backend) Owns**: Session authentication, device binding verification, authorization gate processing, rehydration release.

---

### Contract 4.1: Owner Registration & Device Binding Flow

1. **Step 1 — Register Mobile**: `POST /api/v1/auth/register`
   ```json
   { "mobile_number": "9876543210" }
   ```
   *Response*: `{"message": "OTP sent successfully.", "next_step": "POST /auth/verify-otp"}`

2. **Step 2 — Verify OTP**: `POST /api/v1/auth/verify-otp`
   ```json
   { "mobile_number": "9876543210", "otp_code": "000000" }
   ```
   *Response*: `{"message": "OTP verified successfully.", "mobile_verified": true}`

3. **Step 3 — Bind Device**: `POST /api/v1/auth/bind-device`
   ```json
   {
     "device_fingerprint_hash": "a1b2c3d4e5f60718293a4b5c6d7e8f90...",
     "platform": "windows",
     "pin_hash": null
   }
   ```
   *Response*: `{"owner_id": "...", "device_id": "...", "message": "Device bound successfully."}`

---

### Contract 4.2: Owner Permission Gate (Authorization)

When an application or rehydration flow requests release of a real sensitive value:

1. **Initiate Authorization**: `POST /api/v1/authorization/request`
   ```json
   {
     "synthetic_token": "SHD_4A7F9B12",
     "requesting_component": "Frontend HUD Sandbox",
     "purpose_scope": "Testing Aadhaar paste to official portal"
   }
   ```
   *Response*:
   ```json
   {
     "authorization_id": "a1002003-4455-6677-8899-aabbccddeeff",
     "state": "PENDING",
     "requesting_component": "Frontend HUD Sandbox",
     "purpose_scope": "Testing Aadhaar paste to official portal",
     "requested_at": "2026-10-08T21:32:00Z"
   }
   ```

2. **Owner Approves via Biometric / PIN Modal**: `POST /api/v1/authorization/approve/{authorization_id}`
   ```json
   {
     "authorization_id": "a1002003-4455-6677-8899-aabbccddeeff",
     "auth_method": "BIOMETRIC"
   }
   ```
   *Response*: `{"authorization_id": "...", "state": "APPROVED", "auth_method": "BIOMETRIC"}`

3. **Owner Denies**: `POST /api/v1/authorization/deny/{authorization_id}`
   *Response*: `{"authorization_id": "...", "state": "DENIED"}`

---

### Contract 4.3: Local Rehydration Flow

- **Detect & Request Rehydration**: `POST /api/v1/rehydration/submit`
  ```json
  {
    "content": "Pasting Aadhaar token: SHD_4A7F9B12 into destination form",
    "requesting_component": "Browser Extension Hook",
    "purpose_scope": "Form autofill"
  }
  ```
  *Response*:
  ```json
  {
    "tokens_detected": ["SHD_4A7F9B12"],
    "rehydration_request_ids": ["rehyd-1122-3344"],
    "all_authorized": false,
    "message": "1 token(s) detected. Authorization required from owner."
  }
  ```

- **Retrieve Result Once Approved**: `POST /api/v1/rehydration/result/{rehydration_request_id}?authorization_id={authorization_id}`
  *Response (if APPROVED)*:
  ```json
  {
    "rehydration_request_id": "rehyd-1122-3344",
    "synthetic_token": "SHD_4A7F9B12",
    "state": "APPROVED",
    "real_value": "266853339452"
  }
  ```
  *Response (if DENIED or PENDING)*:
  ```json
  {
    "rehydration_request_id": "rehyd-1122-3344",
    "synthetic_token": "SHD_4A7F9B12",
    "state": "DENIED",
    "real_value": null
  }
  ```

---

### Contract 4.4: Statutory Erasure & 7-Day Deadline Workflow

1. **Create Erasure Draft**: `POST /api/v1/erasure/`
   ```json
   {
     "case_id": "case-9988-7766",
     "dpo_email": "dpo@examplecorp.com",
     "legal_basis": "DPDP Act 2023, Section 12(1)",
     "request_body": "Notice is hereby served under Section 12 of the Digital Personal Data Protection Act 2023..."
   }
   ```
   *Response*: `{"id": "...", "status": "DRAFT"}`

2. **Send Erasure Request**: `POST /api/v1/erasure/{id}/send`
   *Response*:
   ```json
   {
     "id": "erasure-123",
     "status": "SENT",
     "request_date": "2026-10-08T21:35:00Z",
     "deadline_date": "2026-10-15T21:35:00Z",
     "message": "Erasure request marked as sent. 7-day statutory deadline: 2026-10-15"
   }
   ```

3. **Check Deadline**: `GET /api/v1/erasure/{id}/deadline`
   *Response*:
   ```json
   {
     "id": "erasure-123",
     "status": "SENT",
     "deadline_date": "2026-10-15T21:35:00Z",
     "is_overdue": false,
     "days_remaining": 7,
     "message": "Within deadline."
   }
   ```

4. **Record Organization Response**: `POST /api/v1/erasure/{id}/response`
   ```json
   {
     "organization_response": "We have deleted the user record from our primary database.",
     "new_status": "RESOLVED"
   }
   ```
   *Rule*: The backend never marks data deleted without documented evidence in `organization_response`.

---

## 5. Standard Error Envelopes (RFC 7807)

All non-2xx responses return consistent, machine-readable JSON:

```json
{
  "error": "AUTHORIZATION_REQUIRED",
  "message": "An APPROVED authorization is required to access this sensitive value.",
  "detail": null
}
```

### Standard Error Codes
| HTTP Status | Error Code | Description |
|:---|:---|:---|
| 400 | `INVALID_REQUEST` | Malformed parameters, duplicate registration, or invalid token structure. |
| 400 | `INVALID_TOKEN` | Token does not conform to `SHD_[0-9A-F]{8}` specification. |
| 401 | `UNAUTHORIZED` | Expired or missing session token / incorrect OTP. |
| 403 | `DEVICE_NOT_BOUND` | Device is not registered or bound to the active vault. |
| 403 | `AUTHORIZATION_REQUIRED` | Attempted access without an `APPROVED` owner authorization. |
| 403 | `AUTHORIZATION_EXPIRED` | The 60-second owner authorization prompt has timed out. |
| 404 | `NOT_FOUND` | Record, case, or token not located. |
| 404 | `SENSITIVE_DATA_NOT_FOUND`| Value does not exist or has been deleted. |
| 503 | `EXTERNAL_SERVICE_UNAVAILABLE` | Pluggable external provider (e.g., OTP gateway) is unavailable. |
