# S.H.A.D.E. — Backend & Core Architecture Module

**Ownership**: Member 1 (`member-1/backend`)  
**Role**: Core Architecture + Backend + Database + Security Integration  
**Status**: HARDENED IMPLEMENTATION & REAL-WORLD VERIFIED (88/88 Tests Passing)  

---

## 1. Overview & Architecture

The **S.H.A.D.E.** backend is the central integration backbone of the application. It enforces privacy boundaries, manages the device-local encrypted vault, and mediates all communication between the frontend, security/DLP engine, AI/ML engine, and OS key storage.

```
       Frontend (Member 4)
              ↕ (REST JSON / localhost:8000/api/v1)
       FastAPI Gateway (Member 1)
        ├── Auth & Device Binding (OTP, hardware attestation)
        ├── Session Enforcement & Owner Isolation
        ├── Clipboard Ingestion (/clipboard/submit)
        ├── Rehydration Flow (/rehydration/submit)
        ├── Owner Authorization Gate (/authorization/challenge, approve, deny)
        ├── Exposure Provider & Monitoring (/exposure/search, /exposure/monitor/run)
        ├── Risk Engine Integration (/risk/submit, /risk/{id})
        ├── Case & Investigation Management (/cases)
        └── Statutory DPDP Erasure Tracking (/erasure)
              ↕
       Vault Service (AES-256-GCM + Token Service + Encrypted SQLite)
              ↕
       Device-Local Encrypted Vault (12 Entities + Encrypted at Rest)
              ↕
       SecureKeyStore (HKDF Key Separation: Vault, DB, Lookup, JWT)
```

---

## 2. Security Hardening & Implementation Details

### 2.1 API Authentication & Strict Owner Isolation
- Every protected endpoint enforces the `get_current_session` dependency.
- All queries, vault lookups, exposures, cases, and erasure requests are strictly scoped to the authenticated owner (`session_ctx.owner.id`).
- Requests from Owner A cannot read, delete, or inspect Owner B's vault, tokens, exposures, or legal requests. Negative isolation tests prove complete isolation.

### 2.2 Device Binding & Attestation
- Sessions are strictly bound to the physical installation device.
- `DeviceAttestationProvider` abstraction separates development local binding (`DevDeviceAttestationProvider`) from hardware platform attestation (`ProductionDeviceAttestationProvider`).

### 2.3 Challenge-Response Owner Authorization
- The backend prohibits trusting client-asserted strings such as `"auth_method": "BIOMETRIC"`.
- Authorization flow requires:
  1. `POST /api/v1/authorization/challenge/{id}`: Issues a single-use, 60-second cryptographic challenge nonce.
  2. Platform verifies owner identity via platform biometrics or Argon2id PIN.
  3. `POST /api/v1/authorization/approve/{id}`: Consumes and verifies the authentication assertion.
  4. Failed assertions, expired challenges, or wrong owners are rejected.
- PIN fallback uses Argon2id password hashing with an automatic 300-second lockout after 3 failed attempts.

### 2.4 Cryptographic Key Separation & Keyed Lookup
- `SecureKeyStore` uses HKDF-SHA256 to derive cryptographically independent keys:
  - **Vault Key**: 32-byte AES-256-GCM key for sensitive values (`shade:vault:v1`).
  - **Database Key**: 32-byte key for local SQLite vault storage (`shade:database:v1`).
  - **Lookup Key**: 32-byte key for HMAC-SHA256 duplicate detection (`shade:lookup_hmac:v1`).
  - **JWT Secret**: Session token signing secret (`shade:jwt_secret:v1`).
- In production, missing OS keystores fail fast and securely without creating silent ephemeral keys.

### 2.5 Complete Database Encryption
- `EncryptedVaultStorage` ensures that the database file at rest is fully encrypted.
- The database file header at rest is never plaintext SQLite (`b"SQLite format 3"` is prohibited).
- Opening the database with an incorrect key fails fast with `VaultLockedError`.
- Defense-in-depth: individual sensitive values remain encrypted with their own AES-256-GCM vault key.

### 2.6 Hardened OTP & Mobile Identity
- OTP has a 300-second TTL expiry and a 30-second cooldown between resends.
- Maximum 3 verification attempts before an automatic 300-second account lockout.
- OTP codes are hashed in memory — never persisted or logged in production.
- Verified OTP issues a single-use verification ticket, ensuring `owner.mobile_hash` is directly derived from the verified mobile number.

### 2.7 Exposure Provider & Monitoring Infrastructure
- `ExposureProvider` interface supports normalized manual search and monitoring passes.
- `MonitoringService` runs background exposure checks for vaulted values and gracefully handles offline states without impacting vault operations.

### 2.8 Destination Trust Evaluator
- `DestinationTrustEvaluator` classifies destinations into `TRUSTED`, `NOT_TRUSTED`, and `UNKNOWN`.
- Unknown destinations are never automatically trusted.

### 2.9 Real-World Integrations & Hardware Truthfulness
- **Camera Presence Verification**: `CameraVerifier` detects optical webcam hardware (verified on device index 0 at 640x480), checks Haar cascades, and performs ephemeral optical presence verification with **zero biometric image persistence** on disk or database. Explicitly and truthfully distinguishes optical webcam from Windows Hello IR depth hardware (`is_windows_hello_hardware: False`).
- **Platform Biometric Boundary**: Verifies cryptographic signatures (Ed25519 & ECDSA P-256) over single-use challenge nonces with anti-replay guarantees, client-forgery rejection, and Argon2id PIN fallback.
- **Statutory SMTP Legal Delivery**: `SMTPDeliveryProvider` provides configurable, TLS-secured dispatch with dev-simulation fallback and strict idempotency to prevent duplicate notice dispatch.
- **Accurately Scoped Breach Providers**: HIBP k-anonymity SHA-1 prefixing for passwords, optional HIBP v3 account API with authenticated key, local canary attribution, and truthful unsupported declaration for Aadhaar, PAN, and License Plates.

---

## 3. Running & Testing

### Running Tests
```bash
python -m pytest -v --durations=10
```
All 88 test cases pass with full multi-module integration, real-world hardware verification, security attack resistance, and owner isolation verification.

### Running Backend Server
```bash
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000 --reload
```
