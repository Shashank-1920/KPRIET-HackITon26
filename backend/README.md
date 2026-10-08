# S.H.A.D.E. — Backend & Core Architecture Module
**Ownership**: Member 1 (`member-1/backend`)  
**Role**: "Core Architecture + Backend + Database + Integration"

---

## Scope of Responsibility
- FastAPI ASGI application factory and lifecycle management (`main.py`)
- Central routing and versioned API registration (`api/routes/`)
- Ingress authentication guards (Argon2id password verification, JWT issuance, token rotation)
- **Local Encrypted Data Vault**: Device-local SQLite database with SQLCipher encryption protection (`database/`)
- **Cryptographic Key Storage**: Platform abstraction (`SecureKeyStore`) integrating with OS Keyring / Windows DPAPI / macOS Keychain / Linux Secret Service
- **Synthetic Token Mapping & Rehydration**: Bidirectional token-to-encrypted-real-value registry (`models/token_mapping.py`)
- **Permission & Owner Authorization Layer**: Granular permission gate managing access states (`PENDING`, `APPROVED`, `DENIED`, `EXPIRED`, `REVOKED`)
- Inter-module Pydantic v2 data contracts and validation schemas (`schemas/`)
- Deployment infrastructure (`docker-compose.yml`) and configuration (`core/config.py`)

## Core Privacy Invariants
- **Local-First & Device-Authoritative**: Real sensitive data and synthetic token mappings reside exclusively on the owner's device. No cloud database holds the user's plaintext records.
- **Secure Key Boundary**: The database encryption key is managed outside the database file via `SecureKeyStore` OS-level credential storage.
- **Explicit Owner Authorization**: Rehydration of real values requires explicit owner consent; external services never receive or rehydrate real sensitive values.
- **Zero Plaintext Sensitive Values**: Raw Aadhaar, PAN, passwords, and secrets are strictly excluded from audit logs and external API calls.
