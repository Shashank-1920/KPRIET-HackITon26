# S.H.A.D.E. — Backend & Core Architecture Module
**Ownership**: Member 1 (`member-1/backend`)  
**Role**: "Core Architecture + Backend + Database + Integration"

---

## Scope of Responsibility
- FastAPI ASGI application factory and lifecycle management (`main.py`)
- Central routing and versioned API registration (`api/routes/`)
- Ingress authentication guards (Argon2id password verification, JWT issuance, token rotation)
- Database engine, connection pooling, and SQLAlchemy 2.x session managers (`database/`)
- Relational ORM entity models (`models/`)
- Inter-module Pydantic v2 data contracts and validation schemas (`schemas/`)
- Deployment infrastructure (`docker-compose.yml`) and environment configuration (`core/config.py`)

## Boundary Invariants
- **No Hardcoded Secrets**: Secrets are loaded from environment variables via Pydantic settings.
- **Fail-Safe Offline Persistence**: Automatically falls back to SQLite (`sqlite+aiosqlite:///./shade_local.db`) if PostgreSQL is unavailable.
- **Zero Raw PII in Logs**: The structured logger filters out Aadhaar, PAN, passwords, and secrets before writing to stdout.
