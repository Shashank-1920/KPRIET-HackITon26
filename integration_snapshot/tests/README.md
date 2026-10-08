# S.H.A.D.E. — Automated Test Suite Architecture
**Ownership**: All Members (Decoupled per discipline)

---

## Directory Organization
- `tests/backend/`: Owned by Member 1 (FastAPI routing, Auth token issuance, rate limits, DB persistence)
- `tests/security/`: Owned by Member 2 (Verhoeff checksum edge cases, Indian PAN regex, HIBP k-anonymity, risk weights)
- `tests/ai/`: Owned by Member 3 (Statistical anomaly scoring, Z-score thresholds, DPDP legal notice templates)
- `tests/frontend/`: Owned by Member 4 (React component unit tests, threat meter SVG rendering)
- `tests/integration/`: Shared (End-to-end integration tests connecting all modules)

## Execution Standards
Run backend, security, and AI tests using pytest:
```bash
pytest tests/ -v
```
Run specific module tests:
```bash
pytest tests/security/ -v
pytest tests/backend/ -v
pytest tests/ai/ -v
```
