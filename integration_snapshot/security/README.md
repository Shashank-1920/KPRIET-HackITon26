# S.H.A.D.E. — Security & Threat Engine Module
**Ownership**: Member 2 (`member-2/security`)  
**Role**: "Security + Threat Engine + Risk Analysis"

---

## Scope of Responsibility
- Deterministic Data Loss Prevention (DLP) pattern matching (`dlp/detectors/`)
- Indian Aadhaar Dihedral D5 Verhoeff checksum algorithm (`validators/verhoeff/`)
- Indian PAN structure verification and high-entropy secret detection (`dlp/patterns/`)
- Synthetic token placeholder generator (`dlp/tokenizer/`) emitting `<SYN_{TYPE}_{HASH}>`
- Canary honey-token generator for cryptographic leak attribution (`threat_engine/canaries.py`)
- Privacy-preserving HaveIBeenPwned Passwords API v3 k-anonymity client (`breach_radar/`)
- Centralized 0–100 Exposome Threat Index calculator (`risk_engine/`)

## Boundary Invariants
- **k-Anonymity Standard**: Only the first 5 characters of a local SHA-1 password hash may be dispatched to HIBP. Never send full passwords, emails, Aadhaar, or PAN to external APIs.
- **Deterministic Authority**: Security blocks and Verhoeff checksums must execute deterministically without AI dependency.
- **No Direct DB Access**: Receive inputs via Pydantic dataclasses and return results to the backend integration layer.
