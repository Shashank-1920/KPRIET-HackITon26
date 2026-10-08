# S.H.A.D.E. — Sovereign War-Room HUD & Sentinel
### Frontend Module (Member 4 / UI Lead)
*Sovereign Host for AI Data Enforcement (On-Device Hypervisor)*

---

## 1. Overview
The S.H.A.D.E. Frontend is an **Executive Cyber War-Room HUD** engineered for the live 3-minute hackathon pitch. It runs natively in any modern browser without heavy node dependencies and connects directly to the local S.H.A.D.E. reverse proxy at `http://127.0.0.1:8000`.

---

## 2. Implemented Modules & Architecture Mapping

| S.H.A.D.E. Module | Blueprint Specification | Frontend Implementation |
| :--- | :--- | :--- |
| **Module 1: Sovereign AI Gateway** | Section 2.0 & 2.1 | **In-Flight Tokenization Sandbox**: Live side-by-side stream comparison (Raw Ingress ➡️ Sanitized Cloud Egress with `<SYN_AADHAAR_xxxx>` ➡️ Local Stream Re-hydration). |
| **Module 2: Local Breach Radar** | Section 3.0 & 3.2 | **SVG Threat Gauge (Benchmark 72/100)**: Animated radial gauge implementing formula `min(100, SUM[W_type * R_recency])` + cryptographic **k-Anonymity protocol visualizer** (5-character SHA-1 prefix query). |
| **Module 3: DPDP Act 2023 Studio** | Section 4.0 | **Section 12(1) & 12(3) Requisition Generator**: Curated Indian Fiduciary directory (Swiggy, Zomato, PhonePe, CRED, PolicyBazaar), Section 33 penalties (₹250 Crore), 1-click email dispatch & immutable audit stamp. |
| **Module 4: Ambient Voice Sentinel** | Section 5.0 | **'Hey Shade' Audio Deck**: Web Audio API canvas visualizer, speech synthesis (`WebSpeech`), and **Auditorium Failsafe Quick-Trigger Chips** for noisy hackathon presentation halls. |
| **Module 5: Context-Aware Clipboard** | Section 1.1 & 6.0 (Setback 2) | **Floating Clipboard HUD**: 1-click *"Paste as Safe Decoy"* vs *"Send Real Value (KYC Exception)"*, preventing banking KYC breakage. |
| **Module 6: Ephemeral RAM Vault** | Section 2.1 | **Live Session Token Inspector**: Thread-safe bidirectional token mappings with countdown 15-minute TTL & emergency memory zeroization wipe. |

---

## 3. How to Launch & Test Locally

You can launch and view the War-Room HUD immediately in any browser:

### Option A: Direct Browser Launch
Simply double-click or open `frontend/index.html` in Chrome, Edge, Brave, or Firefox.

### Option B: Local HTTP Server (Python)
Run the built-in Python web server in the `frontend` folder:
```bash
cd frontend
python -m http.server 3000
```
Then visit: `http://localhost:3000`

---

## 4. 3-Minute Live Hackathon Pitch Guide
Inside the HUD, click the **"⚡ PITCH Cue Cards"** button in the header, or follow this exact sequence:

1. **Minute 1 (Gateway Live Test)**:
   - Click preset *"Aadhaar + PAN Customer KYC"*.
   - Click *"Intercept & Stream Through S.H.A.D.E."*.
   - **Show judges:** The cloud LLM received *only* `<SYN_AADHAAR_9921>`, while the local client screen seamlessly restored the plaintext without network exposure.
2. **Minute 2 (Voice Sentinel & Breach Radar)**:
   - Click the chip: *"Hey Shade, run exposure scan"*.
   - System confirms audibly: *"Scan complete. Illustrative threat score 72."*
   - Point out the k-anonymity cryptographic model (5-character SHA-1 prefix query).
3. **Minute 3 (Statutory DPDP Enforcement)**:
   - Click *"Synthesize Certified DPDP Requisition"*.
   - Point out the lawyer-verified statutory citations citing Section 12 and Section 33 penalties of up to ₹250 Crore.
   - Click *"Dispatch via Default Email Client"*.
