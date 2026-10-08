# S.H.A.D.E. — Frontend & User Workflow Module
**Ownership**: Member 4 (`member-4/frontend`)  
**Role**: "Frontend + UI/UX + User Workflow"

---

## Scope of Responsibility
- React 19 application built with Vite and custom cyberpunk Vanilla CSS (`src/`)
- SVG 0–100 Exposome Threat Index visual gauge (`src/components/ThreatMeter.jsx`)
- Interactive real-time prompt interception sandbox (`src/components/SandboxConsole.jsx`)
- Canary honey-token generator card and breach attribution visualization
- One-click DPDP Act 2023 Section 12 legal notice preview and export modal
- Voice simulation HUD with one-click trigger chips for loud auditorium resilience

## Boundary Invariants
- **No Secrets in Frontend**: API keys, master encryption keys, and database credentials must never exist in frontend code or client bundles.
- **Backend API Boundary**: All operations communicate through the backend API gateway at `/api/v1/`. Frontend does not connect directly to PostgreSQL or Redis.
- **Zero Client-Side Auth Decisions**: The frontend reflects backend authorization states and never makes independent security access determinations.
