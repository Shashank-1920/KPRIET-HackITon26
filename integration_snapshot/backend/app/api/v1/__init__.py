"""
S.H.A.D.E. — API v1 Router Aggregator
Role: Member 1 — Core Architecture + Backend + Database + Integration

All versioned endpoints are registered here under /api/v1/.
"""

from fastapi import APIRouter

from backend.app.api.v1 import (
    auth,
    authorization,
    cases,
    clipboard,
    device,
    erasure,
    exposure,
    rehydration,
    risk,
    session,
    vault,
)

router = APIRouter()

router.include_router(auth.router, prefix="/auth", tags=["Auth & Registration"])
router.include_router(device.router, prefix="/device", tags=["Device"])
router.include_router(session.router, prefix="/session", tags=["Session"])
router.include_router(vault.router, prefix="/vault", tags=["Vault"])
router.include_router(clipboard.router, prefix="/clipboard", tags=["Clipboard / DLP"])
router.include_router(authorization.router, prefix="/authorization", tags=["Authorization"])
router.include_router(rehydration.router, prefix="/rehydration", tags=["Rehydration"])
router.include_router(exposure.router, prefix="/exposure", tags=["Exposure"])
router.include_router(risk.router, prefix="/risk", tags=["Risk"])
router.include_router(cases.router, prefix="/cases", tags=["Cases"])
router.include_router(erasure.router, prefix="/erasure", tags=["Erasure"])
