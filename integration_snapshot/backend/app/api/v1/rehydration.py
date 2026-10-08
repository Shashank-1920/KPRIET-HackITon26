"""
S.H.A.D.E. — Rehydration Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST /rehydration/submit                    — Submit text with synthetic tokens for rehydration
  POST /rehydration/result/{request_id}       — Retrieve approved rehydration result

INVARIANTS:
  - Requires authenticated session.
  - Evaluates destination trustworthiness.
  - External AI never receives real values without explicit authorization.
  - Merely knowing a synthetic token does NOT grant access to the real value.
  - Never forwards real values to external systems.
"""

import logging
import re

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import SessionContext, get_current_session
from backend.app.core.errors import NotFoundError, UnauthorizedError
from backend.app.database.models import Authorization, RehydrationRequest, SensitiveValue, SyntheticToken
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    RehydrationResultResponse,
    RehydrationSubmitRequest,
    RehydrationSubmitResponse,
)
from backend.app.services.authorization_service import AuthorizationService
from backend.app.services.destination_trust import get_destination_trust_evaluator
from backend.app.services.vault_service import VaultService

logger = logging.getLogger(__name__)
router = APIRouter()

_TOKEN_REGEX = re.compile(r"SHD_[0-9A-F]{8}")


@router.post("/submit", response_model=RehydrationSubmitResponse, summary="Submit text for rehydration")
async def submit_for_rehydration(
    body: RehydrationSubmitRequest,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Scan submitted text for synthetic tokens and initiate rehydration authorization flows.
    Evaluates destination trust and owner authorization requirements.
    """
    trust_evaluator = get_destination_trust_evaluator()
    trust_level = trust_evaluator.evaluate_destination(
        destination_url=body.destination_url,
        source_context={"component": body.requesting_component, "external_ai": body.is_external_ai},
    )

    tokens_found = _TOKEN_REGEX.findall(body.content)
    tokens_found = list(set(tokens_found))  # deduplicate

    auth_svc = AuthorizationService(db)
    rehydration_ids = []

    scope = body.purpose_scope or ""
    if body.is_external_ai:
        scope = f"[EXTERNAL_AI_REQUEST] {scope}".strip()

    for token in tokens_found:
        try:
            rr, auth = await auth_svc.request_rehydration(
                token=token,
                requesting_component=body.requesting_component,
                purpose_scope=scope,
                owner_id=session_ctx.owner.id,
            )
            rehydration_ids.append(rr.id)
        except Exception as exc:
            logger.warning("[Rehydration] Could not process token %s for owner %s: %s", token, session_ctx.owner.id, exc)

    return RehydrationSubmitResponse(
        tokens_detected=tokens_found,
        rehydration_request_ids=rehydration_ids,
        all_authorized=False,  # Owner must explicitly approve
        destination_trust=trust_level.value,
        message=f"{len(tokens_found)} token(s) detected. Owner authorization required.",
    )


@router.post("/result/{rehydration_request_id}", response_model=RehydrationResultResponse)
async def get_rehydration_result(
    rehydration_request_id: str,
    authorization_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Return the rehydration result for an approved request.
    Requires an APPROVED authorization belonging to the authenticated owner.
    """
    rr = await db.get(RehydrationRequest, rehydration_request_id)
    if rr is None:
        raise NotFoundError("Rehydration request not found.")

    token_record = await db.get(SyntheticToken, rr.synthetic_token_id)
    if token_record is None:
        raise NotFoundError("Associated synthetic token not found.")

    # Check sensitive value belongs to this owner
    sv = await db.get(SensitiveValue, token_record.sensitive_value_id)
    if sv is None or sv.deleted_at is not None or sv.owner_id != session_ctx.owner.id:
        raise NotFoundError("Sensitive value not found or deleted.")

    auth = await db.get(Authorization, authorization_id)
    real_value = None
    state = rr.state

    if auth and auth.state == "APPROVED" and auth.sensitive_value_id == sv.id:
        vault = VaultService(db)
        try:
            real_value = await vault.retrieve_sensitive_value(
                sensitive_value_id=token_record.sensitive_value_id,
                authorization_id=authorization_id,
                owner_id=session_ctx.owner.id,
            )
            state = "APPROVED"
        except Exception as exc:
            logger.error("[Rehydration] Error retrieving value: %s", exc)

    return RehydrationResultResponse(
        rehydration_request_id=rr.id,
        synthetic_token=token_record.token,
        state=state,
        destination_trust="EVALUATED",
        real_value=real_value,
    )
