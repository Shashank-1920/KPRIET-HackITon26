"""
S.H.A.D.E. — Rehydration Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST /rehydration/submit    — Submit text with synthetic tokens for rehydration
  GET  /rehydration/{id}      — Get result of a rehydration request
"""

import logging
import re

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    RehydrationResultResponse,
    RehydrationSubmitRequest,
    RehydrationSubmitResponse,
)
from backend.app.services.authorization_service import AuthorizationService
from backend.app.services.vault_service import VaultService

logger = logging.getLogger(__name__)
router = APIRouter()

_TOKEN_REGEX = re.compile(r"SHD_[0-9A-F]{8}")


@router.post("/submit", response_model=RehydrationSubmitResponse, summary="Submit text for rehydration")
async def submit_for_rehydration(
    body: RehydrationSubmitRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Scan submitted text for synthetic tokens and initiate rehydration authorization flows.

    For each token found:
    - A RehydrationRequest (PENDING) is created.
    - An Authorization (PENDING) is created for the owner to approve/deny.

    The owner must separately approve/deny via POST /authorization/approve/{id}.
    """
    tokens_found = _TOKEN_REGEX.findall(body.content)
    tokens_found = list(set(tokens_found))  # deduplicate

    auth_svc = AuthorizationService(db)
    rehydration_ids = []

    for token in tokens_found:
        try:
            rr, auth = await auth_svc.request_rehydration(
                token=token,
                requesting_component=body.requesting_component,
                purpose_scope=body.purpose_scope,
            )
            rehydration_ids.append(rr.id)
        except Exception as exc:
            logger.warning("[Rehydration] Could not process token %s: %s", token, exc)

    return RehydrationSubmitResponse(
        tokens_detected=tokens_found,
        rehydration_request_ids=rehydration_ids,
        all_authorized=False,  # Owner must explicitly approve
        message=f"{len(tokens_found)} token(s) detected. Authorization required from owner.",
    )


@router.post("/result/{rehydration_request_id}", response_model=RehydrationResultResponse)
async def get_rehydration_result(
    rehydration_request_id: str,
    authorization_id: str,
    db: AsyncSession = Depends(get_db),
):
    """
    Return the rehydration result for an approved request.
    Requires a valid APPROVED authorization_id.
    If not approved: returns state only (real_value=None).

    NEVER forward real_value to external systems.
    """
    from backend.app.database.models import Authorization, RehydrationRequest, SyntheticToken

    rr = await db.get(RehydrationRequest, rehydration_request_id)
    if rr is None:
        from backend.app.core.errors import NotFoundError
        raise NotFoundError("Rehydration request not found.")

    token_record = await db.get(SyntheticToken, rr.synthetic_token_id)
    auth = await db.get(Authorization, authorization_id)

    real_value = None
    state = rr.state

    if auth and auth.state == "APPROVED":
        vault = VaultService(db)
        try:
            real_value = await vault.retrieve_sensitive_value(
                sensitive_value_id=token_record.sensitive_value_id,
                authorization_id=authorization_id,
            )
            rr.state = "APPROVED"
            state = "APPROVED"
        except Exception as exc:
            logger.warning("[Rehydration] Retrieval failed: %s", exc)
            state = rr.state
    else:
        state = auth.state if auth else rr.state

    return RehydrationResultResponse(
        rehydration_request_id=rehydration_request_id,
        synthetic_token=token_record.token if token_record else "",
        state=state,
        real_value=real_value,
    )
