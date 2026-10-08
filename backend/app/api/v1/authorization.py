"""
S.H.A.D.E. — Authorization Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST /authorization/request           — Request access to a sensitive value
  POST /authorization/challenge/{id}    — Create single-use authentication challenge
  POST /authorization/approve/{id}      — Owner approves (verified biometric/PIN assertion)
  POST /authorization/deny/{id}         — Owner denies
  GET  /authorization/{id}              — Check authorization state
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.api.dependencies import SessionContext, get_current_session
from backend.app.core.errors import NotFoundError
from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    AuthChallengeResponse,
    AuthorizationApprovalRequest,
    AuthorizationRequest,
    AuthorizationResponse,
)
from backend.app.services.authorization_service import AuthorizationService
from backend.app.services.vault_service import VaultService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/request", summary="Request authorization to access a sensitive value")
async def request_authorization(
    body: AuthorizationRequest,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate an authorization request for a sensitive value identified by its synthetic token.
    Enforces that caller has a valid session and token belongs to the authenticated owner.
    """
    auth_svc = AuthorizationService(db)
    vault = VaultService(db)

    token_record = await vault.lookup_by_token(body.synthetic_token)
    if token_record is None:
        raise NotFoundError(f"Synthetic token not found: {body.synthetic_token}")

    auth = await auth_svc.request_authorization(
        sensitive_value_id=token_record.sensitive_value_id,
        requesting_component=body.requesting_component,
        purpose_scope=body.purpose_scope,
        owner_id=session_ctx.owner.id,
    )
    return AuthorizationResponse(
        authorization_id=auth.id,
        state=auth.state,
        requesting_component=auth.requesting_component,
        purpose_scope=auth.purpose_scope,
        requested_at=auth.requested_at,
        resolved_at=auth.resolved_at,
        auth_method=auth.auth_method,
    )


@router.post("/challenge/{authorization_id}", response_model=AuthChallengeResponse, summary="Create owner authentication challenge")
async def create_authorization_challenge(
    authorization_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Generate a single-use time-bound challenge nonce for biometric/PIN approval.
    """
    auth_svc = AuthorizationService(db)
    challenge = await auth_svc.create_challenge(authorization_id, session_ctx.owner.id)
    return AuthChallengeResponse(
        challenge_id=challenge.challenge_id,
        owner_id=challenge.owner_id,
        action=challenge.action,
        resource_id=challenge.resource_id,
        nonce=challenge.nonce,
        expires_at=challenge.expires_at,
    )


@router.post("/approve/{authorization_id}", summary="Owner approves authorization (verified assertion required)")
async def approve_authorization(
    authorization_id: str,
    body: AuthorizationApprovalRequest,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """
    Owner approves a PENDING authorization with verified authentication assertion.
    Rejects raw claims. Requires verified biometric cryptographic assertion or Argon2id PIN.
    """
    auth_svc = AuthorizationService(db)
    auth = await auth_svc.approve_authorization(
        authorization_id=authorization_id,
        auth_method=body.auth_method,
        challenge_id=body.challenge_id,
        assertion=body.assertion,
        owner=session_ctx.owner,
    )
    return AuthorizationResponse(
        authorization_id=auth.id,
        state=auth.state,
        requesting_component=auth.requesting_component,
        purpose_scope=auth.purpose_scope,
        requested_at=auth.requested_at,
        resolved_at=auth.resolved_at,
        auth_method=auth.auth_method,
    )


@router.post("/deny/{authorization_id}", summary="Owner denies authorization")
async def deny_authorization(
    authorization_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    auth_svc = AuthorizationService(db)
    auth = await auth_svc.deny_authorization(authorization_id, session_ctx.owner.id)
    return AuthorizationResponse(
        authorization_id=auth.id,
        state=auth.state,
        requesting_component=auth.requesting_component,
        purpose_scope=auth.purpose_scope,
        requested_at=auth.requested_at,
        resolved_at=auth.resolved_at,
        auth_method=auth.auth_method,
    )


@router.get("/{authorization_id}", response_model=AuthorizationResponse)
async def get_authorization_status(
    authorization_id: str,
    session_ctx: SessionContext = Depends(get_current_session),
    db: AsyncSession = Depends(get_db),
):
    """Check the current state of an authorization. Scoped to authenticated owner."""
    auth_svc = AuthorizationService(db)
    auth = await auth_svc.check_authorization(authorization_id, session_ctx.owner.id)
    return AuthorizationResponse(
        authorization_id=auth.id,
        state=auth.state,
        requesting_component=auth.requesting_component,
        purpose_scope=auth.purpose_scope,
        requested_at=auth.requested_at,
        resolved_at=auth.resolved_at,
        auth_method=auth.auth_method,
    )
