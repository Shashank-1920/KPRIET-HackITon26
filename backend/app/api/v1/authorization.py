"""
S.H.A.D.E. — Authorization Router
Role: Member 1 — Core Architecture + Backend + Database + Integration

Endpoints:
  POST /authorization/request      — Request access to a sensitive value
  POST /authorization/approve/{id} — Owner approves (biometric/PIN)
  POST /authorization/deny/{id}    — Owner denies
  GET  /authorization/{id}         — Check authorization state
"""

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from backend.app.database.session import get_db
from backend.app.schemas.schemas import (
    AuthorizationApprovalRequest,
    AuthorizationRequest,
    AuthorizationResponse,
)
from backend.app.services.authorization_service import AuthorizationService

logger = logging.getLogger(__name__)
router = APIRouter()


@router.post("/request", summary="Request authorization to access a sensitive value")
async def request_authorization(
    body: AuthorizationRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate an authorization request for a sensitive value identified by its synthetic token.
    Creates a PENDING authorization; owner must explicitly approve or deny.

    REQUEST ≠ AUTHORIZATION. Calling this endpoint does NOT grant access.
    """
    auth_svc = AuthorizationService(db)

    # Resolve token → sensitive_value_id
    from backend.app.services.vault_service import VaultService
    vault = VaultService(db)
    token_record = await vault.lookup_by_token(body.synthetic_token)
    if token_record is None:
        from backend.app.core.errors import NotFoundError
        raise NotFoundError(f"Synthetic token not found: {body.synthetic_token}")

    auth = await auth_svc.request_authorization(
        sensitive_value_id=token_record.sensitive_value_id,
        requesting_component=body.requesting_component,
        purpose_scope=body.purpose_scope,
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


@router.post("/approve/{authorization_id}", summary="Owner approves authorization (biometric/PIN)")
async def approve_authorization(
    authorization_id: str,
    body: AuthorizationApprovalRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Owner explicitly approves a PENDING authorization after biometric/PIN verification.
    auth_method must be 'BIOMETRIC' or 'PIN'.

    This endpoint must only be called AFTER the platform layer has verified
    the biometric/PIN. The backend records the auth_method for audit purposes.
    """
    auth_svc = AuthorizationService(db)
    auth = await auth_svc.approve_authorization(authorization_id, body.auth_method)
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
    db: AsyncSession = Depends(get_db),
):
    auth_svc = AuthorizationService(db)
    auth = await auth_svc.deny_authorization(authorization_id)
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
    db: AsyncSession = Depends(get_db),
):
    """Check the current state of an authorization. PENDING requests are expired if timed out."""
    auth_svc = AuthorizationService(db)
    auth = await auth_svc.check_authorization(authorization_id)
    return AuthorizationResponse(
        authorization_id=auth.id,
        state=auth.state,
        requesting_component=auth.requesting_component,
        purpose_scope=auth.purpose_scope,
        requested_at=auth.requested_at,
        resolved_at=auth.resolved_at,
        auth_method=auth.auth_method,
    )
