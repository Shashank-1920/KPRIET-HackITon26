"""
S.H.A.D.E. — Pydantic v2 Schemas (API Contracts)
Role: Member 1 — Core Architecture + Backend + Database + Integration

These schemas define the integration contracts for all four team members.
All API inputs/outputs are validated through these schemas.

SECURITY RULES:
- Schemas that return data to callers must NEVER include plaintext sensitive values
  unless the caller holds an APPROVED authorization.
- Sensitive values in REQUEST bodies are accepted only by vault-write endpoints
  (clipboard/DLP submit, manual vault store) and must be handled carefully.
- All sensitive request fields are marked with descriptions for auditors.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator


# ─────────────────────────────────────────────────────────────────────────────
# OWNER / REGISTRATION
# ─────────────────────────────────────────────────────────────────────────────

class OwnerRegistrationRequest(BaseModel):
    """
    Step 1: Owner submits their mobile number to begin registration.
    The mobile number is hashed server-side; it is not stored in plaintext.
    """
    mobile_number: str = Field(
        ..., min_length=10, max_length=15,
        description="Owner mobile number for OTP-based registration. Not stored in plaintext.",
    )


class OTPVerificationRequest(BaseModel):
    """Step 2: Owner submits the OTP received on their mobile."""
    mobile_number: str = Field(..., min_length=10, max_length=15)
    otp_code: str = Field(..., min_length=4, max_length=8, description="One-time passcode.")


class DeviceBindingRequest(BaseModel):
    """Step 3: After OTP verification, bind the vault to this device."""
    device_fingerprint_hash: str = Field(
        ..., min_length=64, max_length=64,
        description="SHA-256 of composite hardware fingerprint. Must be provided by client.",
    )
    platform: str = Field(..., description="windows | macos | linux")
    pin_hash: Optional[str] = Field(
        default=None,
        description="Optional Argon2id hash of device PIN for fallback authorization.",
    )


class OwnerStatusResponse(BaseModel):
    owner_id: str
    is_registered: bool
    device_is_bound: bool
    registered_at: Optional[datetime]


# ─────────────────────────────────────────────────────────────────────────────
# VAULT — Sensitive Value Storage
# ─────────────────────────────────────────────────────────────────────────────

class StoreSensitiveValueRequest(BaseModel):
    """
    Store a new sensitive value in the encrypted vault.
    Accepted by vault-write endpoints (clipboard/DLP pipeline and manual entry).
    raw_value is encrypted immediately upon receipt; never persisted as plaintext.
    """
    raw_value: str = Field(
        ..., min_length=1,
        description="The actual sensitive value. Encrypted at rest; never logged.",
    )
    data_type: str = Field(
        ...,
        description="AADHAAR | PAN | PASSWORD | API_KEY | MOBILE | EMAIL | CREDIT_CARD | UPI_ID | VEHICLE_PLATE | URL_WITH_SECRET | OTHER",
    )


class SensitiveValueResponse(BaseModel):
    """Safe vault entry response — never includes plaintext sensitive value."""
    id: str
    data_type: str
    synthetic_token: str = Field(..., description="12-character safe synthetic representation.")
    created_at: datetime
    deleted_at: Optional[datetime] = None


class DeleteSensitiveValueResponse(BaseModel):
    id: str
    deleted: bool
    authorizations_invalidated: int = Field(
        description="Number of authorization records invalidated by this deletion."
    )


# ─────────────────────────────────────────────────────────────────────────────
# TOKEN
# ─────────────────────────────────────────────────────────────────────────────

class TokenLookupResponse(BaseModel):
    """Response to a token lookup — safe metadata only."""
    token_id: str
    synthetic_token: str
    data_type: str
    exists: bool
    created_at: Optional[datetime] = None


class TokenValidationResponse(BaseModel):
    synthetic_token: str
    is_valid: bool
    data_type: Optional[str] = None
    sensitive_value_id: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# CLIPBOARD / DLP  (Integration Contract for Member 2)
# ─────────────────────────────────────────────────────────────────────────────

class ClipboardSubmitRequest(BaseModel):
    """
    Member 2 (DLP) submits detected clipboard content to the backend.
    Backend decides: tokenize if sensitive, pass through if clean.

    This endpoint is the ONLY point where raw sensitive content enters the backend.
    It must be encrypted immediately upon receipt.
    """
    content: str = Field(
        ..., min_length=1,
        description="Copied text content from clipboard. May be sensitive.",
    )
    detected_type: Optional[str] = Field(
        default=None,
        description="Data type detected by Member 2 DLP (AADHAAR, PAN, etc.). "
                    "If None, backend treats content as undetected/normal.",
    )
    detection_confidence: Optional[float] = Field(
        default=None, ge=0.0, le=1.0,
        description="DLP detection confidence score (0.0–1.0) provided by Member 2.",
    )
    detection_metadata: Optional[Dict[str, Any]] = Field(
        default=None, description="Additional detection metadata from Member 2.",
    )


class ClipboardSubmitResponse(BaseModel):
    """
    Response to a clipboard submission.
    If sensitive: synthetic_token is set, is_sensitive=True.
    If normal: is_sensitive=False, synthetic_token=None.
    """
    is_sensitive: bool
    synthetic_token: Optional[str] = Field(
        default=None, description="12-char token if sensitive, else None."
    )
    data_type: Optional[str] = None
    action: str = Field(description="TOKENIZED | REUSED | PASSTHROUGH")


# ─────────────────────────────────────────────────────────────────────────────
# AUTHORIZATION
# ─────────────────────────────────────────────────────────────────────────────

class AuthorizationRequest(BaseModel):
    """Request authorization to access a real sensitive value by its synthetic token."""
    synthetic_token: str = Field(
        ..., min_length=12, max_length=12,
        description="The 12-character synthetic token for which access is requested.",
    )
    requesting_component: str = Field(
        ..., max_length=128,
        description="Identifier of the component/application requesting access.",
    )
    purpose_scope: Optional[str] = Field(
        default=None,
        description="Business justification for the access request.",
    )


class AuthorizationApprovalRequest(BaseModel):
    """Owner approves a PENDING authorization (via biometric or PIN)."""
    authorization_id: str
    auth_method: str = Field(description="BIOMETRIC | PIN")


class AuthorizationResponse(BaseModel):
    authorization_id: str
    state: str = Field(description="PENDING | APPROVED | DENIED | EXPIRED | REVOKED")
    requesting_component: str
    purpose_scope: Optional[str]
    requested_at: datetime
    resolved_at: Optional[datetime]
    auth_method: Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# REHYDRATION
# ─────────────────────────────────────────────────────────────────────────────

class RehydrationSubmitRequest(BaseModel):
    """
    Submit text containing one or more synthetic tokens for rehydration processing.
    Backend detects tokens and initiates the owner authorization flow.
    """
    content: str = Field(
        ..., description="Text (possibly from external AI response) containing synthetic tokens."
    )
    requesting_component: str = Field(..., max_length=128)
    purpose_scope: Optional[str] = None


class RehydrationSubmitResponse(BaseModel):
    """
    Result of scanning content for synthetic tokens.
    If tokens found: authorization flow initiated (PENDING).
    """
    tokens_detected: List[str]
    rehydration_request_ids: List[str]
    all_authorized: bool
    message: str


class RehydrationResultRequest(BaseModel):
    """Request the result of a completed rehydration authorization."""
    rehydration_request_id: str


class RehydrationResultResponse(BaseModel):
    """
    If APPROVED: real_value contains the decrypted value (device-local only).
    If PENDING/DENIED/EXPIRED: real_value is None.
    NEVER send real_value to external systems.
    """
    rehydration_request_id: str
    synthetic_token: str
    state: str
    real_value: Optional[str] = Field(
        default=None,
        description="Decrypted sensitive value. Only present if state=APPROVED. "
                    "MUST NOT be forwarded to external services.",
    )


# ─────────────────────────────────────────────────────────────────────────────
# EXPOSURE  (Integration Contract for Member 2)
# ─────────────────────────────────────────────────────────────────────────────

class ExposureSearchRequest(BaseModel):
    """
    Manual exposure search request.
    Member 2's security engine processes the search; Member 1 persists results.
    """
    search_type: str = Field(
        description="EMAIL | MOBILE | API_KEY | PASSWORD | AADHAAR | OTHER"
    )
    search_value_hash: str = Field(
        ...,
        description="SHA-256 hash of the value being searched. "
                    "Raw sensitive value must NOT be sent here.",
    )
    sensitive_value_id: Optional[str] = Field(
        default=None,
        description="If the value is already in the vault, reference its ID.",
    )


class ExposureSubmitRequest(BaseModel):
    """
    Member 2 submits a discovered exposure result to the backend for persistence.
    """
    sensitive_value_id: Optional[str] = None
    data_type: str
    organization: Optional[str] = None
    source_url: Optional[str] = None
    evidence_summary: Optional[str] = None
    discovery_mode: str = Field(default="MANUAL", description="MANUAL | AUTOMATIC")


class ExposureResponse(BaseModel):
    id: str
    data_type: str
    organization: Optional[str]
    source_url: Optional[str]
    evidence_summary: Optional[str]
    discovered_at: datetime
    discovery_mode: str
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# RISK  (Integration Contract for Member 3)
# ─────────────────────────────────────────────────────────────────────────────

class RiskResultSubmitRequest(BaseModel):
    """
    Member 3 submits a computed risk result to the backend.
    Backend stores it; does NOT recompute.
    """
    exposure_id: str
    risk_score: float = Field(..., ge=0, le=100, description="Risk score 0–100.")
    risk_level: str = Field(description="NONE | LOW | MEDIUM | CRITICAL")
    analysis_metadata: Optional[Dict[str, Any]] = Field(
        default=None,
        description="Safe metadata from Member 3's AI analysis. Must not contain raw PII.",
    )


class RiskResultResponse(BaseModel):
    id: str
    exposure_id: str
    risk_score: float
    risk_level: str
    scored_at: datetime
    analysis_metadata: Optional[str]


# ─────────────────────────────────────────────────────────────────────────────
# CASE MANAGEMENT
# ─────────────────────────────────────────────────────────────────────────────

class CaseCreateRequest(BaseModel):
    exposure_id: str
    organization: Optional[str] = None
    data_type: str
    affected_data_description: Optional[str] = Field(
        default=None, description="Human-readable description. Must NOT include plaintext PII."
    )
    discovery_date: datetime
    evidence: Optional[str] = None
    unsupported_notes: Optional[str] = Field(
        default=None,
        description="Notes clearly marked as unconfirmed/unsupported assumptions.",
    )


class CaseResponse(BaseModel):
    id: str
    exposure_id: str
    organization: Optional[str]
    data_type: str
    affected_data_description: Optional[str]
    discovery_date: datetime
    evidence: Optional[str]
    unsupported_notes: Optional[str]
    risk_score: Optional[float]
    risk_level: Optional[str]
    status: str
    created_at: datetime
    updated_at: datetime


class CaseUpdateRequest(BaseModel):
    status: Optional[str] = None
    evidence: Optional[str] = None
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None


# ─────────────────────────────────────────────────────────────────────────────
# ERASURE REQUESTS
# ─────────────────────────────────────────────────────────────────────────────

class ErasureRequestCreate(BaseModel):
    case_id: str
    dpo_email: Optional[str] = None
    legal_basis: Optional[str] = Field(
        default="DPDP Act 2023, Section 12(1) and Section 12(2)"
    )
    request_body: str = Field(..., description="Full text of the erasure request.")


class ErasureRequestResponse(BaseModel):
    id: str
    case_id: str
    dpo_email: Optional[str]
    legal_basis: Optional[str]
    request_date: Optional[datetime]
    deadline_date: Optional[datetime]
    status: str
    organization_response: Optional[str]
    created_at: datetime


class ErasureRequestSendResponse(BaseModel):
    id: str
    status: str
    request_date: datetime
    deadline_date: datetime
    message: str


class ErasureResponseUpdate(BaseModel):
    organization_response: str = Field(
        ...,
        description="Response received from the organization. "
                    "Backend does NOT mark data deleted unless evidence confirms it.",
    )
    new_status: str = Field(description="RESPONSE_RECEIVED | RESOLVED | NO_RESPONSE")


class FollowUpRequestCreate(BaseModel):
    erasure_request_id: str
    follow_up_body: str


class FollowUpResponse(BaseModel):
    id: str
    erasure_request_id: str
    follow_up_body: str
    status: str
    sent_at: Optional[datetime]
    created_at: datetime


# ─────────────────────────────────────────────────────────────────────────────
# DEVICE
# ─────────────────────────────────────────────────────────────────────────────

class DeviceStatusResponse(BaseModel):
    device_id: str
    platform: str
    is_bound: bool
    bound_at: Optional[datetime]
    vault_status: str = Field(description="INITIALIZED | LOCKED | UNLOCKED")


# ─────────────────────────────────────────────────────────────────────────────
# SESSION
# ─────────────────────────────────────────────────────────────────────────────

class SessionCreateResponse(BaseModel):
    session_id: str
    access_token: str
    token_type: str = "bearer"
    expires_at: datetime


class SessionValidationResponse(BaseModel):
    session_id: str
    is_valid: bool
    owner_id: str
    device_id: str
    expires_at: datetime


# ─────────────────────────────────────────────────────────────────────────────
# AUDIT
# ─────────────────────────────────────────────────────────────────────────────

class AuditEventResponse(BaseModel):
    """Safe audit event for API responses."""
    id: str
    event_type: str
    synthetic_token: Optional[str]
    session_id: Optional[str]
    device_id: Optional[str]
    requesting_component: Optional[str]
    result: Optional[str]
    timestamp: datetime
