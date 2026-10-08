"""
S.H.A.D.E. — SQLAlchemy Database Models
Role: Member 1 — Core Architecture + Backend + Database + Integration

Device-local encrypted SQLite schema.
All 12 entities required by PRODUCT_REQUIREMENTS.md are defined here.

SECURITY INVARIANTS:
- Sensitive plaintext values are NEVER stored in unencrypted columns.
- lookup_hash (SHA-256) enables duplicate detection without plaintext.
- Encryption keys are never stored in the database.
- All relationships use cascaded deletes to maintain referential integrity.
- Deleting a SensitiveValue record cascades to invalidate its Authorization.
"""

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    event,
)
from sqlalchemy.orm import DeclarativeBase, relationship


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _new_uuid() -> str:
    return str(uuid.uuid4())


class Base(DeclarativeBase):
    pass


# ─────────────────────────────────────────────────────────────────────────────
# 1. DEVICE
# ─────────────────────────────────────────────────────────────────────────────
class Device(Base):
    """
    Represents the single physical device to which this vault is bound.
    One S.H.A.D.E. installation = one device = one vault.
    """

    __tablename__ = "devices"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    # Composite hardware fingerprint (CPU ID, motherboard serial, MAC, etc.)
    # Stored as a salted hash — never raw hardware identifiers.
    device_fingerprint_hash = Column(String(64), nullable=False, unique=True)
    platform = Column(String(32), nullable=False)  # windows | macos | linux
    is_bound = Column(Boolean, default=False, nullable=False)
    bound_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    owners = relationship("Owner", back_populates="device", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────────────────
# 2. OWNER
# ─────────────────────────────────────────────────────────────────────────────
class Owner(Base):
    """
    The single owner of this S.H.A.D.E. installation.
    Mobile number is stored as a lookup hash (not plaintext) to prevent
    unnecessary exposure even inside the encrypted vault.
    """

    __tablename__ = "owners"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    # SHA-256 of mobile number — used for identity checks without storing plaintext
    mobile_hash = Column(String(64), nullable=False, unique=True)
    # Argon2id hash of device PIN (if PIN fallback is configured)
    pin_hash = Column(String(256), nullable=True)
    is_registered = Column(Boolean, default=False, nullable=False)
    registered_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    device = relationship("Device", back_populates="owners")
    sessions = relationship("Session", back_populates="owner", cascade="all, delete-orphan")
    sensitive_values = relationship(
        "SensitiveValue", back_populates="owner", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 3. SENSITIVE_VALUE
# ─────────────────────────────────────────────────────────────────────────────
class SensitiveValue(Base):
    """
    An encrypted sensitive value stored in the local vault.

    encrypted_blob : AES-256-GCM ciphertext (nonce || ciphertext || tag)
    lookup_hash    : SHA-256 of raw plaintext — allows duplicate detection
                     without ever storing plaintext.

    INVARIANT: encrypted_blob is the ONLY place the real value exists at rest.
               lookup_hash is a one-way fingerprint only.
    """

    __tablename__ = "sensitive_values"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    owner_id = Column(String(36), ForeignKey("owners.id", ondelete="CASCADE"), nullable=False)
    data_type = Column(
        Enum(
            "AADHAAR", "PAN", "PASSWORD", "API_KEY", "MOBILE", "EMAIL",
            "CREDIT_CARD", "UPI_ID", "VEHICLE_PLATE", "URL_WITH_SECRET", "OTHER",
            name="data_type_enum",
        ),
        nullable=False,
    )
    encrypted_blob = Column(LargeBinary, nullable=False)
    # SHA-256(plaintext) for duplicate detection — NOT decryptable back to plaintext
    lookup_hash = Column(String(64), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    deleted_at = Column(DateTime(timezone=True), nullable=True)  # soft-delete

    owner = relationship("Owner", back_populates="sensitive_values")
    token = relationship(
        "SyntheticToken",
        back_populates="sensitive_value",
        uselist=False,
        cascade="all, delete-orphan",
    )
    authorizations = relationship(
        "Authorization", back_populates="sensitive_value", cascade="all, delete-orphan"
    )

    __table_args__ = (
        # Enforce uniqueness: one encrypted record per (owner, hash) — no duplicates
        UniqueConstraint("owner_id", "lookup_hash", name="uq_owner_value_hash"),
    )


# ─────────────────────────────────────────────────────────────────────────────
# 4. SYNTHETIC_TOKEN
# ─────────────────────────────────────────────────────────────────────────────
class SyntheticToken(Base):
    """
    Exactly-12-character synthetic token mapped to one SensitiveValue.
    Safe to share externally; contains no recoverable information about the real value.

    FORMAT: SHD_XXXXXXX  (prefix 'SHD_' + 8 uppercase hex chars = 12 chars total)
    """

    __tablename__ = "synthetic_tokens"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    sensitive_value_id = Column(
        String(36),
        ForeignKey("sensitive_values.id", ondelete="CASCADE"),
        nullable=False,
        unique=True,
    )
    token = Column(String(12), nullable=False, unique=True)
    data_type = Column(String(32), nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    sensitive_value = relationship("SensitiveValue", back_populates="token")
    rehydration_requests = relationship(
        "RehydrationRequest", back_populates="synthetic_token", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 5. AUTHORIZATION
# ─────────────────────────────────────────────────────────────────────────────
class Authorization(Base):
    """
    Owner authorization record for a specific sensitive value.

    Lifecycle: PENDING → APPROVED | DENIED | EXPIRED → REVOKED (on deletion)

    Authorization lifetime:
        APPROVED state persists until the associated SensitiveValue is deleted.
        Deletion of SensitiveValue cascades to REVOKED status here.
    """

    __tablename__ = "authorizations"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    sensitive_value_id = Column(
        String(36), ForeignKey("sensitive_values.id", ondelete="CASCADE"), nullable=False
    )
    requesting_component = Column(String(128), nullable=False)
    purpose_scope = Column(Text, nullable=True)
    state = Column(
        Enum("PENDING", "APPROVED", "DENIED", "EXPIRED", "REVOKED", name="auth_state_enum"),
        default="PENDING",
        nullable=False,
    )
    # Authorization method used: BIOMETRIC | PIN | NONE (for DENIED/EXPIRED)
    auth_method = Column(String(32), nullable=True)
    requested_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    expires_prompt_at = Column(DateTime(timezone=True), nullable=True)  # 60s prompt budget

    sensitive_value = relationship("SensitiveValue", back_populates="authorizations")
    audit_events = relationship(
        "AuditEvent", back_populates="authorization", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 6. SESSION
# ─────────────────────────────────────────────────────────────────────────────
class Session(Base):
    """
    Owner session (JWT-backed). Sessions are device-bound.
    Sessions support creation, validation, expiration, and revocation.
    """

    __tablename__ = "sessions"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    owner_id = Column(String(36), ForeignKey("owners.id", ondelete="CASCADE"), nullable=False)
    device_id = Column(String(36), ForeignKey("devices.id", ondelete="CASCADE"), nullable=False)
    token_hash = Column(String(64), nullable=False, unique=True)  # SHA-256 of JWT
    is_revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)

    owner = relationship("Owner", back_populates="sessions")


# ─────────────────────────────────────────────────────────────────────────────
# 7. EXPOSURE
# ─────────────────────────────────────────────────────────────────────────────
class Exposure(Base):
    """
    An exposure record linking a sensitive value to a breach/leak event.
    Member 2 submits detected exposures; Member 1 persists them.
    """

    __tablename__ = "exposures"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    owner_id = Column(
        String(36), ForeignKey("owners.id", ondelete="CASCADE"), nullable=True
    )
    sensitive_value_id = Column(
        String(36), ForeignKey("sensitive_values.id", ondelete="SET NULL"), nullable=True
    )
    data_type = Column(String(32), nullable=False)
    organization = Column(String(256), nullable=True)
    source_url = Column(Text, nullable=True)
    evidence_summary = Column(Text, nullable=True)
    discovered_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    # Monitoring mode: MANUAL | AUTOMATIC
    discovery_mode = Column(String(16), default="MANUAL", nullable=False)

    owner = relationship("Owner", backref="exposures")

    risk_results = relationship(
        "RiskResult", back_populates="exposure", cascade="all, delete-orphan"
    )
    cases = relationship(
        "Case", back_populates="exposure", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 8. RISK_RESULT
# ─────────────────────────────────────────────────────────────────────────────
class RiskResult(Base):
    """
    Risk scoring result submitted by Member 3's AI/ML engine.
    Backend stores and exposes it; does NOT recompute or override it.

    Risk classification:
        0            → no exposure
        LOW          → low-risk website
        MEDIUM       → private organization
        CRITICAL     → public organization
    """

    __tablename__ = "risk_results"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    exposure_id = Column(
        String(36), ForeignKey("exposures.id", ondelete="CASCADE"), nullable=False
    )
    risk_score = Column(Float, nullable=False)  # 0–100
    risk_level = Column(
        Enum("NONE", "LOW", "MEDIUM", "CRITICAL", name="risk_level_enum"), nullable=False
    )
    analysis_metadata = Column(Text, nullable=True)  # JSON string from Member 3
    scored_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    scored_by = Column(String(64), default="member3-risk-engine", nullable=False)

    exposure = relationship("Exposure", back_populates="risk_results")


# ─────────────────────────────────────────────────────────────────────────────
# 9. CASE
# ─────────────────────────────────────────────────────────────────────────────
class Case(Base):
    """
    Investigation/exposure case record.
    Tracks evidence, risk, and statutory erasure lifecycle.

    Evidence invariant: confirmed information is separated from unsupported assumptions.
    """

    __tablename__ = "cases"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    owner_id = Column(
        String(36), ForeignKey("owners.id", ondelete="CASCADE"), nullable=True
    )
    exposure_id = Column(
        String(36), ForeignKey("exposures.id", ondelete="CASCADE"), nullable=False
    )
    organization = Column(String(256), nullable=True)
    data_type = Column(String(64), nullable=False)
    affected_data_description = Column(Text, nullable=True)  # safe description, no plaintext PII
    discovery_date = Column(DateTime(timezone=True), nullable=False)
    evidence = Column(Text, nullable=True)           # confirmed evidence
    unsupported_notes = Column(Text, nullable=True)  # clearly distinguished from evidence
    risk_score = Column(Float, nullable=True)
    risk_level = Column(String(16), nullable=True)
    status = Column(
        Enum(
            "OPEN", "ERASURE_REQUESTED", "AWAITING_RESPONSE",
            "FOLLOW_UP_SENT", "RESOLVED", "CLOSED",
            name="case_status_enum",
        ),
        default="OPEN",
        nullable=False,
    )
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=_utcnow, onupdate=_utcnow, nullable=False)

    exposure = relationship("Exposure", back_populates="cases")
    erasure_requests = relationship(
        "ErasureRequest", back_populates="case", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 10. ERASURE_REQUEST
# ─────────────────────────────────────────────────────────────────────────────
class ErasureRequest(Base):
    """
    Statutory data erasure request (DPDP Act 2023 Section 12).
    User reviews the prepared request before sending. 7-day deadline is tracked.

    INVARIANT: The backend must NOT mark data as deleted without evidence.
    """

    __tablename__ = "erasure_requests"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    case_id = Column(String(36), ForeignKey("cases.id", ondelete="CASCADE"), nullable=False)
    dpo_email = Column(String(256), nullable=True)
    legal_basis = Column(Text, nullable=True)      # e.g., "DPDP Act 2023, Section 12(1)"
    request_body = Column(Text, nullable=False)    # Full erasure request text
    request_date = Column(DateTime(timezone=True), nullable=True)  # When user sent it
    deadline_date = Column(DateTime(timezone=True), nullable=True)  # request_date + 7 days
    status = Column(
        Enum(
            "DRAFT", "SENT", "RESPONSE_RECEIVED", "NO_RESPONSE",
            "FOLLOW_UP_SENT", "RESOLVED",
            name="erasure_status_enum",
        ),
        default="DRAFT",
        nullable=False,
    )
    organization_response = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    case = relationship("Case", back_populates="erasure_requests")
    follow_up_requests = relationship(
        "FollowUpRequest", back_populates="erasure_request", cascade="all, delete-orphan"
    )


# ─────────────────────────────────────────────────────────────────────────────
# 11. FOLLOW_UP_REQUEST
# ─────────────────────────────────────────────────────────────────────────────
class FollowUpRequest(Base):
    """
    A follow-up erasure request dispatched after the 7-day deadline passes
    with no response from the organization.
    """

    __tablename__ = "follow_up_requests"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    erasure_request_id = Column(
        String(36), ForeignKey("erasure_requests.id", ondelete="CASCADE"), nullable=False
    )
    follow_up_body = Column(Text, nullable=False)
    sent_at = Column(DateTime(timezone=True), nullable=True)
    status = Column(
        Enum("DRAFT", "SENT", "ACKNOWLEDGED", name="followup_status_enum"),
        default="DRAFT",
        nullable=False,
    )
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    erasure_request = relationship("ErasureRequest", back_populates="follow_up_requests")


# ─────────────────────────────────────────────────────────────────────────────
# 12. AUDIT_EVENT
# ─────────────────────────────────────────────────────────────────────────────
class AuditEvent(Base):
    """
    Immutable security audit log entry.

    PROHIBITED from containing:
        - plaintext passwords, API keys, Aadhaar, PAN numbers
        - mobile numbers in plaintext
        - encryption keys
        - raw sensitive values of any kind

    ALLOWED to contain:
        - event_type, timestamp, token_id (synthetic), device/session ID,
          operation status, authorization result, component name.
    """

    __tablename__ = "audit_events"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    authorization_id = Column(
        String(36), ForeignKey("authorizations.id", ondelete="SET NULL"), nullable=True
    )
    event_type = Column(String(64), nullable=False)
    # Safe identifiers only — never plaintext sensitive values
    token_id = Column(String(36), nullable=True)       # synthetic_token.id
    synthetic_token = Column(String(12), nullable=True) # the 12-char token (safe)
    session_id = Column(String(36), nullable=True)
    device_id = Column(String(36), nullable=True)
    requesting_component = Column(String(128), nullable=True)
    result = Column(String(32), nullable=True)          # APPROVED | DENIED | EXPIRED | ERROR
    metadata_safe = Column(Text, nullable=True)         # JSON — no secrets
    timestamp = Column(DateTime(timezone=True), default=_utcnow, nullable=False)

    authorization = relationship("Authorization", back_populates="audit_events")


# ─────────────────────────────────────────────────────────────────────────────
# REHYDRATION_REQUEST  (tracks active token detection / rehydration flow)
# ─────────────────────────────────────────────────────────────────────────────
class RehydrationRequest(Base):
    """
    Tracks a live rehydration request from token detection through owner decision.
    Linked to SyntheticToken; the owner's decision is recorded in Authorization.
    """

    __tablename__ = "rehydration_requests"

    id = Column(String(36), primary_key=True, default=_new_uuid)
    synthetic_token_id = Column(
        String(36), ForeignKey("synthetic_tokens.id", ondelete="CASCADE"), nullable=False
    )
    requesting_component = Column(String(128), nullable=False)
    purpose_scope = Column(Text, nullable=True)
    state = Column(
        Enum("PENDING", "APPROVED", "DENIED", "EXPIRED", name="rehydration_state_enum"),
        default="PENDING",
        nullable=False,
    )
    created_at = Column(DateTime(timezone=True), default=_utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    synthetic_token = relationship("SyntheticToken", back_populates="rehydration_requests")
