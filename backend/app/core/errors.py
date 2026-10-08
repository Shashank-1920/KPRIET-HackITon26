"""
S.H.A.D.E. — Structured Error Definitions
Role: Member 1 — Core Architecture + Backend + Database + Integration

All API errors use RFC 7807-style structured JSON.
Error messages MUST NOT leak sensitive values, stack traces, or SQL.
"""

from typing import Optional


class ShadeError(Exception):
    """Base structured error for the S.H.A.D.E. backend."""

    status_code: int = 500
    error_code: str = "INTERNAL_ERROR"

    def __init__(self, message: str = "An unexpected error occurred.", detail: Optional[str] = None):
        self.message = message
        self.detail = detail
        super().__init__(message)


# ── 400 Bad Request ────────────────────────────────────────────────────────────
class InvalidRequestError(ShadeError):
    status_code = 400
    error_code = "INVALID_REQUEST"


class InvalidTokenError(ShadeError):
    status_code = 400
    error_code = "INVALID_TOKEN"


class DuplicateMappingError(ShadeError):
    status_code = 400
    error_code = "DUPLICATE_MAPPING"


# ── 401 Unauthorized ───────────────────────────────────────────────────────────
class UnauthorizedError(ShadeError):
    status_code = 401
    error_code = "UNAUTHORIZED"


# ── 403 Forbidden ─────────────────────────────────────────────────────────────
class ForbiddenError(ShadeError):
    status_code = 403
    error_code = "FORBIDDEN"


class DeviceNotBoundError(ShadeError):
    status_code = 403
    error_code = "DEVICE_NOT_BOUND"


class VaultLockedError(ShadeError):
    status_code = 403
    error_code = "VAULT_LOCKED"


class AuthorizationRequiredError(ShadeError):
    status_code = 403
    error_code = "AUTHORIZATION_REQUIRED"


class AuthorizationExpiredError(ShadeError):
    status_code = 403
    error_code = "AUTHORIZATION_EXPIRED"


# ── 404 Not Found ─────────────────────────────────────────────────────────────
class NotFoundError(ShadeError):
    status_code = 404
    error_code = "NOT_FOUND"


class SensitiveDataNotFoundError(ShadeError):
    status_code = 404
    error_code = "SENSITIVE_DATA_NOT_FOUND"


# ── 503 Service Unavailable ───────────────────────────────────────────────────
class ExternalServiceUnavailableError(ShadeError):
    status_code = 503
    error_code = "EXTERNAL_SERVICE_UNAVAILABLE"


class KeyStoreUnavailableError(ShadeError):
    status_code = 503
    error_code = "KEYSTORE_UNAVAILABLE"

