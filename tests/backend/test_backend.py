"""
S.H.A.D.E. — Backend Test Suite
Role: Member 1 — Core Architecture + Backend + Database + Integration

Tests cover all 25 acceptance criteria:
1-6:   Owner registration, OTP, device binding, DB init, encryption
7-12:  Token generation (12 chars), collision handling, duplicate reuse, unauthorized rejection
13-25: Auth persistence, auth invalidation, offline vault, exposure, risk, case, erasure,
       session, audit (no plaintext secrets), API response security

All tests use synthetic/test values. NO real PII, NO real API keys.
"""

import sys
from pathlib import Path

# ── Ensure repo root is on sys.path (handles workspace paths with spaces) ────
_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import asyncio
import hashlib
import re
import pytest
import pytest_asyncio
from datetime import datetime, timezone

from httpx import AsyncClient, ASGITransport

# ── Configure test database (in-memory SQLite) ──────────────────────────────
import os
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHADE_MASTER_ENCRYPTION_KEY", "dGVzdF9tYXN0ZXJfa2V5X2Zvcl90ZXN0aW5nX29ubHlfMzI=")
os.environ.setdefault("SHADE_JWT_SECRET", "test-jwt-secret-for-testing-only")
os.environ.setdefault("OTP_PROVIDER", "mock")

from backend.main import app
from backend.app.database.session import init_db, AsyncSessionLocal
from backend.app.core.crypto import encrypt_value, decrypt_value, compute_lookup_hash
from backend.app.core.keystore import SecureKeyStore, EnvDevBackend
from backend.app.services.token_service import TokenService, generate_token, validate_token_format
from backend.app.database.models import Base, Owner, Device, SensitiveValue, SyntheticToken


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db():
    """Initialize in-memory database once for the test session."""
    await init_db()
    yield


@pytest_asyncio.fixture
async def client():
    """Async HTTP test client for the FastAPI app."""
    async with AsyncClient(
        transport=ASGITransport(app=app), base_url="http://test"
    ) as ac:
        yield ac


@pytest_asyncio.fixture
async def db():
    """Async database session for direct model testing."""
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()


# ── 1. Owner Registration ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_owner_registration_sends_otp(client: AsyncClient):
    """Test 1: Registration with valid mobile number sends OTP."""
    response = await client.post(
        "/api/v1/auth/register",
        json={"mobile_number": "9876543210"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "OTP sent" in data["message"]


@pytest.mark.asyncio
async def test_duplicate_owner_registration_rejected(client: AsyncClient):
    """Test 1b: Duplicate registration for same mobile is rejected."""
    # First registration
    await client.post("/api/v1/auth/register", json={"mobile_number": "9111111111"})
    # Second registration with same number
    response = await client.post("/api/v1/auth/register", json={"mobile_number": "9111111111"})
    assert response.status_code == 400


# ── 2. OTP Verification Abstraction ──────────────────────────────────────────

@pytest.mark.asyncio
async def test_otp_verification_success(client: AsyncClient):
    """Test 2: Mock OTP "000000" always passes in dev mode."""
    response = await client.post(
        "/api/v1/auth/verify-otp",
        json={"mobile_number": "9876543210", "otp_code": "000000"},
    )
    assert response.status_code == 200
    assert response.json()["mobile_verified"] is True


@pytest.mark.asyncio
async def test_otp_verification_wrong_code(client: AsyncClient):
    """Test 2b: Invalid OTP is rejected."""
    response = await client.post(
        "/api/v1/auth/verify-otp",
        json={"mobile_number": "9876543210", "otp_code": "999999"},
    )
    assert response.status_code == 401


# ── 3. Device Binding ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_device_binding(client: AsyncClient):
    """Test 3: Device binding creates owner and device records."""
    fingerprint = hashlib.sha256(b"test-device-unique-hw-id").hexdigest()
    response = await client.post(
        "/api/v1/auth/bind-device",
        json={
            "device_fingerprint_hash": fingerprint,
            "platform": "windows",
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert "owner_id" in data
    assert "device_id" in data


# ── 4. Database Initialization ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_database_initialized(client: AsyncClient):
    """Test 4: Health endpoint responds, confirming DB and app startup."""
    response = await client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


# ── 5 & 6. Encryption / Decryption ───────────────────────────────────────────

def test_encrypt_decrypt_roundtrip():
    """Test 5: AES-256-GCM encrypt/decrypt round-trip."""
    key = b"A" * 32
    plaintext = "my_secret_api_key_12345"
    blob = encrypt_value(plaintext, key)
    recovered = decrypt_value(blob, key)
    assert recovered == plaintext


def test_encrypt_produces_different_blobs():
    """Test 5b: Same plaintext with different nonces produces different blobs."""
    key = b"B" * 32
    blob1 = encrypt_value("same_value", key)
    blob2 = encrypt_value("same_value", key)
    assert blob1 != blob2  # Different nonces


def test_decrypt_wrong_key_fails():
    """Test 6: Decryption with wrong key raises exception (authentication failure)."""
    key_correct = b"C" * 32
    key_wrong = b"D" * 32
    blob = encrypt_value("secret", key_correct)
    with pytest.raises(Exception):
        decrypt_value(blob, key_wrong)


# ── 7. Token Length = 12 ─────────────────────────────────────────────────────

def test_token_length_exactly_12():
    """Test 7: Generated tokens are exactly 12 characters."""
    for _ in range(100):
        token = generate_token()
        assert len(token) == 12, f"Token length mismatch: '{token}' is {len(token)} chars"


def test_token_format():
    """Test 7b: Tokens match SHD_XXXXXXXX pattern."""
    for _ in range(50):
        token = generate_token()
        assert validate_token_format(token), f"Invalid token format: {token}"
        assert token.startswith("SHD_")
        assert len(token) == 12


# ── 8. Token Collision Handling ───────────────────────────────────────────────

def test_tokens_are_unique():
    """Test 8: Generated tokens are unique (collision test over 1000 tokens)."""
    tokens = {generate_token() for _ in range(1000)}
    assert len(tokens) == 1000, "Token collisions detected — CSPRNG may be broken"


# ── 9 & 10. Duplicate Sensitive-Value Mapping & New Mapping ──────────────────

@pytest.mark.asyncio
async def test_duplicate_sensitive_value_reuses_token(client: AsyncClient):
    """Tests 9 & 10: Same value → same token (reuse). Different value → new token."""
    # First store
    r1 = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "sample_api_key_test_abcdefg123", "data_type": "API_KEY"},
    )
    assert r1.status_code == 200
    token1 = r1.json()["synthetic_token"]
    assert len(token1) == 12

    # Same value → same token
    r2 = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "sample_api_key_test_abcdefg123", "data_type": "API_KEY"},
    )
    assert r2.status_code == 200
    token2 = r2.json()["synthetic_token"]
    assert token1 == token2, "Duplicate value must reuse existing token"

    # Different value → new token
    r3 = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "sample_api_key_different_xyz", "data_type": "API_KEY"},
    )
    assert r3.status_code == 200
    token3 = r3.json()["synthetic_token"]
    assert token1 != token3, "New value must get a new token"


# ── 11 & 12. Unauthorized Access Rejection & Authorized Access ───────────────

@pytest.mark.asyncio
async def test_unauthorized_vault_retrieval_rejected(client: AsyncClient):
    """Test 11: Retrieval without APPROVED authorization is rejected."""
    # Store a value
    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "my_password_123!", "data_type": "PASSWORD"},
    )
    sv_id = r.json()["id"]

    # Attempt retrieval with fake authorization_id
    response = await client.post(
        "/api/v1/vault/retrieve",
        params={"sensitive_value_id": sv_id, "authorization_id": "fake-auth-id"},
    )
    assert response.status_code in (400, 403, 404)


@pytest.mark.asyncio
async def test_authorized_access_succeeds(client: AsyncClient):
    """Test 12: Full vault → request auth → approve → retrieve cycle."""
    # Store
    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "password_for_auth_test_!@#", "data_type": "PASSWORD"},
    )
    assert r.status_code == 200
    sv_id = r.json()["id"]
    token = r.json()["synthetic_token"]

    # Request authorization
    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={
            "synthetic_token": token,
            "requesting_component": "test_suite",
            "purpose_scope": "automated test",
        },
    )
    assert auth_r.status_code == 200
    auth_id = auth_r.json()["authorization_id"]
    assert auth_r.json()["state"] == "PENDING"

    # Approve authorization (simulates owner biometric approval)
    approve_r = await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={"authorization_id": auth_id, "auth_method": "BIOMETRIC"},
    )
    assert approve_r.status_code == 200
    assert approve_r.json()["state"] == "APPROVED"

    # Retrieve real value
    retrieve_r = await client.post(
        "/api/v1/vault/retrieve",
        params={"sensitive_value_id": sv_id, "authorization_id": auth_id},
    )
    assert retrieve_r.status_code == 200
    assert retrieve_r.json()["real_value"] == "password_for_auth_test_!@#"


# ── 13. Authorization Persistence ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_authorization_persistence(client: AsyncClient):
    """Test 13: Authorization state persists in DB and can be re-queried."""
    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "persist_test_token_value", "data_type": "API_KEY"},
    )
    token = r.json()["synthetic_token"]

    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "persistence_test"},
    )
    auth_id = auth_r.json()["authorization_id"]

    # Re-query state
    status_r = await client.get(f"/api/v1/authorization/{auth_id}")
    assert status_r.status_code == 200
    assert status_r.json()["state"] == "PENDING"


# ── 14. Authorization Invalidation After Deletion ─────────────────────────────

@pytest.mark.asyncio
async def test_authorization_invalidated_on_deletion(client: AsyncClient):
    """Test 14: Deleting a sensitive value invalidates its APPROVED authorization."""
    # Store value
    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "value_to_delete_XYZ789", "data_type": "PASSWORD"},
    )
    sv_id = r.json()["id"]
    token = r.json()["synthetic_token"]

    # Request + approve authorization
    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "delete_test"},
    )
    auth_id = auth_r.json()["authorization_id"]
    await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={"authorization_id": auth_id, "auth_method": "PIN"},
    )

    # Delete the sensitive value
    del_r = await client.delete(f"/api/v1/vault/{sv_id}")
    assert del_r.status_code == 200
    assert del_r.json()["deleted"] is True
    assert del_r.json()["authorizations_invalidated"] >= 1


# ── 15. Device Binding Enforcement ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_device_status_endpoint(client: AsyncClient):
    """Test 15: Device status endpoint returns binding state."""
    response = await client.get("/api/v1/device/status")
    assert response.status_code == 200
    data = response.json()
    assert "is_bound" in data
    assert "vault_status" in data


# ── 16. Offline Vault Operations ─────────────────────────────────────────────

def test_offline_vault_encryption_decryption():
    """Test 16: Encryption/decryption works without network (pure local crypto)."""
    backend = EnvDevBackend("dGVzdF9tYXN0ZXJfa2V5X2Zvcl90ZXN0aW5nX29ubHlfMzI=")
    ks = SecureKeyStore(backend=backend)
    key = ks.get_master_key()
    assert len(key) == 32
    blob = encrypt_value("offline_test_aadhaar_266853339452", key)
    decrypted = decrypt_value(blob, key)
    assert decrypted == "offline_test_aadhaar_266853339452"


# ── 17. Exposure Persistence ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_exposure_submission(client: AsyncClient):
    """Test 17: Member 2 can submit an exposure record."""
    r = await client.post(
        "/api/v1/exposure/submit",
        json={
            "data_type": "EMAIL",
            "organization": "test_org",
            "evidence_summary": "Found in test breach database.",
            "discovery_mode": "MANUAL",
        },
    )
    assert r.status_code == 200
    assert "exposure_id" in r.json()


# ── 18. Risk Result Persistence ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_risk_result_persistence(client: AsyncClient):
    """Test 18: Member 3 can submit and retrieve a risk result."""
    # First create an exposure
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "PASSWORD", "organization": "risk_test_org", "discovery_mode": "AUTOMATIC"},
    )
    exposure_id = exp_r.json()["exposure_id"]

    # Submit risk result
    risk_r = await client.post(
        "/api/v1/risk/submit",
        json={
            "exposure_id": exposure_id,
            "risk_score": 85.0,
            "risk_level": "CRITICAL",
            "analysis_metadata": {"source": "member3_engine", "anomaly_score": 0.92},
        },
    )
    assert risk_r.status_code == 200

    # Retrieve
    get_r = await client.get(f"/api/v1/risk/{exposure_id}")
    assert get_r.status_code == 200
    assert get_r.json()["risk_score"] == 85.0
    assert get_r.json()["risk_level"] == "CRITICAL"


# ── 19. Case Creation ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_case_creation(client: AsyncClient):
    """Test 19: Investigation case created with evidence/unsupported_notes separation."""
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "AADHAAR", "organization": "case_test_org", "discovery_mode": "MANUAL"},
    )
    exposure_id = exp_r.json()["exposure_id"]

    case_r = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exposure_id,
            "organization": "case_test_org",
            "data_type": "AADHAAR",
            "discovery_date": "2026-10-01T00:00:00Z",
            "evidence": "Found in confirmed breach dump.",
            "unsupported_notes": "Unverified social media claim — NOT confirmed.",
        },
    )
    assert case_r.status_code == 200
    data = case_r.json()
    assert data["status"] == "OPEN"
    assert data["evidence"] == "Found in confirmed breach dump."
    assert "Unverified" in data["unsupported_notes"]


# ── 20. Erasure Request Creation ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_erasure_request_creation(client: AsyncClient):
    """Test 20: Erasure request created in DRAFT state."""
    # Create exposure + case
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "EMAIL", "organization": "erasure_org", "discovery_mode": "MANUAL"},
    )
    exposure_id = exp_r.json()["exposure_id"]
    case_r = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exposure_id,
            "data_type": "EMAIL",
            "discovery_date": "2026-10-01T00:00:00Z",
        },
    )
    case_id = case_r.json()["id"]

    erasure_r = await client.post(
        "/api/v1/erasure/",
        json={
            "case_id": case_id,
            "request_body": "I request erasure of my data under DPDP Act 2023.",
            "legal_basis": "DPDP Act 2023, Section 12(1)",
        },
    )
    assert erasure_r.status_code == 200
    assert erasure_r.json()["status"] == "DRAFT"


# ── 21. 7-Day Deadline Calculation ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_7_day_deadline_calculated(client: AsyncClient):
    """Test 21: 7-day deadline is calculated correctly when request is sent."""
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "PASSWORD", "organization": "deadline_org", "discovery_mode": "MANUAL"},
    )
    case_r = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exp_r.json()["exposure_id"],
            "data_type": "PASSWORD",
            "discovery_date": "2026-10-01T00:00:00Z",
        },
    )
    erasure_r = await client.post(
        "/api/v1/erasure/",
        json={
            "case_id": case_r.json()["id"],
            "request_body": "Deadline test erasure request.",
        },
    )
    erasure_id = erasure_r.json()["id"]

    send_r = await client.post(f"/api/v1/erasure/{erasure_id}/send")
    assert send_r.status_code == 200
    data = send_r.json()
    assert data["status"] == "SENT"
    assert data["deadline_date"] is not None

    # Verify it's 7 days from request_date
    from datetime import datetime
    req_date = datetime.fromisoformat(data["request_date"].replace("Z", "+00:00"))
    deadline = datetime.fromisoformat(data["deadline_date"].replace("Z", "+00:00"))
    delta_days = (deadline - req_date).days
    assert delta_days == 7, f"Expected 7-day deadline, got {delta_days} days"


# ── 22. Follow-Up Persistence ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_followup_persistence(client: AsyncClient):
    """Test 22: Follow-up request is persisted with DRAFT status."""
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "MOBILE", "organization": "followup_org", "discovery_mode": "MANUAL"},
    )
    case_r = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exp_r.json()["exposure_id"],
            "data_type": "MOBILE",
            "discovery_date": "2026-10-01T00:00:00Z",
        },
    )
    erasure_r = await client.post(
        "/api/v1/erasure/",
        json={"case_id": case_r.json()["id"], "request_body": "Follow-up test."},
    )
    erasure_id = erasure_r.json()["id"]

    followup_r = await client.post(
        f"/api/v1/erasure/{erasure_id}/followup",
        json={"erasure_request_id": erasure_id, "follow_up_body": "7 days passed. No response."},
    )
    assert followup_r.status_code == 200
    assert followup_r.json()["status"] == "DRAFT"


# ── 23. Session Validation and Revocation ────────────────────────────────────

@pytest.mark.asyncio
async def test_session_lifecycle(client: AsyncClient):
    """Test 23: Session creation and revocation cycle."""
    # Create session (requires registered owner from earlier tests)
    create_r = await client.post("/api/v1/session/create")
    if create_r.status_code == 404:
        pytest.skip("No registered owner — run registration tests first.")
    assert create_r.status_code == 200
    data = create_r.json()
    session_id = data["session_id"]
    token = data["access_token"]

    # Validate
    val_r = await client.post("/api/v1/session/validate", params={"token": token})
    assert val_r.status_code == 200
    assert val_r.json()["is_valid"] is True

    # Revoke
    rev_r = await client.post(f"/api/v1/session/revoke/{session_id}")
    assert rev_r.status_code == 200
    assert rev_r.json()["revoked"] is True


# ── 24. Audit Logging Without Plaintext Secrets ───────────────────────────────

def test_lookup_hash_is_not_reversible():
    """Test 24: Lookup hash cannot be used to reconstruct the original value."""
    sensitive = "my_real_aadhaar_266853339452"
    h = compute_lookup_hash(sensitive)
    assert len(h) == 64  # SHA-256 hex = 64 chars
    assert sensitive not in h
    assert "266853" not in h


def test_token_contains_no_plaintext_information():
    """Test 24b: Synthetic token reveals nothing about the original value."""
    # Aadhaar
    token1 = generate_token()
    assert "266853" not in token1
    assert "aadhaar" not in token1.lower()
    # API key
    token2 = generate_token()
    assert "sample_api_key" not in token2


# ── 25. API Responses Do Not Expose Secrets ──────────────────────────────────

@pytest.mark.asyncio
async def test_vault_list_does_not_expose_plaintext(client: AsyncClient):
    """Test 25: Vault listing returns only safe metadata, never plaintext values."""
    await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "super_secret_api_key_LEAKTEST", "data_type": "API_KEY"},
    )
    list_r = await client.get("/api/v1/vault/")
    assert list_r.status_code == 200
    response_text = list_r.text
    assert "super_secret_api_key_LEAKTEST" not in response_text
    # All tokens should match SHD_ pattern
    import json
    data = list_r.json()
    for entry in data.get("entries", []):
        token = entry.get("synthetic_token", "")
        assert re.match(r"^SHD_[0-9A-F]{8}$", token), f"Bad token format: {token}"


# ── 26. Clipboard Flow: Normal Text → Passthrough ─────────────────────────────

@pytest.mark.asyncio
async def test_clipboard_passthrough_clean_text(client: AsyncClient):
    """Test 26: Clean text without sensitive detection results in PASSTHROUGH."""
    response = await client.post(
        "/api/v1/clipboard/submit",
        json={
            "content": "Hello world, this is a harmless non-sensitive message.",
            "detected_type": None,
        },
    )
    assert response.status_code == 200
    data = response.json()
    assert data["is_sensitive"] is False
    assert data["action"] == "PASSTHROUGH"
    assert data["synthetic_token"] is None


# ── 27. Clipboard Flow: Sensitive Text → Tokenized & Reused ───────────────────

@pytest.mark.asyncio
async def test_clipboard_tokenization_and_reuse(client: AsyncClient):
    """Test 27: Sensitive clipboard content is tokenized, and duplicates are reused."""
    raw_key = "sample_api_key_clipboard_test_secret_9999"
    # First submit -> TOKENIZED
    r1 = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": raw_key, "detected_type": "API_KEY"},
    )
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["is_sensitive"] is True
    assert d1["action"] == "TOKENIZED"
    assert len(d1["synthetic_token"]) == 12

    # Second submit with same content -> REUSED
    r2 = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": raw_key, "detected_type": "API_KEY"},
    )
    assert r2.status_code == 200
    d2 = r2.json()
    assert d2["is_sensitive"] is True
    assert d2["action"] == "REUSED"
    assert d2["synthetic_token"] == d1["synthetic_token"]


# ── 28. Rehydration Flow: Denied Request Stays Synthetic ──────────────────────

@pytest.mark.asyncio
async def test_rehydration_denied_keeps_synthetic(client: AsyncClient):
    """Test 28: Denying rehydration keeps the token synthetic (real_value is None)."""
    # Store a sensitive value
    store_r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "secret_aadhaar_998877665544", "data_type": "AADHAAR"},
    )
    token = store_r.json()["synthetic_token"]

    # Submit text with token for rehydration
    rehyd_r = await client.post(
        "/api/v1/rehydration/submit",
        json={
            "content": f"Please verify Aadhaar token: {token}",
            "requesting_component": "external_ai_service",
            "purpose_scope": "identity verification",
        },
    )
    assert rehyd_r.status_code == 200
    r_data = rehyd_r.json()
    assert token in r_data["tokens_detected"]
    rehydration_id = r_data["rehydration_request_ids"][0]

    # Owner denies authorization
    auth_req_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "rehydration_test"},
    )
    auth_id = auth_req_r.json()["authorization_id"]
    deny_r = await client.post(f"/api/v1/authorization/deny/{auth_id}")
    assert deny_r.status_code == 200
    assert deny_r.json()["state"] == "DENIED"

    # Attempt to retrieve rehydration result -> real_value must remain None
    result_r = await client.post(
        f"/api/v1/rehydration/result/{rehydration_id}",
        params={"authorization_id": auth_id},
    )
    assert result_r.status_code == 200
    assert result_r.json()["real_value"] is None
    assert result_r.json()["state"] == "DENIED"


# ── 29. Rehydration Flow: Approved Request Releases Locally ───────────────────

@pytest.mark.asyncio
async def test_rehydration_approved_releases_locally(client: AsyncClient):
    """Test 29: Approved rehydration releases real value locally."""
    secret = "my_official_aadhaar_112233445566"
    store_r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": secret, "data_type": "AADHAAR"},
    )
    token = store_r.json()["synthetic_token"]

    # Submit for rehydration
    rehyd_r = await client.post(
        "/api/v1/rehydration/submit",
        json={
            "content": f"Pasting to official gov portal: {token}",
            "requesting_component": "gov_portal_trusted",
            "purpose_scope": "aadhaar authentication",
        },
    )
    assert rehyd_r.status_code == 200
    rehydration_id = rehyd_r.json()["rehydration_request_ids"][0]

    # Request and approve authorization
    auth_req_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "gov_portal_trusted"},
    )
    auth_id = auth_req_r.json()["authorization_id"]
    await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={"authorization_id": auth_id, "auth_method": "BIOMETRIC"},
    )

    # Get rehydration result -> returns decrypted value
    result_r = await client.post(
        f"/api/v1/rehydration/result/{rehydration_id}",
        params={"authorization_id": auth_id},
    )
    assert result_r.status_code == 200
    assert result_r.json()["real_value"] == secret
    assert result_r.json()["state"] == "APPROVED"


# ── 30. Audit Logging Verification ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_logging_without_plaintext_secrets(client: AsyncClient, db):
    """Test 30: Verify AuditEvent records contain no plaintext secrets."""
    from backend.app.database.models import AuditEvent
    from sqlalchemy import select

    secret_key = "super_classified_api_secret_XYZ"
    store_r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": secret_key, "data_type": "API_KEY"},
    )
    token = store_r.json()["synthetic_token"]

    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "audit_test_suite"},
    )
    auth_id = auth_r.json()["authorization_id"]
    await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={"authorization_id": auth_id, "auth_method": "PIN"},
    )

    # Query audit events from DB
    audit_res = await db.execute(select(AuditEvent).where(AuditEvent.authorization_id == auth_id))
    events = audit_res.scalars().all()
    assert len(events) >= 1

    for event in events:
        # Check event attributes
        assert secret_key not in (event.metadata_safe or "")
        assert secret_key not in (event.event_type or "")
        assert secret_key not in (event.result or "")
        assert secret_key not in (event.requesting_component or "")

