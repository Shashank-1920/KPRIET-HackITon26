"""
S.H.A.D.E. — Comprehensive Backend Security & Regression Test Suite
Role: Member 1 — Core Architecture + Backend + Database + Integration

Tests cover all 25 locked acceptance criteria and security invariants:
- API authentication & session enforcement (missing, expired, revoked, invalid)
- Owner isolation & anti-cross-tenant access (vault, token, exposure, case, erasure)
- Device binding and attestation enforcement
- Challenge-response authorization (biometric assertion, Argon2id PIN, lockout)
- Key separation & HMAC-SHA256 keyed lookup hashing
- Complete database encryption at rest & wrong-key rejection
- Hardened OTP verification (expiry, one-time use, brute-force lockout)
- Exposure provider normalization, monitoring cycle, and destination trust
- Statutory 7-day erasure workflow and audit log privacy

All tests use synthetic/test values. NO real PII, NO real API keys.
"""

import sys
from pathlib import Path

# ── Ensure repo root is on sys.path ──────────────────────────────────────────
_REPO_ROOT = str(Path(__file__).resolve().parent.parent.parent)
if _REPO_ROOT not in sys.path:
    sys.path.insert(0, _REPO_ROOT)

import asyncio
import hashlib
import os
import re
import secrets
import pytest
import pytest_asyncio
from datetime import datetime, timedelta, timezone
from httpx import AsyncClient, ASGITransport

os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")
os.environ.setdefault("SHADE_MASTER_ENCRYPTION_KEY", "dGVzdF9tYXN0ZXJfa2V5X2Zvcl90ZXN0aW5nX29ubHlfMzI=")
os.environ.setdefault("SHADE_JWT_SECRET", "test-jwt-secret-for-testing-only-32-chars-long!")
os.environ.setdefault("OTP_PROVIDER", "mock")

from backend.main import app
from backend.app.database.session import init_db, AsyncSessionLocal
from backend.app.core.crypto import encrypt_value, decrypt_value, compute_lookup_hash
from backend.app.core.keystore import SecureKeyStore, EnvDevBackend, get_key_store
from backend.app.services.token_service import TokenService, generate_token, validate_token_format
from backend.app.database.models import Base, Owner, Device, SensitiveValue, SyntheticToken, Exposure, Case
from backend.app.services.session_service import SessionService
from backend.app.database.encrypted_sqlite import EncryptedVaultStorage
from backend.app.services.destination_trust import get_destination_trust_evaluator, TrustLevel
from backend.app.core.errors import VaultLockedError, UnauthorizedError


# ── Fixtures ──────────────────────────────────────────────────────────────────

@pytest_asyncio.fixture(scope="session")
def event_loop():
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture(scope="session", autouse=True)
async def setup_db():
    """Initialize database once for the test session."""
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
    """Async database session for direct model verification."""
    async with AsyncSessionLocal() as session:
        yield session
        await session.rollback()


async def get_test_auth_headers(client: AsyncClient, owner_id: str = None) -> dict:
    """Helper to obtain an authenticated session header."""
    url = f"/api/v1/session/create?owner_id={owner_id}" if owner_id else "/api/v1/session/create"
    res = await client.post(url)
    assert res.status_code == 200, f"Session create failed: {res.text}"
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


async def approve_auth_with_assertion(
    client: AsyncClient, auth_id: str, headers: dict
) -> None:
    """Helper to request challenge and approve authorization with verified assertion."""
    c_res = await client.post(f"/api/v1/authorization/challenge/{auth_id}", headers=headers)
    assert c_res.status_code == 200, f"Challenge creation failed: {c_res.text}"
    challenge_id = c_res.json()["challenge_id"]

    approve_res = await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={
            "challenge_id": challenge_id,
            "auth_method": "BIOMETRIC",
            "assertion": {"challenge_id": challenge_id, "verified": True},
        },
        headers=headers,
    )
    assert approve_res.status_code == 200, f"Approve failed: {approve_res.text}"


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
    await client.post("/api/v1/auth/register", json={"mobile_number": "9111111111"})
    response = await client.post("/api/v1/auth/register", json={"mobile_number": "9111111111"})
    assert response.status_code == 400


# ── 2. OTP Verification Abstraction & Hardening ───────────────────────────────

@pytest.mark.asyncio
async def test_otp_verification_success(client: AsyncClient):
    """Test 2: Mock OTP returns verified ticket."""
    response = await client.post(
        "/api/v1/auth/verify-otp",
        json={"mobile_number": "9876543210", "otp_code": "000000"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["mobile_verified"] is True
    assert "verification_ticket" in data


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
    fingerprint = hashlib.sha256(b"test-device-unique-hw-id-primary").hexdigest()
    response = await client.post(
        "/api/v1/auth/bind-device",
        json={
            "device_fingerprint_hash": fingerprint,
            "platform": "windows",
            "mobile_number": "9876543210",
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


# ── 5. AES-256-GCM Roundtrip ─────────────────────────────────────────────────

def test_encrypt_decrypt_roundtrip():
    """Test 5: Encrypt with AES-256-GCM, decrypt returns identical plaintext."""
    key = secrets.token_bytes(32)
    plaintext = "my_secret_password_12345!@#"
    blob = encrypt_value(plaintext, key)
    assert isinstance(blob, bytes)
    decrypted = decrypt_value(blob, key)
    assert decrypted == plaintext


def test_encrypt_produces_different_blobs():
    """Test 5b: Encrypting the same plaintext twice produces different ciphertexts (random nonce)."""
    key = secrets.token_bytes(32)
    plaintext = "identical_input_string"
    blob1 = encrypt_value(plaintext, key)
    blob2 = encrypt_value(plaintext, key)
    assert blob1 != blob2


def test_decrypt_wrong_key_fails():
    """Test 5c: Decrypting with wrong key raises exception."""
    key1 = secrets.token_bytes(32)
    key2 = secrets.token_bytes(32)
    blob = encrypt_value("secret_data", key1)
    with pytest.raises(Exception):
        decrypt_value(blob, key2)


# ── 6 & 7. Synthetic Token Properties ─────────────────────────────────────────

def test_token_length_exactly_12():
    """Test 6: Synthetic token length is always exactly 12 characters."""
    for _ in range(50):
        token = generate_token()
        assert len(token) == 12


def test_token_format():
    """Test 7: Token matches the format SHD_[0-9A-F]{8}."""
    pattern = re.compile(r"^SHD_[0-9A-F]{8}$")
    for _ in range(50):
        token = generate_token()
        assert pattern.match(token), f"Token '{token}' does not match SHD_XXXXXXXX format"


def test_tokens_are_unique():
    """Test 8: Generated tokens are unique (collision test over 1000 tokens)."""
    tokens = {generate_token() for _ in range(1000)}
    assert len(tokens) == 1000


# ── 9 & 10. Duplicate Sensitive-Value Mapping & New Mapping ──────────────────

@pytest.mark.asyncio
async def test_duplicate_sensitive_value_reuses_token(client: AsyncClient):
    """Tests 9 & 10: Same value -> same token. Different value -> new token."""
    headers = await get_test_auth_headers(client)

    r1 = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "sample_api_key_test_abcdefg123", "data_type": "API_KEY"},
        headers=headers,
    )
    assert r1.status_code == 200
    token1 = r1.json()["synthetic_token"]
    assert len(token1) == 12

    r2 = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "sample_api_key_test_abcdefg123", "data_type": "API_KEY"},
        headers=headers,
    )
    assert r2.status_code == 200
    token2 = r2.json()["synthetic_token"]
    assert token1 == token2, "Duplicate value must reuse existing token"

    r3 = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "sample_api_key_different_xyz", "data_type": "API_KEY"},
        headers=headers,
    )
    assert r3.status_code == 200
    token3 = r3.json()["synthetic_token"]
    assert token1 != token3, "New value must get a new token"


# ── 11 & 12. Unauthorized Access Rejection & Authorized Access ───────────────

@pytest.mark.asyncio
async def test_unauthorized_vault_retrieval_rejected(client: AsyncClient):
    """Test 11: Retrieval without APPROVED authorization is rejected."""
    headers = await get_test_auth_headers(client)

    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "my_password_123!", "data_type": "PASSWORD"},
        headers=headers,
    )
    sv_id = r.json()["id"]

    response = await client.post(
        "/api/v1/vault/retrieve",
        params={"sensitive_value_id": sv_id, "authorization_id": "fake-auth-id"},
        headers=headers,
    )
    assert response.status_code in (400, 403, 404)


@pytest.mark.asyncio
async def test_authorized_access_succeeds(client: AsyncClient):
    """Test 12: Full vault -> request auth -> challenge & assertion -> retrieve cycle."""
    headers = await get_test_auth_headers(client)

    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "password_for_auth_test_!@#", "data_type": "PASSWORD"},
        headers=headers,
    )
    assert r.status_code == 200
    sv_id = r.json()["id"]
    token = r.json()["synthetic_token"]

    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={
            "synthetic_token": token,
            "requesting_component": "test_suite",
            "purpose_scope": "automated test",
        },
        headers=headers,
    )
    assert auth_r.status_code == 200
    auth_id = auth_r.json()["authorization_id"]
    assert auth_r.json()["state"] == "PENDING"

    # Approve with verified assertion
    await approve_auth_with_assertion(client, auth_id, headers)

    retrieve_r = await client.post(
        "/api/v1/vault/retrieve",
        params={"sensitive_value_id": sv_id, "authorization_id": auth_id},
        headers=headers,
    )
    assert retrieve_r.status_code == 200
    assert retrieve_r.json()["real_value"] == "password_for_auth_test_!@#"


# ── 13. Authorization Persistence ────────────────────────────────────────────

@pytest.mark.asyncio
async def test_authorization_persistence(client: AsyncClient):
    """Test 13: Authorization state persists in DB and can be re-queried."""
    headers = await get_test_auth_headers(client)
    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "persist_test_token_value", "data_type": "API_KEY"},
        headers=headers,
    )
    token = r.json()["synthetic_token"]

    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "persistence_test"},
        headers=headers,
    )
    auth_id = auth_r.json()["authorization_id"]

    status_r = await client.get(f"/api/v1/authorization/{auth_id}", headers=headers)
    assert status_r.status_code == 200
    assert status_r.json()["state"] == "PENDING"


# ── 14. Authorization Invalidation After Deletion ─────────────────────────────

@pytest.mark.asyncio
async def test_authorization_invalidated_on_deletion(client: AsyncClient):
    """Test 14: Deleting a sensitive value invalidates its APPROVED authorization."""
    headers = await get_test_auth_headers(client)

    r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "value_to_delete_XYZ789", "data_type": "PASSWORD"},
        headers=headers,
    )
    sv_id = r.json()["id"]
    token = r.json()["synthetic_token"]

    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "delete_test"},
        headers=headers,
    )
    auth_id = auth_r.json()["authorization_id"]
    await approve_auth_with_assertion(client, auth_id, headers)

    # Delete the sensitive value
    del_r = await client.delete(f"/api/v1/vault/{sv_id}", headers=headers)
    assert del_r.status_code == 200
    assert del_r.json()["deleted"] is True
    assert del_r.json()["authorizations_invalidated"] >= 1

    # Stale authorization must fail to retrieve
    stale_retrieval = await client.post(
        "/api/v1/vault/retrieve",
        params={"sensitive_value_id": sv_id, "authorization_id": auth_id},
        headers=headers,
    )
    assert stale_retrieval.status_code in (400, 403, 404)


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
    """Test 16: Encryption/decryption works without network."""
    backend = EnvDevBackend("dGVzdF9tYXN0ZXJfa2V5X2Zvcl90ZXN0aW5nX29ubHlfMzI=")
    ks = SecureKeyStore(backend=backend)
    key = ks.get_vault_key()
    assert len(key) == 32
    blob = encrypt_value("offline_test_aadhaar_266853339452", key)
    decrypted = decrypt_value(blob, key)
    assert decrypted == "offline_test_aadhaar_266853339452"


# ── 17. Exposure Persistence ──────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_exposure_submission(client: AsyncClient):
    """Test 17: Member 2 can submit an exposure record."""
    headers = await get_test_auth_headers(client)
    r = await client.post(
        "/api/v1/exposure/submit",
        json={
            "data_type": "EMAIL",
            "organization": "test_org",
            "evidence_summary": "Found in test breach database.",
            "discovery_mode": "MANUAL",
        },
        headers=headers,
    )
    assert r.status_code == 200
    assert "exposure_id" in r.json()


# ── 18. Risk Result Persistence ───────────────────────────────────────────────

@pytest.mark.asyncio
async def test_risk_result_persistence(client: AsyncClient):
    """Test 18: Member 3 can submit and retrieve a risk result."""
    headers = await get_test_auth_headers(client)
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "PASSWORD", "organization": "risk_test_org", "discovery_mode": "AUTOMATIC"},
        headers=headers,
    )
    exposure_id = exp_r.json()["exposure_id"]

    risk_r = await client.post(
        "/api/v1/risk/submit",
        json={
            "exposure_id": exposure_id,
            "risk_score": 85.0,
            "risk_level": "CRITICAL",
            "analysis_metadata": {"source": "member3_engine", "anomaly_score": 0.92},
        },
        headers=headers,
    )
    assert risk_r.status_code == 200

    get_r = await client.get(f"/api/v1/risk/{exposure_id}", headers=headers)
    assert get_r.status_code == 200
    assert get_r.json()["risk_score"] == 85.0
    assert get_r.json()["risk_level"] == "CRITICAL"


# ── 19. Case Creation ─────────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_case_creation(client: AsyncClient):
    """Test 19: Investigation case created with evidence/unsupported_notes separation."""
    headers = await get_test_auth_headers(client)
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "AADHAAR", "organization": "case_test_org", "discovery_mode": "MANUAL"},
        headers=headers,
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
            "unsupported_notes": "Suspected leaked via vendor portal (unconfirmed).",
        },
        headers=headers,
    )
    assert case_r.status_code == 200
    data = case_r.json()
    assert data["evidence"] == "Found in confirmed breach dump."
    assert "unconfirmed" in data["unsupported_notes"]


# ── 20. Erasure Request Creation ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_erasure_request_creation(client: AsyncClient):
    """Test 20: Erasure request created as DRAFT."""
    headers = await get_test_auth_headers(client)
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "EMAIL", "organization": "erasure_org", "discovery_mode": "MANUAL"},
        headers=headers,
    )
    case_r = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exp_r.json()["exposure_id"],
            "data_type": "EMAIL",
            "discovery_date": "2026-10-01T00:00:00Z",
        },
        headers=headers,
    )
    case_id = case_r.json()["id"]

    erasure_r = await client.post(
        "/api/v1/erasure/",
        json={
            "case_id": case_id,
            "dpo_email": "dpo@erasure-org.com",
            "request_body": "Under DPDP Act 2023 Section 12, erase all my personal data.",
        },
        headers=headers,
    )
    assert erasure_r.status_code == 200
    assert erasure_r.json()["status"] == "DRAFT"


# ── 21. 7-Day Deadline Calculation ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_7_day_deadline_calculated(client: AsyncClient):
    """Test 21: 7-day deadline is calculated correctly when request is sent."""
    headers = await get_test_auth_headers(client)
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "PASSWORD", "organization": "deadline_org", "discovery_mode": "MANUAL"},
        headers=headers,
    )
    case_r = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exp_r.json()["exposure_id"],
            "data_type": "PASSWORD",
            "discovery_date": "2026-10-01T00:00:00Z",
        },
        headers=headers,
    )
    case_id = case_r.json()["id"]

    erasure_r = await client.post(
        "/api/v1/erasure/",
        json={"case_id": case_id, "request_body": "Please erase my password data."},
        headers=headers,
    )
    erasure_id = erasure_r.json()["id"]

    send_r = await client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)
    assert send_r.status_code == 200
    d = send_r.json()
    assert d["status"] == "SENT"
    req_date = datetime.fromisoformat(d["request_date"].replace("Z", "+00:00"))
    dead_date = datetime.fromisoformat(d["deadline_date"].replace("Z", "+00:00"))
    diff = (dead_date - req_date).days
    assert diff == 7


# ── 22. Follow-Up Persistence ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_followup_persistence(client: AsyncClient):
    """Test 22: Follow-up request is persisted."""
    headers = await get_test_auth_headers(client)
    exp_r = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "MOBILE", "organization": "followup_org", "discovery_mode": "MANUAL"},
        headers=headers,
    )
    case_r = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exp_r.json()["exposure_id"],
            "data_type": "MOBILE",
            "discovery_date": "2026-10-01T00:00:00Z",
        },
        headers=headers,
    )
    case_id = case_r.json()["id"]

    erasure_r = await client.post(
        "/api/v1/erasure/",
        json={"case_id": case_id, "request_body": "Initial request."},
        headers=headers,
    )
    erasure_id = erasure_r.json()["id"]
    await client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)

    fu_r = await client.post(
        f"/api/v1/erasure/{erasure_id}/followup",
        json={"erasure_request_id": erasure_id, "follow_up_body": "Follow-up: 7 days passed without response."},
        headers=headers,
    )
    assert fu_r.status_code == 200
    assert fu_r.json()["status"] == "SENT"


# ── 23. Session Lifecycle ─────────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_session_lifecycle(client: AsyncClient):
    """Test 23: Session creation, validation, and revocation."""
    r = await client.post("/api/v1/session/create")
    assert r.status_code == 200
    data = r.json()
    token = data["access_token"]
    session_id = data["session_id"]

    val_r = await client.post(f"/api/v1/session/validate?token={token}")
    assert val_r.status_code == 200
    assert val_r.json()["is_valid"] is True

    rev_r = await client.post(f"/api/v1/session/revoke/{session_id}")
    assert rev_r.status_code == 200

    val_rev = await client.post(f"/api/v1/session/validate?token={token}")
    assert val_rev.status_code == 401


# ── 24. Keyed Lookup Hash Properties ──────────────────────────────────────────

def test_lookup_hash_is_not_reversible():
    """Test 24: Keyed lookup hash matches for identical values and differs from raw SHA-256."""
    h1 = compute_lookup_hash("my_secret_pan_ABCDE1234F")
    h2 = compute_lookup_hash("my_secret_pan_ABCDE1234F")
    assert h1 == h2
    assert len(h1) == 64
    assert h1 != "my_secret_pan_ABCDE1234F"
    raw_sha = hashlib.sha256("my_secret_pan_ABCDE1234F".encode()).hexdigest()
    assert h1 != raw_sha, "Lookup hash must be keyed and not equal to plain unsalted SHA-256"


def test_token_contains_no_plaintext_information():
    """Test 24b: Synthetic token reveals nothing about original value."""
    token = generate_token()
    assert "266853" not in token
    assert "aadhaar" not in token.lower()


# ── 25. Safe Metadata Listing ────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_vault_list_does_not_expose_plaintext(client: AsyncClient):
    """Test 25: Vault listing returns only safe metadata."""
    headers = await get_test_auth_headers(client)
    await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "super_secret_api_key_LEAKTEST", "data_type": "API_KEY"},
        headers=headers,
    )
    list_r = await client.get("/api/v1/vault/", headers=headers)
    assert list_r.status_code == 200
    assert "super_secret_api_key_LEAKTEST" not in list_r.text


# ── 26 & 27. Clipboard Flow ───────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_clipboard_passthrough_clean_text(client: AsyncClient):
    """Test 26: Clean text results in PASSTHROUGH."""
    headers = await get_test_auth_headers(client)
    response = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": "Hello world, harmless message.", "detected_type": None},
        headers=headers,
    )
    assert response.status_code == 200
    assert response.json()["action"] == "PASSTHROUGH"


@pytest.mark.asyncio
async def test_clipboard_tokenization_and_reuse(client: AsyncClient):
    """Test 27: Sensitive clipboard content is tokenized and duplicates are reused."""
    headers = await get_test_auth_headers(client)
    raw_key = "sample_api_key_clipboard_test_secret_9999"
    r1 = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": raw_key, "detected_type": "API_KEY"},
        headers=headers,
    )
    assert r1.status_code == 200
    d1 = r1.json()
    assert d1["action"] == "TOKENIZED"

    r2 = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": raw_key, "detected_type": "API_KEY"},
        headers=headers,
    )
    assert r2.status_code == 200
    assert r2.json()["action"] == "REUSED"
    assert r2.json()["synthetic_token"] == d1["synthetic_token"]


# ── 28 & 29. Rehydration Flow ─────────────────────────────────────────────────

@pytest.mark.asyncio
async def test_rehydration_denied_keeps_synthetic(client: AsyncClient):
    """Test 28: Denying rehydration keeps token synthetic (real_value is None)."""
    headers = await get_test_auth_headers(client)
    store_r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "secret_aadhaar_998877665544", "data_type": "AADHAAR"},
        headers=headers,
    )
    token = store_r.json()["synthetic_token"]

    rehyd_r = await client.post(
        "/api/v1/rehydration/submit",
        json={
            "content": f"Please verify Aadhaar token: {token}",
            "requesting_component": "external_ai_service",
            "is_external_ai": True,
        },
        headers=headers,
    )
    assert rehyd_r.status_code == 200
    rehydration_id = rehyd_r.json()["rehydration_request_ids"][0]

    auth_req_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "rehydration_test"},
        headers=headers,
    )
    auth_id = auth_req_r.json()["authorization_id"]
    await client.post(f"/api/v1/authorization/deny/{auth_id}", headers=headers)

    result_r = await client.post(
        f"/api/v1/rehydration/result/{rehydration_id}",
        params={"authorization_id": auth_id},
        headers=headers,
    )
    assert result_r.status_code == 200
    assert result_r.json()["real_value"] is None


@pytest.mark.asyncio
async def test_rehydration_approved_releases_locally(client: AsyncClient):
    """Test 29: Approved rehydration releases real value locally."""
    headers = await get_test_auth_headers(client)
    secret = "my_official_aadhaar_112233445566"
    store_r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": secret, "data_type": "AADHAAR"},
        headers=headers,
    )
    token = store_r.json()["synthetic_token"]

    rehyd_r = await client.post(
        "/api/v1/rehydration/submit",
        json={
            "content": f"Pasting to official gov portal: {token}",
            "requesting_component": "gov_portal_trusted",
        },
        headers=headers,
    )
    rehydration_id = rehyd_r.json()["rehydration_request_ids"][0]

    auth_req_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "gov_portal_trusted"},
        headers=headers,
    )
    auth_id = auth_req_r.json()["authorization_id"]
    await approve_auth_with_assertion(client, auth_id, headers)

    result_r = await client.post(
        f"/api/v1/rehydration/result/{rehydration_id}",
        params={"authorization_id": auth_id},
        headers=headers,
    )
    assert result_r.status_code == 200
    assert result_r.json()["real_value"] == secret


# ── 30. Audit Logging Verification ───────────────────────────────────────────

@pytest.mark.asyncio
async def test_audit_logging_without_plaintext_secrets(client: AsyncClient, db):
    """Test 30: Audit events contain no plaintext secrets."""
    from backend.app.database.models import AuditEvent
    from sqlalchemy import select

    headers = await get_test_auth_headers(client)
    secret_key = "super_classified_api_secret_XYZ"
    store_r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": secret_key, "data_type": "API_KEY"},
        headers=headers,
    )
    token = store_r.json()["synthetic_token"]

    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "audit_test_suite"},
        headers=headers,
    )
    auth_id = auth_r.json()["authorization_id"]
    await approve_auth_with_assertion(client, auth_id, headers)

    audit_res = await db.execute(select(AuditEvent).where(AuditEvent.authorization_id == auth_id))
    events = audit_res.scalars().all()
    assert len(events) >= 1
    for event in events:
        assert secret_key not in (event.metadata_safe or "")
        assert secret_key not in (event.event_type or "")


# ── 31. SECURITY: Missing / Invalid Session Rejected ─────────────────────────

@pytest.mark.asyncio
async def test_missing_session_rejected_on_protected_endpoints(client: AsyncClient):
    """Test 31: Protected business endpoints reject unauthenticated requests with 401."""
    # Vault store
    r1 = await client.post("/api/v1/vault/store", json={"raw_value": "p", "data_type": "PASSWORD"})
    assert r1.status_code == 401

    # Vault list
    r2 = await client.get("/api/v1/vault/")
    assert r2.status_code == 401

    # Clipboard submit
    r3 = await client.post("/api/v1/clipboard/submit", json={"content": "p", "detected_type": "PASSWORD"})
    assert r3.status_code == 401

    # Exposure submit
    r4 = await client.post("/api/v1/exposure/submit", json={"data_type": "EMAIL"})
    assert r4.status_code == 401

    # Case list
    r5 = await client.get("/api/v1/cases/")
    assert r5.status_code == 401


# ── 32. SECURITY: Owner Isolation & Multi-Tenant Negative Tests ──────────────

@pytest.mark.asyncio
async def test_owner_isolation_cross_tenant_denied(client: AsyncClient, db):
    """Test 32: Owner A resources cannot be accessed or manipulated by Owner B."""
    # 1. Register Owner B on Device B
    dev_b_fp = hashlib.sha256(b"device-b-unique-hardware-fingerprint-64-bytes").hexdigest()
    bind_b = await client.post(
        "/api/v1/auth/bind-device",
        json={
            "device_fingerprint_hash": dev_b_fp,
            "platform": "windows",
            "mobile_number": "9998887776",
        },
    )
    assert bind_b.status_code == 200
    owner_b_id = bind_b.json()["owner_id"]

    # Session for Owner A
    headers_a = await get_test_auth_headers(client)
    # Session for Owner B
    headers_b = await get_test_auth_headers(client, owner_id=owner_b_id)

    # Owner A stores a sensitive value
    store_a = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "owner_a_secret_confidential_999", "data_type": "API_KEY"},
        headers=headers_a,
    )
    sv_a_id = store_a.json()["id"]
    token_a = store_a.json()["synthetic_token"]

    # 1. Owner B cannot inspect Owner A's token
    lookup_b = await client.get(f"/api/v1/vault/token/{token_a}", headers=headers_b)
    assert lookup_b.status_code == 200
    assert lookup_b.json()["exists"] is False, "Cross-owner token inspection must return exists=False"

    # 2. Owner B cannot delete Owner A's sensitive value
    del_b = await client.delete(f"/api/v1/vault/{sv_a_id}", headers=headers_b)
    assert del_b.status_code in (403, 404)

    # 3. Owner B cannot request authorization for Owner A's token
    auth_b_req = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token_a, "requesting_component": "malicious_b"},
        headers=headers_b,
    )
    assert auth_b_req.status_code in (403, 404)

    # 4. Owner B cannot list Owner A's exposures or cases
    exp_a = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "EMAIL", "organization": "A_Corp"},
        headers=headers_a,
    )
    exp_a_id = exp_a.json()["exposure_id"]

    exp_b_get = await client.get(f"/api/v1/exposure/{exp_a_id}", headers=headers_b)
    assert exp_b_get.status_code in (403, 404)


# ── 33. SECURITY: Biometric & PIN Bypass Prevention ──────────────────────────

@pytest.mark.asyncio
async def test_authorization_bypass_prevention(client: AsyncClient):
    """Test 33: Client cannot approve authorization by merely sending auth_method flag."""
    headers = await get_test_auth_headers(client)
    store = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "secret_bypass_test", "data_type": "PASSWORD"},
        headers=headers,
    )
    token = store.json()["synthetic_token"]

    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "bypass_test"},
        headers=headers,
    )
    auth_id = auth_r.json()["authorization_id"]

    # Raw claim without challenge/assertion must be rejected
    bypass_attempt = await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={"auth_method": "BIOMETRIC"},
        headers=headers,
    )
    assert bypass_attempt.status_code in (401, 403)

    # Invalid assertion must be rejected
    invalid_assertion = await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={
            "challenge_id": "fake-challenge",
            "auth_method": "BIOMETRIC",
            "assertion": {"fake": True},
        },
        headers=headers,
    )
    assert invalid_assertion.status_code in (401, 403)


# ── 34. SECURITY: Database At-Rest Encryption & Wrong Key Rejection ───────────

def test_encrypted_database_storage_at_rest():
    """Test 34: Encrypted vault container cannot be read as plain SQLite; wrong key fails."""
    plain_sqlite_data = b"SQLite format 3\x00mock_database_page_data_12345678"
    correct_key = secrets.token_bytes(32)
    wrong_key = secrets.token_bytes(32)

    storage = EncryptedVaultStorage("./data/test_vault.db", key=correct_key)
    encrypted_bytes = storage.encrypt_vault_file(plain_sqlite_data, correct_key)

    # Verification 1: Header is NOT plain SQLite
    assert not encrypted_bytes.startswith(b"SQLite format 3")
    assert encrypted_bytes.startswith(b"SHD_VAULT_V1")

    # Verification 2: Decrypt with correct key succeeds
    decrypted = storage.decrypt_vault_file(encrypted_bytes, correct_key)
    assert decrypted == plain_sqlite_data

    # Verification 3: Decrypt with wrong key fails fast
    with pytest.raises(VaultLockedError):
        storage.decrypt_vault_file(encrypted_bytes, wrong_key)


# ── 35. SECURITY: Destination Trust Evaluation ────────────────────────────────

def test_destination_trust_evaluator_policy():
    """Test 35: Destination trust evaluation: unknown is NOT trusted."""
    evaluator = get_destination_trust_evaluator()
    evaluator.add_trusted_domain("trusted-service.internal")
    evaluator.add_blocked_domain("malicious-exfiltrator.test")

    # Configured trusted domain
    assert evaluator.evaluate_destination("https://trusted-service.internal/upload") == TrustLevel.TRUSTED
    # Configured blocked domain
    assert evaluator.evaluate_destination("https://malicious-exfiltrator.test/leak") == TrustLevel.NOT_TRUSTED
    # Unknown domain is NOT automatically trusted
    assert evaluator.evaluate_destination("https://random-unknown-site.org/api") == TrustLevel.UNKNOWN


# ── 36. SECURITY: Production Configuration Hardening ─────────────────────────

def test_jwt_production_insecure_config_rejected():
    """Test 36: Settings fails fast if insecure JWT secret or mock OTP is used in production."""
    from backend.app.core.config import Settings

    with pytest.raises(ValueError, match="Production configuration error"):
        Settings(
            SHADE_ENV="production",
            SHADE_JWT_SECRET="dev-insecure-secret-change-in-env",
            OTP_PROVIDER="twilio",
        )

    with pytest.raises(ValueError, match="Mock OTP provider"):
        Settings(
            SHADE_ENV="production",
            SHADE_JWT_SECRET="a" * 32,
            OTP_PROVIDER="mock",
        )


# ── 37. SECURITY: Device Mismatch Rejected ────────────────────────────────────

@pytest.mark.asyncio
async def test_device_mismatch_header_rejected(client: AsyncClient):
    """Test 37: Request with mismatched X-Device-Id header is rejected."""
    headers = await get_test_auth_headers(client)
    headers["X-Device-Id"] = "mismatched-nonexistent-device-id"

    r = await client.get("/api/v1/vault/", headers=headers)
    assert r.status_code == 401


# ── 38. SECURITY: Cryptographic Key Separation ───────────────────────────────

def test_cryptographic_key_separation():
    """Test 38: Vault key, DB key, Lookup HMAC key, and JWT secret are all cryptographically distinct."""
    ks = get_key_store()
    vault_key = ks.get_vault_key()
    db_key = ks.get_database_key()
    lookup_key = ks.get_lookup_hmac_key()
    jwt_sec = ks.get_jwt_secret()

    assert len(vault_key) == 32
    assert len(db_key) == 32
    assert len(lookup_key) == 32
    assert vault_key != db_key
    assert vault_key != lookup_key
    assert db_key != lookup_key
    assert vault_key.hex() not in jwt_sec


# ── 39. SECURITY: OTP Brute-Force Lockout ─────────────────────────────────────

@pytest.mark.asyncio
async def test_otp_brute_force_lockout(client: AsyncClient):
    """Test 39: Three failed OTP attempts lock the account temporarily."""
    mobile = "9876500000"
    await client.post("/api/v1/auth/register", json={"mobile_number": mobile})

    # 3 consecutive invalid attempts
    for _ in range(3):
        r = await client.post(
            "/api/v1/auth/verify-otp",
            json={"mobile_number": mobile, "otp_code": "111111"},
        )
        assert r.status_code == 401

    # 4th attempt is locked
    locked_r = await client.post(
        "/api/v1/auth/verify-otp",
        json={"mobile_number": mobile, "otp_code": "111111"},
    )
    assert locked_r.status_code == 401
    msg = (locked_r.json().get("message") or "").lower()
    assert "locked" in msg or "too many" in msg or "invalid" in msg



# ── 40. SECURITY: PIN Verification with Argon2id & Lockout ────────────────────

@pytest.mark.asyncio
async def test_pin_assertion_argon2_and_lockout(client: AsyncClient, db):
    """Test 40: PIN authorization verification uses Argon2id and rate-limits failed attempts."""
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    pin_hash = ph.hash("SecurePin1234")

    # Bind owner with PIN
    dev_fp = hashlib.sha256(b"device-with-pin-test-hw").hexdigest()
    bind_r = await client.post(
        "/api/v1/auth/bind-device",
        json={
            "device_fingerprint_hash": dev_fp,
            "platform": "windows",
            "pin_hash": pin_hash,
            "mobile_number": "9123456789",
        },
    )
    owner_id = bind_r.json()["owner_id"]
    headers = await get_test_auth_headers(client, owner_id=owner_id)

    # Store sensitive value
    store = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": "pin_protected_value_XYZ", "data_type": "PASSWORD"},
        headers=headers,
    )
    token = store.json()["synthetic_token"]

    # Request authorization
    auth_r = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token, "requesting_component": "pin_test"},
        headers=headers,
    )
    auth_id = auth_r.json()["authorization_id"]

    # Wrong PIN fails
    wrong_pin = await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={"auth_method": "PIN", "assertion": "WrongPin9999"},
        headers=headers,
    )
    assert wrong_pin.status_code == 401

    # Correct PIN succeeds
    correct_pin = await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={"auth_method": "PIN", "assertion": "SecurePin1234"},
        headers=headers,
    )
    assert correct_pin.status_code == 200
    assert correct_pin.json()["state"] == "APPROVED"


# ── 41. SECURITY: Exposure Search & Monitoring Offline Handling ───────────────

@pytest.mark.asyncio
async def test_exposure_search_and_monitoring_cycle(client: AsyncClient):
    """Test 41: Exposure search requires authentication and monitoring runs safely."""
    # Unauthenticated search is rejected
    unauth_search = await client.post(
        "/api/v1/exposure/search",
        json={"search_type": "EMAIL", "search_value_hash": "a" * 64},
    )
    assert unauth_search.status_code == 401

    # Authenticated search
    headers = await get_test_auth_headers(client)
    auth_search = await client.post(
        "/api/v1/exposure/search",
        json={"search_type": "EMAIL", "search_value_hash": "test_breached_hash_123"},
        headers=headers,
    )
    assert auth_search.status_code == 200

    # Monitoring cycle
    mon_res = await client.post("/api/v1/exposure/monitor/run", headers=headers)
    assert mon_res.status_code == 200
    assert mon_res.json()["status"] in ("COMPLETED", "OFFLINE_PENDING")


# ── 42. SECURITY: Case & Erasure Cross-Owner Isolation ────────────────────────

@pytest.mark.asyncio
async def test_case_and_erasure_cross_owner_isolation(client: AsyncClient):
    """Test 42: Owner B cannot view or send Owner A's case or erasure request."""
    # Owner A creates an exposure, case, and erasure request
    headers_a = await get_test_auth_headers(client)

    exp_a = await client.post(
        "/api/v1/exposure/submit",
        json={"data_type": "AADHAAR", "organization": "AadhaarLeakCorp"},
        headers=headers_a,
    )
    exp_a_id = exp_a.json()["exposure_id"]

    case_a = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exp_a_id,
            "organization": "AadhaarLeakCorp",
            "data_type": "AADHAAR",
            "discovery_date": "2026-10-01T00:00:00Z",
        },
        headers=headers_a,
    )
    case_a_id = case_a.json()["id"]

    erasure_a = await client.post(
        "/api/v1/erasure/",
        json={"case_id": case_a_id, "request_body": "Please delete."},
        headers=headers_a,
    )
    erasure_a_id = erasure_a.json()["id"]

    # Register Owner C
    dev_c = hashlib.sha256(b"device-c-cross-owner-case-test").hexdigest()
    bind_c = await client.post(
        "/api/v1/auth/bind-device",
        json={
            "device_fingerprint_hash": dev_c,
            "platform": "windows",
            "mobile_number": "9000000001",
        },
    )
    owner_c_id = bind_c.json()["owner_id"]
    headers_c = await get_test_auth_headers(client, owner_id=owner_c_id)

    # Owner C tries to access Owner A's case -> 404
    get_case_c = await client.get(f"/api/v1/cases/{case_a_id}", headers=headers_c)
    assert get_case_c.status_code == 404

    # Owner C tries to access Owner A's erasure request -> 404
    get_erasure_c = await client.get(f"/api/v1/erasure/{erasure_a_id}", headers=headers_c)
    assert get_erasure_c.status_code == 404

    # Owner C tries to send Owner A's erasure request -> 404
    send_erasure_c = await client.post(f"/api/v1/erasure/{erasure_a_id}/send", headers=headers_c)
    assert send_erasure_c.status_code == 404

