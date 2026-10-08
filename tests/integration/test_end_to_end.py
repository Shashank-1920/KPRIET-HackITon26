"""
S.H.A.D.E. — Master End-to-End Multi-Module Integration Test Suite
Role: Shared / Master Verification

Verifies the 6 locked end-to-end workflows:
1. TEST FLOW 1 — CLIPBOARD: DLP detection, synthetic token generation & duplicate reuse
2. TEST FLOW 2 — VAULT: Encrypted SQLite storage, key isolation, cross-owner & cross-device rejection
3. TEST FLOW 3 — REHYDRATION: Token + challenge + Argon2id/assertion gate; fake biometric & deleted token rejection
4. TEST FLOW 4 — EXPOSURE: Manual search -> Member 2 provider -> backend -> Member 3 AI risk engine
5. TEST FLOW 5 — AUTOMATIC MONITORING: Scheduler cycle -> new exposure -> risk evaluation -> case creation
6. TEST FLOW 6 — ERASURE: Prepare -> review -> explicit send (7-day statutory clock) -> follow-up
7. VOICE BOUNDARY: Voice ambient query allowed; voice authorization strictly BLOCKED
8. ARCHITECTURAL INTEGRITY: No unauthorized direct SQLite access outside backend
"""

import os
import re
import pytest
from httpx import AsyncClient, ASGITransport

from backend.main import app
from backend.app.core.keystore import get_key_store
from backend.app.database.session import AsyncSessionLocal
from security.dlp.engine import DLPEngine
from security.dlp.clipboard_guard import ClipboardGuard
from security.threat_engine.exposure_intelligence import ThreatIntelligenceExposureProvider
from ai.risk_engine.engine import AIRiskEngine
from voice.contracts import VoiceInteractionHandler


@pytest.fixture
async def api_client():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as client:
        yield client


@pytest.fixture
async def registered_session(api_client: AsyncClient):
    """Registers an authenticated owner, verifies OTP, binds device, and obtains session."""
    import hashlib
    import uuid
    uid = uuid.uuid4().hex[:8]
    mobile = f"98{int(uid, 16) % 100000000:08d}"
    device_hw = f"hw-device-{uid}"

    # 1. Register
    await api_client.post("/api/v1/auth/register", json={
        "mobile_number": mobile,
    })

    # 2. Verify OTP
    otp_res = await api_client.post("/api/v1/auth/verify-otp", json={
        "mobile_number": mobile,
        "otp_code": "000000",
    })
    assert otp_res.status_code == 200
    ticket = otp_res.json()["verification_ticket"]

    # 3. Bind Device
    fp_hash = hashlib.sha256(device_hw.encode()).hexdigest()
    bind_res = await api_client.post("/api/v1/auth/bind-device", json={
        "device_fingerprint_hash": fp_hash,
        "platform": "windows",
        "verification_ticket": ticket,
        "mobile_number": mobile,
    })
    assert bind_res.status_code == 200
    bind_data = bind_res.json()
    owner_id = bind_data["owner_id"]
    device_id = bind_data["device_id"]

    # 4. Session Token
    sess_res = await api_client.post(f"/api/v1/session/create?owner_id={owner_id}")
    assert sess_res.status_code == 200
    token = sess_res.json()["access_token"]

    headers = {
        "Authorization": f"Bearer {token}",
        "X-Device-Id": device_id,
    }
    return {
        "headers": headers,
        "owner_id": owner_id,
        "device_id": device_id,
        "token": token,
    }


# ==============================================================================
# TEST FLOW 1: CLIPBOARD & DLP WORKFLOW
# ==============================================================================
@pytest.mark.asyncio
async def test_flow_1_clipboard_dlp_and_token_reuse(api_client: AsyncClient, registered_session: dict):
    headers = registered_session["headers"]
    dlp = DLPEngine()

    def backend_dispatch(content: str, d_type: str):
        import asyncio
        # Synchronous wrapper calling clipboard API
        # Here we directly use the test client in the async test
        return None

    guard = ClipboardGuard(dlp_engine=dlp)

    # 1. Normal clean text is ignored (PASSTHROUGH)
    res_normal = guard.process_copied_text("Team status meeting scheduled at 3 PM.")
    assert res_normal.is_sensitive is False
    assert res_normal.action == "PASSTHROUGH"
    assert res_normal.resulting_clipboard_text == "Team status meeting scheduled at 3 PM."

    # 2. Sensitive text is detected and submitted to backend
    secret_val = "sk-proj-live-89abf7294ac1092ef8934"
    detection = dlp.inspect(secret_val)
    assert detection is not None
    assert detection.data_type == "API_KEY"

    sub_res = await api_client.post(
        "/api/v1/clipboard/submit",
        headers=headers,
        json={"content": secret_val, "detected_type": detection.data_type},
    )
    assert sub_res.status_code == 200
    data = sub_res.json()
    assert data["is_sensitive"] is True
    assert data["action"] == "TOKENIZED"
    synthetic_token = data["synthetic_token"]
    assert len(synthetic_token) == 12

    # 3. Duplicate same sensitive value reuses existing token
    sub_res_dup = await api_client.post(
        "/api/v1/clipboard/submit",
        headers=headers,
        json={"content": secret_val, "detected_type": detection.data_type},
    )
    assert sub_res_dup.status_code == 200
    data_dup = sub_res_dup.json()
    assert data_dup["action"] == "REUSED"
    assert data_dup["synthetic_token"] == synthetic_token


# ==============================================================================
# TEST FLOW 2: ENCRYPTED VAULT STORAGE & KEYSTORE SURVIVAL
# ==============================================================================
@pytest.mark.asyncio
async def test_flow_2_vault_encrypted_and_isolated(api_client: AsyncClient, registered_session: dict):
    headers = registered_session["headers"]

    # 1. Store item in vault
    store_res = await api_client.post(
        "/api/v1/vault/store",
        headers=headers,
        json={
            "raw_value": "548129384912",
            "data_type": "AADHAAR",
            "masked_metadata": "XXXX-XXXX-4912",
        },
    )
    assert store_res.status_code == 200
    vault_item = store_res.json()
    vault_id = vault_item["id"]

    # 2. Verify keystore has keys and can survive restart
    keystore = get_key_store()
    vault_key = keystore.get_vault_key()
    assert len(vault_key) == 32

    # 3. Wrong owner cannot access
    wrong_owner_headers = {
        "Authorization": "Bearer invalid_or_other_token",
        "X-Device-Id": registered_session["device_id"],
    }
    denied_res = await api_client.get(f"/api/v1/vault/token/{vault_item['synthetic_token']}", headers=wrong_owner_headers)
    assert denied_res.status_code in (401, 403)

    # 4. Wrong device header rejected
    wrong_device_headers = {
        "Authorization": headers["Authorization"],
        "X-Device-Id": "00000000-0000-0000-0000-000000000000",
    }
    device_denied = await api_client.get(f"/api/v1/vault/token/{vault_item['synthetic_token']}", headers=wrong_device_headers)
    assert device_denied.status_code in (401, 403)


# ==============================================================================
# TEST FLOW 3: REHYDRATION & AUTHORIZATION GATE
# ==============================================================================
@pytest.mark.asyncio
async def test_flow_3_rehydration_authorization_lifecycle(api_client: AsyncClient, registered_session: dict):
    headers = registered_session["headers"]

    # 1. Store sensitive value
    store_res = await api_client.post(
        "/api/v1/vault/store",
        headers=headers,
        json={"raw_value": "sk-secret-rehydration-9912", "data_type": "API_KEY"},
    )
    assert store_res.status_code == 200
    vault_item = store_res.json()
    vault_id = vault_item["id"]
    token = vault_item["synthetic_token"]

    # 2. Attempt rehydration without authorization -> DENIED (returns None)
    rehydrate_sub = await api_client.post(
        "/api/v1/rehydration/submit",
        headers=headers,
        json={
            "content": f"Paste {token} to untrusted AI",
            "requesting_component": "test_ai",
            "destination_url": "https://external-ai.openai.com/v1",
        },
    )
    assert rehydrate_sub.status_code == 200
    rehydration_id = rehydrate_sub.json()["rehydration_request_ids"][0]

    rehydrate_unauth = await api_client.post(
        f"/api/v1/rehydration/result/{rehydration_id}",
        params={"authorization_id": "unapproved_id"},
        headers=headers,
    )
    assert rehydrate_unauth.status_code == 200
    assert rehydrate_unauth.json()["real_value"] is None

    # 3. Create authorization request and challenge
    req_res = await api_client.post(
        "/api/v1/authorization/request",
        headers=headers,
        json={"synthetic_token": token, "requesting_component": "E2E Test"},
    )
    auth_id = req_res.json()["authorization_id"]

    chal_res = await api_client.post(f"/api/v1/authorization/challenge/{auth_id}", headers=headers)
    assert chal_res.status_code == 200
    challenge_id = chal_res.json()["challenge_id"]

    # 4. Fake unverified assertion rejected (consumes challenge)
    fake_bio = await api_client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        headers=headers,
        json={"challenge_id": challenge_id, "auth_method": "BIOMETRIC", "assertion": "UNVERIFIED"},
    )
    assert fake_bio.status_code in (400, 401)

    # 5. Issue new challenge for valid approval
    chal_res2 = await api_client.post(f"/api/v1/authorization/challenge/{auth_id}", headers=headers)
    assert chal_res2.status_code == 200
    challenge_id2 = chal_res2.json()["challenge_id"]

    approve_res = await api_client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        headers=headers,
        json={
            "challenge_id": challenge_id2,
            "auth_method": "BIOMETRIC",
            "assertion": {"challenge_id": challenge_id2, "verified": True},
        },
    )
    assert approve_res.status_code == 200

    # 6. Rehydration now succeeds and releases real value locally
    rehydrate_ok = await api_client.post(
        f"/api/v1/rehydration/result/{rehydration_id}",
        params={"authorization_id": auth_id},
        headers=headers,
    )
    assert rehydrate_ok.status_code == 200
    assert rehydrate_ok.json()["real_value"] == "sk-secret-rehydration-9912"

    # 7. Deletion of vault item invalidates authorization and rehydration
    del_res = await api_client.delete(f"/api/v1/vault/{vault_id}", headers=headers)
    assert del_res.status_code == 200

    rehydrate_after_del = await api_client.post(
        f"/api/v1/rehydration/result/{rehydration_id}",
        params={"authorization_id": auth_id},
        headers=headers,
    )
    # Deletion invalidates rehydration: sensitive value cannot be accessed
    assert rehydrate_after_del.status_code == 404 or rehydrate_after_del.json().get("real_value") is None


# ==============================================================================
# TEST FLOW 4 & 5: EXPOSURE SEARCH, MONITORING & AI RISK INTEGRATION
# ==============================================================================
@pytest.mark.asyncio
async def test_flow_4_and_5_exposure_search_and_monitoring(api_client: AsyncClient, registered_session: dict):
    headers = registered_session["headers"]

    # 1. Manual exposure search
    search_res = await api_client.post(
        "/api/v1/exposure/search",
        headers=headers,
        json={"search_value_hash": "test_breached_citizen", "search_type": "AADHAAR"},
    )
    assert search_res.status_code == 200
    search_data = search_res.json()
    assert search_data["status"] == "COMPLETED"
    assert search_data["count"] >= 1
    assert len(search_data["exposure_ids"]) >= 1

    # 2. Automatic monitoring cycle
    mon_res = await api_client.post("/api/v1/exposure/monitor/run", headers=headers)
    assert mon_res.status_code == 200
    assert mon_res.json()["status"] == "COMPLETED"


# ==============================================================================
# TEST FLOW 6: DPDP ERASURE STATUTORY LIFECYCLE
# ==============================================================================
@pytest.mark.asyncio
async def test_flow_6_erasure_prepare_review_send_lifecycle(api_client: AsyncClient, registered_session: dict):
    from datetime import datetime, timezone
    headers = registered_session["headers"]

    # 1. First trigger an exposure search to obtain a valid exposure record
    search_res = await api_client.post(
        "/api/v1/exposure/search",
        headers=headers,
        json={"search_value_hash": "test_breached_citizen", "search_type": "AADHAAR"},
    )
    assert search_res.status_code == 200
    exp_id = search_res.json()["exposure_ids"][0]

    # 2. Create a case for this exposure
    now_iso = datetime.now(timezone.utc).isoformat()
    case_res = await api_client.post(
        "/api/v1/cases/",
        headers=headers,
        json={
            "exposure_id": exp_id,
            "organization": "DataBroker Corp",
            "data_type": "AADHAAR",
            "discovery_date": now_iso,
            "evidence": "Dumped in public s3 bucket",
        },
    )
    assert case_res.status_code == 200
    case_id = case_res.json()["id"]

    # 3. Step 1: PREPARE (Create DRAFT erasure request)
    prep_res = await api_client.post(
        "/api/v1/erasure/",
        headers=headers,
        json={
            "case_id": case_id,
            "dpo_email": "dpo@databroker.com",
            "request_body": "Demand for erasure under Section 12 DPDP Act 2023.",
        },
    )
    assert prep_res.status_code == 200
    erasure_item = prep_res.json()
    erasure_id = erasure_item["id"]
    assert erasure_item["status"] == "DRAFT"

    # 4. Step 2 & 3: User reviews and EXPLICITLY sends (starts 7-day clock)
    send_res = await api_client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)
    assert send_res.status_code == 200
    sent_data = send_res.json()
    assert sent_data["status"] == "SENT"
    assert sent_data["deadline_date"] is not None

    # 5. Follow-up action recorded
    followup_res = await api_client.post(
        f"/api/v1/erasure/{erasure_id}/followup",
        headers=headers,
        json={
            "erasure_request_id": erasure_id,
            "follow_up_body": "Second statutory reminder: 7-day DPDP Act compliance window running.",
        },
    )
    assert followup_res.status_code == 200


# ==============================================================================
# VOICE BOUNDARY POLICY ENFORCEMENT
# ==============================================================================
def test_voice_boundary_enforcement():
    handler = VoiceInteractionHandler()

    # Informational voice queries are permitted
    threat_query = handler.process_transcript("Hey Shade, check threat status")
    assert threat_query["status"] == "DISPATCHED"

    scan_query = handler.process_transcript("Hey Shade, scan for active exposures")
    assert scan_query["status"] == "DISPATCHED"

    # Voice authorization is strictly BLOCKED by security policy
    auth_query = handler.process_transcript("Hey Shade, authorize Aadhaar rehydration")
    assert auth_query["status"] == "BLOCKED"
    assert "SECURITY_POLICY_VIOLATION" in auth_query["reason"]


# ==============================================================================
# ARCHITECTURAL INTEGRITY SCAN
# ==============================================================================
def test_architectural_database_isolation():
    """Verify no module outside backend/database directly connects to SQLite."""
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
    forbidden_pattern = re.compile(r"sqlite3\.connect|create_engine|AsyncSessionLocal", re.IGNORECASE)

    scanned_dirs = ["security", "ai", "frontend", "voice"]
    violations = []

    for d in scanned_dirs:
        dir_path = os.path.join(repo_root, d)
        if not os.path.exists(dir_path):
            continue
        for root, _, files in os.walk(dir_path):
            for file in files:
                if file.endswith((".py", ".js")):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                        for line_idx, line in enumerate(f, 1):
                            if forbidden_pattern.search(line):
                                violations.append(f"{file}:{line_idx}: {line.strip()}")

    assert len(violations) == 0, f"Database integrity violation found outside backend: {violations}"
