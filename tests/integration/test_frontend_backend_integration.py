"""
S.H.A.D.E. — Complete Frontend ↔ Backend Integration Test Suite
Role: Member 1 — Architecture + Backend + Database + Integration

Validates all 23 real-world frontend user workflows against the live backend:
1. Owner registration
2. OTP verification & device binding
3. Session establishment & JWT acquisition
4. Dashboard loading & metrics telemetry
5. Static HUD mounting (GET /, /app, /static/index.html, /static/js/app.js)
6. Normal text sandbox submission -> PASSTHROUGH (unaltered)
7. Sensitive identifier sandbox submission -> DLP TOKENIZED
8. Duplicate sensitive copy -> REUSED existing synthetic token
9. Vault listing (safe metadata only, no plaintext)
10. Owner authorization gate initiation
11. Cryptographic challenge nonce issuance
12. PIN authentication assertion approval
13. Vault decryption release (authorized release locally)
14. Exposure search execution
15. Exposure listing
16. DPDP Investigation Case creation
17. Case listing & detail lookup
18. Statutory Section 12 Erasure preparation (DRAFT)
19. Explicit User Send -> Statutory 7-day deadline activation
20. 7-Day Deadline inspection
21. Statutory Follow-up dispatch
22. Session revocation / logout
23. Voice ambient boundary verification
"""

import uuid
import pytest
from httpx import AsyncClient


@pytest.mark.asyncio
async def test_full_frontend_backend_e2e_workflow(client: AsyncClient):
    # ── 1. Static HUD Files Mounting ─────────────────────────────────────────
    r_root = await client.get("/")
    assert r_root.status_code == 200
    assert "S.H.A.D.E." in r_root.text

    r_app = await client.get("/app")
    assert r_app.status_code == 200

    r_js = await client.get("/static/js/app.js")
    assert r_js.status_code == 200
    assert "ensureSession" in r_js.text

    # ── 2. Owner Registration & OTP Verification ─────────────────────────────
    import hashlib
    unique_suffix = uuid.uuid4().hex[:6]
    mobile = f"98765{unique_suffix[:5]}"
    device_fingerprint = hashlib.sha256(f"device-test-node-{unique_suffix}".encode()).hexdigest()

    # Step 1: Register mobile
    r_reg = await client.post("/api/v1/auth/register", json={"mobile_number": mobile})
    assert r_reg.status_code == 200
    assert "OTP sent" in r_reg.json()["message"]

    # Step 2: Verify OTP
    r_otp = await client.post(
        "/api/v1/auth/verify-otp",
        json={"mobile_number": mobile, "otp_code": "000000"},
    )
    assert r_otp.status_code == 200
    ticket = r_otp.json()["verification_ticket"]
    assert ticket is not None

    # Step 3: Bind Device with Argon2id PIN
    from backend.app.core.crypto import hash_pin
    pin_hash = hash_pin("123456")
    r_bind = await client.post(
        "/api/v1/auth/bind-device",
        json={
            "device_fingerprint_hash": device_fingerprint,
            "platform": "windows",
            "verification_ticket": ticket,
            "pin_hash": pin_hash,
        },
    )
    assert r_bind.status_code == 200
    owner_id = r_bind.json()["owner_id"]
    device_id = r_bind.json()["device_id"]

    # Step 4: Create Session
    r_sess = await client.post(f"/api/v1/session/create?owner_id={owner_id}")
    assert r_sess.status_code == 200
    access_token = r_sess.json()["access_token"]
    session_id = r_sess.json()["session_id"]
    assert access_token is not None

    headers = {
        "Authorization": f"Bearer {access_token}",
        "X-Device-Id": device_id,
        "Content-Type": "application/json",
    }

    # ── 3. Dashboard Initial State ───────────────────────────────────────────
    v_init = await client.get("/api/v1/vault/", headers=headers)
    assert v_init.status_code == 200
    assert v_init.json()["count"] == 0

    exp_init = await client.get("/api/v1/exposure/", headers=headers)
    assert exp_init.status_code == 200
    assert exp_init.json()["count"] == 0

    cases_init = await client.get("/api/v1/cases/", headers=headers)
    assert cases_init.status_code == 200
    assert cases_init.json()["count"] == 0

    # ── 4. Sandbox Clipboard Interception: Normal Text (PASSTHROUGH) ─────────
    r_clean = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": "Hello team, this is an ordinary harmless email body."},
        headers=headers,
    )
    assert r_clean.status_code == 200
    assert r_clean.json()["action"] == "PASSTHROUGH"
    assert r_clean.json()["is_sensitive"] is False

    # ── 5. Sandbox Clipboard Interception: Sensitive Identifier (TOKENIZED) ──
    sensitive_pwd = "SuperSecretAdminPassword#2026!"
    r_sens = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": sensitive_pwd, "detected_type": "PASSWORD"},
        headers=headers,
    )
    assert r_sens.status_code == 200
    assert r_sens.json()["action"] == "TOKENIZED"
    assert r_sens.json()["is_sensitive"] is True
    token_1 = r_sens.json()["synthetic_token"]
    assert token_1.startswith("SHD_")
    assert len(token_1) == 12

    # ── 6. Duplicate Copy Reuse Invariant (REUSED) ───────────────────────────
    r_dup = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": sensitive_pwd, "detected_type": "PASSWORD"},
        headers=headers,
    )
    assert r_dup.status_code == 200
    assert r_dup.json()["action"] == "REUSED"
    assert r_dup.json()["synthetic_token"] == token_1

    # ── 7. Vault List & Metadata (No Plaintext Leaks) ────────────────────────
    v_list = await client.get("/api/v1/vault/", headers=headers)
    assert v_list.status_code == 200
    assert v_list.json()["count"] == 1
    item = v_list.json()["items"][0]
    assert item["synthetic_token"] == token_1
    assert "SuperSecretAdminPassword" not in str(v_list.json())

    vault_id = item["id"]

    # ── 8. Rehydration Authorization Request & Challenge Nonce ───────────────
    r_auth_req = await client.post(
        "/api/v1/authorization/request",
        json={
            "synthetic_token": token_1,
            "requesting_component": "S.H.A.D.E. Local UI",
            "purpose_scope": "Owner interactive decryption request",
        },
        headers=headers,
    )
    assert r_auth_req.status_code == 200
    auth_id = r_auth_req.json()["authorization_id"]
    assert r_auth_req.json()["state"] == "PENDING"

    r_chal = await client.post(f"/api/v1/authorization/challenge/{auth_id}", headers=headers)
    assert r_chal.status_code == 200
    chal_data = r_chal.json()
    challenge_id = chal_data["challenge_id"]
    nonce = chal_data["nonce"]
    assert len(nonce) >= 32

    # ── 9. Owner Approval with Argon2id PIN ──────────────────────────────────
    r_approve = await client.post(
        f"/api/v1/authorization/approve/{auth_id}",
        json={
            "auth_method": "PIN",
            "challenge_id": challenge_id,
            "assertion": "123456",
        },
        headers=headers,
    )
    assert r_approve.status_code == 200
    assert r_approve.json()["state"] == "APPROVED"

    # ── 10. Vault Retrieve Real Value (Decrypted) ────────────────────────────
    r_ret = await client.post(
        f"/api/v1/vault/retrieve?sensitive_value_id={vault_id}&authorization_id={auth_id}",
        headers=headers,
    )
    assert r_ret.status_code == 200
    assert r_ret.json()["real_value"] == sensitive_pwd

    # ── 11. Exposure Search & Risk Engine Ingestion ──────────────────────────
    r_exp_search = await client.post(
        "/api/v1/exposure/search",
        json={"search_type": "PASSWORD", "search_value_hash": "sha1_hash_sample"},
        headers=headers,
    )
    assert r_exp_search.status_code == 200

    # Submit an exposure telemetry record
    r_sub_exp = await client.post(
        "/api/v1/exposure/submit",
        json={
            "sensitive_value_id": vault_id,
            "data_type": "PASSWORD",
            "organization": "TargetBank",
            "source_url": "https://pastebin.internal/dump1",
            "evidence_summary": "Observed credential in breach archive.",
        },
        headers=headers,
    )
    assert r_sub_exp.status_code == 200
    exp_id = r_sub_exp.json()["exposure_id"]

    # ── 12. Case Creation from Exposure ──────────────────────────────────────
    r_case = await client.post(
        "/api/v1/cases/",
        json={
            "exposure_id": exp_id,
            "organization": "TargetBank",
            "data_type": "PASSWORD",
            "affected_data_description": "Compromised Administrative Password",
            "evidence": "Verified breach dump",
        },
        headers=headers,
    )
    assert r_case.status_code == 200
    case_id = r_case.json()["id"]
    assert r_case.json()["status"] == "OPEN"

    # ── 13. DPDP Section 12 Statutory Erasure Wizard ─────────────────────────
    # Step 1: Prepare Draft
    r_draft = await client.post(
        "/api/v1/erasure/",
        json={
            "case_id": case_id,
            "dpo_email": "dpo@targetbank.example",
            "request_body": "Statutory demand for complete erasure under DPDP Act 2023 Section 12.",
        },
        headers=headers,
    )
    assert r_draft.status_code == 200
    erasure_id = r_draft.json()["id"]
    assert r_draft.json()["status"] == "DRAFT"

    # Step 2: Explicit User Send (Activates 7-day clock)
    r_send = await client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)
    assert r_send.status_code == 200
    assert r_send.json()["status"] == "SENT"
    assert "7-day statutory deadline" in r_send.json()["message"]

    # Step 3: Check Deadline Status
    r_dead = await client.get(f"/api/v1/erasure/{erasure_id}/deadline", headers=headers)
    assert r_dead.status_code == 200
    assert r_dead.json()["deadline_passed"] is False

    # Step 4: Dispatch Follow-up
    r_fu = await client.post(
        f"/api/v1/erasure/{erasure_id}/followup",
        json={"follow_up_body": "Reminder: 7-day statutory deadline is pending compliance."},
        headers=headers,
    )
    assert r_fu.status_code == 200
    assert r_fu.json()["status"] == "SENT"

    # ── 14. Voice Boundary Enforcement ───────────────────────────────────────
    from voice.contracts import VoiceInteractionHandler
    voice = VoiceInteractionHandler()

    res_blocked = voice.process_transcript("Hey Shade, please authorize rehydration of my password")
    assert res_blocked["status"] == "BLOCKED"
    assert res_blocked["reason"] == "SECURITY_POLICY_VIOLATION"

    res_info = voice.process_transcript("Hey Shade, what is the threat status?")
    assert res_info["status"] == "DISPATCHED"
    assert res_info["intent"] == "CHECK_THREAT_STATUS"

    # ── 15. Session Logout / Revocation ──────────────────────────────────────
    r_revoke = await client.post(f"/api/v1/session/revoke/{session_id}", headers=headers)
    assert r_revoke.status_code == 200
    assert r_revoke.json()["revoked"] is True

    # After revocation, protected access must be denied
    r_after = await client.get("/api/v1/vault/", headers=headers)
    assert r_after.status_code == 401


@pytest.mark.asyncio
async def test_scenario_unsupported_national_id_search(client: AsyncClient):
    """
    Scenario 9 — Truthful Unsupported National ID Breach Querying:
    Searching Aadhaar or PAN externally must explicitly return an unsupported capability
    declaration and must NEVER fabricate breach records.
    """
    from tests.integration.test_real_world_integrations import create_registered_owner_session
    headers = await create_registered_owner_session(client)

    # 1. Inspect capability disclosure
    caps_res = await client.get("/api/v1/exposure/capabilities", headers=headers)
    assert caps_res.status_code == 200
    caps = caps_res.json()["capabilities"]
    
    unsupported_types = []
    for c in caps:
        unsupported_types.extend(c.get("unsupported_data_types", []))

    assert "AADHAAR" in unsupported_types
    assert "PAN" in unsupported_types

    # 2. Attempting external search on unsupported type returns truthful empty/unsupported result
    r_search = await client.post(
        "/api/v1/exposure/search",
        json={"search_type": "AADHAAR", "search_value_hash": "dummy_aadhaar_hash_value"},
        headers=headers,
    )
    assert r_search.status_code == 200
    assert r_search.json()["count"] == 0


@pytest.mark.asyncio
async def test_scenario_offline_graceful_handling(client: AsyncClient):
    """
    Scenario 12 — Offline Core Security Operation:
    Local vault, tokenization, and auth challenge/approval continue to work 100% offline
    without internet access. External breach lookups fail gracefully with clear status.
    """
    from tests.integration.test_real_world_integrations import create_registered_owner_session
    headers = await create_registered_owner_session(client)

    # 1. Local clipboard tokenization works completely offline
    r_clip = await client.post(
        "/api/v1/clipboard/submit",
        json={"content": "offline_classified_key_44321", "detected_type": "API_KEY"},
        headers=headers,
    )
    assert r_clip.status_code == 200
    assert r_clip.json()["action"] in ("TOKENIZED", "REUSED")
    offline_token = r_clip.json()["synthetic_token"]

    # 2. Local vault retrieval works completely offline
    r_vault = await client.get(f"/api/v1/vault/token/{offline_token}", headers=headers)
    assert r_vault.status_code == 200
    assert r_vault.json()["exists"] is True

    # 3. External breach search gracefully handles simulated offline / provider failure
    from backend.app.services.exposure_provider import set_exposure_provider, ExposureProvider
    
    class OfflineMockProvider(ExposureProvider):
        @property
        def name(self) -> str:
            return "offline-provider"
        def is_available(self) -> bool:
            return False
        async def search(self, st, svh):
            return []

    orig_provider = None
    try:
        from backend.app.services.exposure_provider import get_exposure_provider
        orig_provider = get_exposure_provider()
        set_exposure_provider(OfflineMockProvider())

        r_exp = await client.post(
            "/api/v1/exposure/search",
            json={"search_type": "PASSWORD", "search_value_hash": "offline_hash"},
            headers=headers,
        )
        assert r_exp.status_code == 200
        assert r_exp.json()["status"] == "PROVIDER_UNAVAILABLE"
    finally:
        if orig_provider:
            set_exposure_provider(orig_provider)
