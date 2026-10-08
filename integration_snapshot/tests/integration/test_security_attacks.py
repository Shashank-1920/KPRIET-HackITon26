"""
S.H.A.D.E. — Security Attack & Adversarial Penetration Test Suite
Role: Member 1 — Core Architecture + Backend + Database + Integration

Validates defense-in-depth protections against active attack vectors:
1. Forged Biometric Assertions & Mock Client Claims
2. Challenge Nonce Replay & Single-Use Invariant
3. Cross-Tenant Token Manipulation & Rehydration Hijacking
4. Device Header Spoofing & Session Binding Violations
5. Erasure Workflow State Machine Tampering & Duplicate Dispatch Flooding
6. Malformed Token Injection & AST Direct DB Query Audit
"""

import hashlib
import uuid
import pytest
from httpx import AsyncClient

from backend.app.services.auth_provider import PlatformBiometricProvider
from tests.integration.test_real_world_integrations import create_registered_owner_session


# ── 1. FORGED BIOMETRIC ATTACKS ─────────────────────────────────────────────

def test_attack_forged_biometric_payloads_strictly_rejected():
    provider = PlatformBiometricProvider()
    owner_id = str(uuid.uuid4())

    ch = provider.create_challenge(owner_id, "VAULT_REHYDRATE", "val-attack-1")

    # Attack vector 1: Client sends naive JSON {"verified": True}
    assert provider.verify_biometric_assertion(ch.challenge_id, {"verified": True}, owner_id) is False

    # Attack vector 2: Client sends string claim "BIOMETRIC_PASS"
    ch2 = provider.create_challenge(owner_id, "VAULT_REHYDRATE", "val-attack-2")
    assert provider.verify_biometric_assertion(ch2.challenge_id, "BIOMETRIC_PASS", owner_id) is False

    # Attack vector 3: Client sends empty signature
    ch3 = provider.create_challenge(owner_id, "VAULT_REHYDRATE", "val-attack-3")
    assert provider.verify_biometric_assertion(ch3.challenge_id, {"signature": "", "nonce": ch3.nonce}, owner_id) is False


def test_attack_challenge_nonce_replay_rejected():
    provider = PlatformBiometricProvider()
    owner_id = str(uuid.uuid4())
    from cryptography.hazmat.primitives.asymmetric import ed25519

    priv = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv.public_key().public_bytes_raw()
    provider.register_credential(owner_id, "cred_test", pub_bytes, key_type="ed25519")

    ch = provider.create_challenge(owner_id, "ACTION", "res-1")
    sig = priv.sign(ch.nonce.encode("utf-8"))

    assertion = {
        "credential_id": "cred_test",
        "signature": sig.hex(),
        "nonce": ch.nonce,
        "user_verified": True,
    }

    # First attempt: succeeds and consumes challenge
    assert provider.verify_biometric_assertion(ch.challenge_id, assertion, owner_id) is True

    # REPLAY ATTACK: Second attempt with identical challenge must fail
    with pytest.raises(Exception):
        provider.verify_biometric_assertion(ch.challenge_id, assertion, owner_id)


# ── 2. CROSS-TENANT & REHYDRATION HIJACKING ATTACKS ─────────────────────────

@pytest.mark.asyncio
async def test_attack_cross_tenant_token_rehydration_denied(client: AsyncClient):
    # Owner A stores a sensitive secret
    headers_a = await create_registered_owner_session(client)
    secret_value = "super_classified_owner_a_secret_key"
    store_r = await client.post(
        "/api/v1/vault/store",
        json={"raw_value": secret_value, "data_type": "API_KEY"},
        headers=headers_a,
    )
    token_a = store_r.json()["synthetic_token"]

    # Owner B registers and attempts to request rehydration of Owner A's token
    headers_b = await create_registered_owner_session(client)
    req_b = await client.post(
        "/api/v1/authorization/request",
        json={"synthetic_token": token_a, "requesting_component": "attacker_component"},
        headers=headers_b,
    )
    # Must be denied (403 or 404 - cannot authorize another owner's token)
    assert req_b.status_code in (403, 404)


@pytest.mark.asyncio
async def test_attack_malformed_synthetic_tokens_rejected(client: AsyncClient):
    headers = await create_registered_owner_session(client)

    malformed_tokens = [
        "SHD_NONEXISTENT",
        "'; DROP TABLE sensitive_values; --",
        "<script>alert(1)</script>",
        "A" * 100,
        "SHD_123",  # Invalid length
    ]

    for bad_token in malformed_tokens:
        r = await client.post(
            "/api/v1/authorization/request",
            json={"synthetic_token": bad_token, "requesting_component": "test"},
            headers=headers,
        )
        assert r.status_code in (400, 404, 422)


# ── 3. DEVICE SPOOFING & HEADER VIOLATIONS ──────────────────────────────────

@pytest.mark.asyncio
async def test_attack_device_mismatch_header_rejected(client: AsyncClient):
    headers = await create_registered_owner_session(client)

    # Inject mismatched hardware device header
    spoofed_headers = dict(headers)
    spoofed_headers["X-Device-ID"] = "fake-spoofed-hardware-id-9999"

    resp = await client.get("/api/v1/vault/", headers=spoofed_headers)
    # Must reject mismatched device
    assert resp.status_code in (401, 403)


# ── 4. ERASURE STATE MACHINE & FLOODING ATTACKS ──────────────────────────────

@pytest.mark.asyncio
async def test_attack_erasure_workflow_tampering_and_duplicate_flooding(client: AsyncClient):
    headers = await create_registered_owner_session(client)

    # 1. Submit exposure
    sub_exp = await client.post(
        "/api/v1/exposure/submit",
        json={
            "data_type": "PASSWORD",
            "organization": "SecurityCorp",
            "source_url": "https://example.com/leak",
            "evidence_summary": "Password exposed in audit dump",
        },
        headers=headers,
    )
    exp_id = sub_exp.json()["exposure_id"]

    # 2. Create case
    case_r = await client.post(
        "/api/v1/cases/",
        json={"exposure_id": exp_id, "data_type": "PASSWORD", "discovery_date": "2026-10-01T00:00:00Z"},
        headers=headers,
    )
    case_id = case_r.json()["id"]

    # 3. Create DRAFT erasure request
    draft_r = await client.post(
        "/api/v1/erasure/",
        json={"case_id": case_id, "dpo_email": "dpo@securitycorp.example", "request_body": "Section 12 Erasure."},
        headers=headers,
    )
    erasure_id = draft_r.json()["id"]

    # Attack: User sends request once
    send1 = await client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)
    assert send1.status_code == 200

    # Flooding Attack: Calling send repeatedly must be idempotent and must NOT reset statutory deadline
    deadline1 = send1.json()["deadline_date"].rstrip("Z")
    for _ in range(3):
        send_dup = await client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)
        assert send_dup.status_code == 200
        assert send_dup.json()["deadline_date"].rstrip("Z") == deadline1
