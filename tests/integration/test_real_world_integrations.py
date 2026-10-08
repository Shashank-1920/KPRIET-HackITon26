"""
S.H.A.D.E. — Real-World Integrations Test Suite
Role: Shared Integration & Verification

Tests:
1. Real Windows OS & Memory Clipboard Interception & Loop Protection
2. Platform Biometric Provider (Ed25519 & ECDSA P-256 signatures, replay rejection, forgery rejection, hardware status)
3. Statutory Legal Request Delivery (SMTP delivery provider, dev simulation, duplicate-send prevention, error handling)
4. Accurately Scoped Breach Capabilities (truthful provider capability disclosure, k-anonymity password check, Aadhaar/PAN unsupported declaration)
"""

import base64
import hashlib
import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from backend.main import app

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat


from backend.app.services.auth_provider import PlatformBiometricProvider, AuthChallenge
from backend.app.services.legal_delivery import SMTPDeliveryProvider, LegalDeliveryResult, set_legal_delivery_provider
from backend.app.services.exposure_provider import (
    CompositeExposureProvider,
    HIBPPasswordExposureProvider,
    HIBPEmailExposureProvider,
    CanaryExposureProvider,
)
from backend.app.database.models import Owner


# ── 1. PLATFORM BIOMETRIC PROVIDER TESTS ─────────────────────────────────────

def test_platform_biometric_hardware_status():
    provider = PlatformBiometricProvider()
    status = provider.check_platform_hardware_status()
    assert "platform" in status
    assert "hardware_biometric_supported" in status
    assert status["requires_physical_user_presence"] is True
    assert "verification_algorithm" in status


def test_platform_biometric_ed25519_valid_and_replay():
    provider = PlatformBiometricProvider()
    owner_id = str(uuid.uuid4())
    cred_id = "cred_win_hello_01"

    # Generate device key pair
    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes_raw()

    provider.register_credential(owner_id, cred_id, pub_bytes, key_type="ed25519")

    # 1. Create server challenge
    challenge = provider.create_challenge(owner_id, "VAULT_REHYDRATE", "val-123")
    nonce_bytes = challenge.nonce.encode("utf-8")

    # 2. Sign challenge nonce
    signature = priv_key.sign(nonce_bytes)

    assertion = {
        "credential_id": cred_id,
        "signature": signature.hex(),
        "nonce": challenge.nonce,
        "user_verified": True,
    }

    # Verify assertion -> TRUE
    assert provider.verify_biometric_assertion(challenge.challenge_id, assertion, owner_id) is True

    # 3. REPLAY ATTACK: Re-using the same challenge must FAIL (already consumed)
    with pytest.raises(Exception):
        provider.verify_biometric_assertion(challenge.challenge_id, assertion, owner_id)


def test_platform_biometric_ecdsa_p256_valid():
    provider = PlatformBiometricProvider()
    owner_id = str(uuid.uuid4())
    cred_id = "cred_tpm_p256_01"

    # Generate ECDSA P-256 key pair
    priv_key = ec.generate_private_key(ec.SECP256R1())
    pub_key = priv_key.public_key()
    pub_bytes = pub_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)

    provider.register_credential(owner_id, cred_id, pub_bytes, key_type="p256")

    challenge = provider.create_challenge(owner_id, "VAULT_REHYDRATE", "val-456")
    nonce_bytes = challenge.nonce.encode("utf-8")
    signature = priv_key.sign(nonce_bytes, ec.ECDSA(hashes.SHA256()))

    assertion = {
        "credential_id": cred_id,
        "signature": signature.hex(),
        "nonce": challenge.nonce,
        "user_verified": True,
    }

    assert provider.verify_biometric_assertion(challenge.challenge_id, assertion, owner_id) is True


def test_platform_biometric_forgery_and_tampering_rejected():
    provider = PlatformBiometricProvider()
    owner_id = str(uuid.uuid4())
    cred_id = "cred_win_hello_02"

    priv_key = ed25519.Ed25519PrivateKey.generate()
    pub_bytes = priv_key.public_key().public_bytes_raw()
    provider.register_credential(owner_id, cred_id, pub_bytes, key_type="ed25519")

    # A. Client forgery: string or mock dict without signature
    ch1 = provider.create_challenge(owner_id, "TEST", "res-1")
    assert provider.verify_biometric_assertion(ch1.challenge_id, "BIOMETRIC_PASS", owner_id) is False

    ch2 = provider.create_challenge(owner_id, "TEST", "res-2")
    assert provider.verify_biometric_assertion(ch2.challenge_id, {"verified": True}, owner_id) is False

    # B. User verification (UV) flag missing
    ch3 = provider.create_challenge(owner_id, "TEST", "res-3")
    sig = priv_key.sign(ch3.nonce.encode("utf-8"))
    assert provider.verify_biometric_assertion(
        ch3.challenge_id,
        {"credential_id": cred_id, "signature": sig.hex(), "nonce": ch3.nonce, "user_verified": False},
        owner_id,
    ) is False

    # C. Nonce mismatch
    ch4 = provider.create_challenge(owner_id, "TEST", "res-4")
    wrong_sig = priv_key.sign(b"wrong_nonce")
    assert provider.verify_biometric_assertion(
        ch4.challenge_id,
        {"credential_id": cred_id, "signature": wrong_sig.hex(), "nonce": "wrong_nonce", "user_verified": True},
        owner_id,
    ) is False


# ── 2. STATUTORY LEGAL REQUEST DELIVERY (SMTP) TESTS ────────────────────────

@pytest.mark.asyncio
async def test_smtp_delivery_provider_dev_simulation():
    provider = SMTPDeliveryProvider(dev_mode=True)
    res = await provider.send_erasure_notice(
        recipient_email="dpo@company.example",
        subject="Statutory Notice Under DPDP Act 2023",
        notice_body="Please erase my personal data according to Section 12.",
        case_id="case-xyz-123",
    )
    assert res.success is True
    assert res.mode == "SMTP_DEV_SIMULATED"
    assert res.message_id is not None
    assert res.recipient == "dpo@company.example"
    assert res.delivered_at is not None


@pytest.mark.asyncio
async def test_smtp_delivery_invalid_email_fails_safely():
    provider = SMTPDeliveryProvider(dev_mode=True)
    res = await provider.send_erasure_notice(
        recipient_email="invalid-not-an-email",
        subject="Notice",
        notice_body="body",
        case_id="case-1",
    )
    assert res.success is False
    assert "Invalid recipient email" in (res.error_message or "")


async def create_registered_owner_session(client: AsyncClient) -> dict:
    uid = uuid.uuid4().hex[:8]
    mobile = f"98{int(uid, 16) % 100000000:08d}"
    device_hw = f"hw-device-{uid}"

    await client.post("/api/v1/auth/register", json={"mobile_number": mobile})
    otp_res = await client.post("/api/v1/auth/verify-otp", json={"mobile_number": mobile, "otp_code": "000000"})
    ticket = otp_res.json()["verification_ticket"]

    fp_hash = hashlib.sha256(device_hw.encode()).hexdigest()
    bind_res = await client.post("/api/v1/auth/bind-device", json={
        "device_fingerprint_hash": fp_hash,
        "platform": "windows",
        "verification_ticket": ticket,
        "mobile_number": mobile,
    })
    owner_id = bind_res.json()["owner_id"]

    sess_res = await client.post(f"/api/v1/session/create?owner_id={owner_id}")
    token = sess_res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.mark.asyncio
async def test_erasure_endpoint_delivery_and_duplicate_prevention(client: AsyncClient):
    headers = await create_registered_owner_session(client)


    # Submit exposure & case
    sub_exp = await client.post(
        "/api/v1/exposure/submit",
        json={
            "data_type": "EMAIL",
            "organization": "TargetCorp",
            "source_url": "https://example.com/leak",
            "evidence_summary": "Email list exposed",
        },
        headers=headers,
    )
    exp_id = sub_exp.json()["exposure_id"]

    case_r = await client.post(
        "/api/v1/cases/",
        json={"exposure_id": exp_id, "data_type": "EMAIL", "discovery_date": "2026-10-01T00:00:00Z"},
        headers=headers,
    )
    case_id = case_r.json()["id"]

    # Draft erasure request
    draft_r = await client.post(
        "/api/v1/erasure/",
        json={
            "case_id": case_id,
            "dpo_email": "dpo@targetcorp.example",
            "request_body": "Official Section 12 erasure demand.",
        },
        headers=headers,
    )
    erasure_id = draft_r.json()["id"]
    assert draft_r.json()["status"] == "DRAFT"

    # 1. First send: dispatches via provider, transitions to SENT, starts 7-day deadline
    send1 = await client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)
    assert send1.status_code == 200
    assert send1.json()["status"] == "SENT"
    assert "7-day statutory deadline" in send1.json()["message"]

    # 2. Duplicate send prevention: calling send again returns already sent message, does not restart deadline
    send2 = await client.post(f"/api/v1/erasure/{erasure_id}/send", headers=headers)
    assert send2.status_code == 200
    assert send2.json()["status"] == "SENT"
    assert "was already sent" in send2.json()["message"]


# ── 3. TRUTHFUL CAPABILITY MATRIX TESTS ─────────────────────────────────────

@pytest.mark.asyncio
async def test_exposure_capabilities_truthful_disclosure(client: AsyncClient):
    headers = await create_registered_owner_session(client)

    caps_r = await client.get("/api/v1/exposure/capabilities", headers=headers)

    assert caps_r.status_code == 200



    data = caps_r.json()
    assert data["provider_count"] >= 3

    # Check that Password capability uses k-anonymity
    providers = {p["provider_name"]: p for p in data["capabilities"]}
    assert "HaveIBeenPwned (Passwords)" in providers
    hibp_pwd = providers["HaveIBeenPwned (Passwords)"]
    assert "PASSWORD" in hibp_pwd["supported_data_types"]
    assert "k-anonymity" in hibp_pwd["lookup_mechanism"]
    assert "Zero-Knowledge" in hibp_pwd["privacy_model"]

    # Check that National Identifiers (Aadhaar/PAN) are truthfully declared UNSUPPORTED
    assert "National Identity Registries (Aadhaar, PAN, DL, Plates)" in providers
    nat_id = providers["National Identity Registries (Aadhaar, PAN, DL, Plates)"]
    assert "AADHAAR" in nat_id["unsupported_data_types"]
    assert "PAN" in nat_id["unsupported_data_types"]
    assert "UNSUPPORTED" in nat_id["lookup_mechanism"]
