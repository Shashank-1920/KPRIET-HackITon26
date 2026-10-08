"""
S.H.A.D.E. — Security & DLP Test Suite
Role: Member 2 — Security + Threat Engine + DLP

Tests:
- Dihedral D5 Verhoeff checksum algorithm for Aadhaar
- Luhn Mod-10 algorithm for Credit/Debit cards
- PAN card structure validation
- API keys, credentials, and passwords detection
- Mobile numbers, vehicle number plates, UPI IDs, secret URLs detection
- Normal text passthrough vs sensitive text tokenization in ClipboardGuard
- Privacy-preserving HIBP k-anonymity client
- Canary honey-token generation and verification
"""

import pytest

from security.validators.verhoeff import validate_aadhaar_number, compute_checksum, validate_verhoeff
from security.validators.luhn import validate_luhn
from security.dlp.detectors.aadhaar import AadhaarDetector
from security.dlp.detectors.pan import PANDetector
from security.dlp.detectors.credentials import CredentialsDetector
from security.dlp.detectors.identifiers import IdentifiersDetector
from security.dlp.engine import DLPEngine
from security.dlp.clipboard_guard import ClipboardGuard
from security.threat_engine.canaries import CanaryGenerator
from security.breach_radar.hibp_client import HIBPClient


def test_verhoeff_checksum_algorithm():
    # Valid Aadhaar numbers generated via Verhoeff
    # Test number base: 54812938491
    # Check digit computation:
    check_digit = compute_checksum("54812938491")
    full_aadhaar = f"54812938491{check_digit}"
    assert validate_verhoeff(full_aadhaar) is True
    assert validate_aadhaar_number(full_aadhaar) is True

    # Negative test: invalid check digit
    wrong_aadhaar = f"54812938491{(check_digit + 1) % 10}"
    assert validate_verhoeff(wrong_aadhaar) is False
    assert validate_aadhaar_number(wrong_aadhaar) is False

    # Negative test: cannot start with 0 or 1
    assert validate_aadhaar_number("012345678901") is False
    assert validate_aadhaar_number("123456789012") is False


def test_luhn_credit_card_validator():
    # Known test card numbers passing Luhn
    assert validate_luhn("49927398716") is True
    assert validate_luhn("49927398717") is False
    # Short length
    assert validate_luhn("12345") is False


def test_aadhaar_detector():
    detector = AadhaarDetector()
    check = compute_checksum("89234819230")
    valid_aadhaar = f"89234819230{check}"
    
    # Formatted with spaces
    text = f"My citizen identity number is {valid_aadhaar[:4]} {valid_aadhaar[4:8]} {valid_aadhaar[8:]}."
    results = detector.detect(text)
    assert len(results) == 1
    assert results[0].data_type == "AADHAAR"
    assert results[0].normalized_value == valid_aadhaar

    # Normal text should return empty
    assert len(detector.detect("Phone number is 9876543210 and meeting is tomorrow.")) == 0


def test_pan_detector():
    detector = PANDetector()
    results = detector.detect("Income tax reference PAN: ABCDE1234F.")
    assert len(results) == 1
    assert results[0].data_type == "PAN"
    assert results[0].normalized_value == "ABCDE1234F"

    # Negative test: invalid structure
    assert len(detector.detect("AB12345678")) == 0


def test_credentials_detector():
    detector = CredentialsDetector()
    
    # OpenAI API Key
    res_openai = detector.detect("export OPENAI_API_KEY=sk-proj-abc1234567890defghijklmnop")
    assert any(r.data_type == "API_KEY" for r in res_openai)

    # AWS Access Key
    res_aws = detector.detect("AWS credentials: AKIAIOSFODNN7EXAMPLE")
    assert any(r.data_type == "API_KEY" for r in res_aws)

    # Password assignment
    res_pwd = detector.detect("Database connection string password=SuperSecretPassword123!")
    assert any(r.data_type == "PASSWORD" for r in res_pwd)


def test_identifiers_detector():
    detector = IdentifiersDetector()

    # Mobile number
    res_mobile = detector.detect("Call me at +91 9876543210 immediately.")
    assert any(r.data_type == "MOBILE" and r.normalized_value == "9876543210" for r in res_mobile)

    # Vehicle Plate
    res_plate = detector.detect("Registered car number plate DL 01 AB 1234 parked outside.")
    assert any(r.data_type == "VEHICLE_PLATE" for r in res_plate)

    # UPI ID
    res_upi = detector.detect("Send payment to user.name@oksbi please.")
    assert any(r.data_type == "UPI_ID" for r in res_upi)

    # URL with secret
    res_url = detector.detect("Webhook endpoint: https://api.service.com/webhook?token=sec_9874182937")
    assert any(r.data_type == "URL_WITH_SECRET" for r in res_url)


def test_dlp_engine_normal_text_ignored():
    engine = DLPEngine()
    # General clean text must be completely ignored (returns None)
    clean_texts = [
        "Hello world, see you tomorrow morning at 9am.",
        "The quick brown fox jumps over the lazy dog.",
        "Please review the attached project architecture documentation.",
    ]
    for text in clean_texts:
        assert engine.inspect(text) is None


def test_clipboard_guard_passthrough_vs_tokenization():
    engine = DLPEngine()

    # Mock backend dispatcher that behaves like Member 1's backend endpoint
    stored_mappings = {}
    def mock_backend_dispatch(content: str, d_type: str):
        if content in stored_mappings:
            return {"synthetic_token": stored_mappings[content], "action": "REUSED"}
        token = f"SHD_MOCK_{len(stored_mappings) + 1:04d}"
        stored_mappings[content] = token
        return {"synthetic_token": token, "action": "TOKENIZED"}

    guard = ClipboardGuard(dlp_engine=engine, backend_dispatcher=mock_backend_dispatch)

    # 1. Normal text -> PASSTHROUGH
    res_normal = guard.process_copied_text("Just normal daily conversation.")
    assert res_normal.is_sensitive is False
    assert res_normal.action == "PASSTHROUGH"
    assert res_normal.resulting_clipboard_text == "Just normal daily conversation."

    # 2. Sensitive text -> TOKENIZED
    res_secret = guard.process_copied_text("export KEY=sk-proj-live-1234567890abcdef1234")
    assert res_secret.is_sensitive is True
    assert res_secret.action == "TOKENIZED"
    assert res_secret.synthetic_token.startswith("SHD_")
    assert res_secret.resulting_clipboard_text == res_secret.synthetic_token

    # 3. Duplicate same sensitive value -> REUSED
    res_dup = guard.process_copied_text("export KEY=sk-proj-live-1234567890abcdef1234")
    assert res_dup.is_sensitive is True
    assert res_dup.action == "REUSED"
    assert res_dup.synthetic_token == res_secret.synthetic_token


def test_canary_honeytoken_generation_and_attribution():
    canary_gen = CanaryGenerator(master_secret=b"test_canary_secret_12345")
    token, canary_id = canary_gen.generate_canary("vendor_corp_alpha", "API_KEY")
    assert token.startswith("sk-canary-")

    # Correct attribution verifies
    assert canary_gen.verify_canary_attribution(token, "vendor_corp_alpha", "API_KEY") is True

    # Tampered or wrong recipient fails verification
    assert canary_gen.verify_canary_attribution(token, "wrong_vendor", "API_KEY") is False


def test_hibp_k_anonymity_privacy_invariant():
    client = HIBPClient()
    # Test checking with offline timeout or mock
    res = client.check_password_pwned("P@ssw0rd123!", timeout=1.0)
    # The client computed SHA-1 prefix of 5 characters and did not send full password
    assert len(res.hash_prefix) == 5
    # Whether online or offline, it must return a valid HIBPCheckResult without crashing
    assert isinstance(res.is_compromised, bool)
