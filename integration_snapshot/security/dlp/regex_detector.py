"""
S.H.A.D.E. — Deterministic Regex DLP Detector
Scans input payloads for sensitive identity data, PII, and credentials.
Converts real values to 12-character synthetic placeholders (SHD_XXXXXXXX).
Performs Verhoeff validation on Aadhaar and Luhn validation on payment cards.
Enforces deterministic token reuse within active detector sessions.
"""

from dataclasses import dataclass, field
from pathlib import Path
import re
import sys
from typing import Final

# Ensure repository root is on sys.path for direct script execution and IDE analysis
_REPO_ROOT = Path(__file__).resolve().parents[2]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from security.dlp.patterns import (
    PATTERN_AADHAAR,
    PATTERN_AWS_KEY,
    PATTERN_CREDIT_CARD,
    PATTERN_EMAIL,
    PATTERN_GITHUB_TOKEN,
    PATTERN_GOOGLE_API_KEY,
    PATTERN_INDIAN_DL,
    PATTERN_INDIAN_PASSPORT,
    PATTERN_INDIAN_PHONE,
    PATTERN_INDIAN_VOTER_ID,
    PATTERN_JWT,
    PATTERN_OPENAI_KEY,
    PATTERN_PAN,
    PATTERN_PRIVATE_KEY,
    PATTERN_SECRET_ASSIGNMENT,
    PATTERN_SLACK_TOKEN,
    PATTERN_UPI,
    PATTERN_URI_PASSWORD,
    PATTERN_URL_SECRET,
    PATTERN_VEHICLE_PLATE,
    calculate_shannon_entropy,
    generate_synthetic_token,
    mask_sensitive_url,
    validate_luhn,
)
from security.validators.verhoeff import is_valid_aadhaar


@dataclass(frozen=True)
class DLPFinding:
    """Represents a single detected sensitive data element."""

    data_type: str
    raw_value: str
    masked_value: str
    synthetic_token: str
    start: int
    end: int
    confidence: float
    entropy: float = 0.0


@dataclass
class DLPScanResult:
    """Composite result of a DLP inspection pass."""

    original_text: str
    findings: list[DLPFinding] = field(default_factory=list)
    tokenized_text: str = ""
    masked_text: str = ""
    synthetic_mappings: dict[str, str] = field(default_factory=dict)

    @property
    def has_pii(self) -> bool:
        pii_types = {
            "AADHAAR",
            "PAN",
            "CREDIT_CARD",
            "EMAIL",
            "PHONE",
            "PASSPORT",
            "VOTER_ID",
            "DRIVING_LICENCE",
            "UPI_ID",
            "VEHICLE_PLATE",
        }
        return any(f.data_type in pii_types for f in self.findings)

    @property
    def has_secrets(self) -> bool:
        secret_types = {
            "API_KEY_AWS",
            "API_KEY_GITHUB",
            "API_KEY_GOOGLE",
            "API_KEY_OPENAI",
            "API_KEY_SLACK",
            "JWT_TOKEN",
            "PRIVATE_KEY",
            "URI_PASSWORD",
            "URL_SECRET",
            "HIGH_ENTROPY_SECRET",
        }
        return any(f.data_type in secret_types for f in self.findings)

    @property
    def total_findings(self) -> int:
        return len(self.findings)


class RegexDLPDetector:
    """
    Deterministic Data Loss Prevention detector.
    Identifies sensitive PII, national identifiers, and secrets using compiled regex patterns
    supplemented by mathematical checksum algorithms (Verhoeff for Aadhaar, Luhn for Cards).
    Provides in-memory deterministic token caching for repeated sensitive values.
    """

    ENTROPY_THRESHOLD: Final[float] = 3.8
    MAX_CACHE_SIZE: Final[int] = 10000

    def __init__(self, min_secret_entropy: float = 3.8) -> None:
        self.min_secret_entropy = min_secret_entropy
        # In-memory session cache ensuring deterministic token reuse across invocations
        self._token_cache: dict[str, str] = {}

    def _get_or_create_token(self, data_type: str, raw_value: str) -> str:
        """
        Retrieve existing synthetic token for value or generate a new 12-char token.
        Ensures exact deterministic reuse for identical values.
        """
        cleaned = raw_value.strip()
        if cleaned in self._token_cache:
            return self._token_cache[cleaned]

        token = generate_synthetic_token(data_type, cleaned)
        if len(self._token_cache) < self.MAX_CACHE_SIZE:
            self._token_cache[cleaned] = token
        return token

    def _mask_value(self, data_type: str, raw: str) -> str:
        """Create privacy-preserving masked representations for safe UI display."""
        cleaned = raw.strip()
        length = len(cleaned)

        if data_type == "AADHAAR":
            # Mask all but the last 4 digits (UIDAI standard: XXXXXXXX1234)
            digits_only = re.sub(r"\D", "", cleaned)
            if len(digits_only) == 12:
                return f"XXXXXXXX{digits_only[-4:]}"
            return "XXXXXXXX" + cleaned[-4:] if length >= 4 else "XXXXXXXX"

        if data_type == "PAN":
            # Retain first and last character: e.g. A*****Z
            if length == 10:
                return f"{cleaned[0]}*****{cleaned[-1]}"
            return "A*****Z"

        if data_type == "UPI_ID":
            # Mask user portion, retain PSP handle: e.g. a***@okhdfcbank
            parts = cleaned.split("@")
            if len(parts) == 2 and parts[0]:
                handle, psp = parts
                masked_handle = handle[0] + "***" if len(handle) > 1 else "*"
                return f"{masked_handle}@{psp}"
            return "***@upi"

        if data_type == "VEHICLE_PLATE":
            # Mask middle registration number: e.g. TN01****1234
            digits = re.findall(r"\d+", cleaned)
            if digits and length >= 6:
                return f"{cleaned[:4]}****{cleaned[-4:]}"
            return "XX****0000"

        if data_type == "CREDIT_CARD":
            digits_only = re.sub(r"\D", "", cleaned)
            if len(digits_only) >= 4:
                return f"****-****-****-{digits_only[-4:]}"
            return "****-****-****-****"

        if data_type == "EMAIL":
            parts = cleaned.split("@")
            if len(parts) == 2 and len(parts[0]) > 0:
                user, domain = parts
                masked_user = user[0] + "***" if len(user) > 1 else "*"
                return f"{masked_user}@{domain}"
            return "*@***.***"

        if data_type == "PHONE":
            digits_only = re.sub(r"\D", "", cleaned)
            if len(digits_only) >= 4:
                return f"+91-******{digits_only[-4:]}"
            return "******0000"

        if data_type == "URL_SECRET":
            return mask_sensitive_url(cleaned)

        if data_type.startswith("API_KEY_") or data_type in (
            "JWT_TOKEN",
            "PRIVATE_KEY",
            "HIGH_ENTROPY_SECRET",
            "URI_PASSWORD",
        ):
            # Secrets: show only first 4 chars prefix + asterisks
            if length > 8:
                return f"{cleaned[:4]}...[REDACTED_SECRET]"
            return "[REDACTED_SECRET]"

        # Default fallback
        if length > 4:
            return f"{cleaned[:2]}***{cleaned[-2:]}"
        return "****"

    def scan(self, text: str) -> DLPScanResult:
        """
        Scan text for all known sensitive patterns.
        Applies mathematical validation (Verhoeff for Aadhaar, Luhn for Cards).
        """
        if not text:
            return DLPScanResult(original_text=text)

        findings: list[DLPFinding] = []
        occupied_ranges: list[tuple[int, int]] = []

        def overlaps(start: int, end: int) -> bool:
            return any(s < end and start < e for s, e in occupied_ranges)

        def add_finding(data_type: str, raw: str, start: int, end: int, confidence: float) -> None:
            if overlaps(start, end):
                return
            entropy = calculate_shannon_entropy(raw)
            masked = self._mask_value(data_type, raw)
            token = self._get_or_create_token(data_type, raw)
            findings.append(
                DLPFinding(
                    data_type=data_type,
                    raw_value=raw,
                    masked_value=masked,
                    synthetic_token=token,
                    start=start,
                    end=end,
                    confidence=confidence,
                    entropy=entropy,
                )
            )
            occupied_ranges.append((start, end))

        # 1. Private Keys (highest precedence because they span multiline blocks)
        for match in PATTERN_PRIVATE_KEY.finditer(text):
            add_finding("PRIVATE_KEY", match.group(0), match.start(), match.end(), 1.0)

        # 2. URLs with sensitive query parameters (e.g. ?token=XYZ, ?password=XYZ)
        for match in PATTERN_URL_SECRET.finditer(text):
            add_finding("URL_SECRET", match.group(0), match.start(), match.end(), 0.95)

        # 3. Connection URIs with embedded credentials (e.g. postgres://user:pass@host)
        for match in PATTERN_URI_PASSWORD.finditer(text):
            add_finding("URI_PASSWORD", match.group(1), match.start(1), match.end(1), 0.90)

        # 4. Aadhaar Numbers (Verified strictly with Verhoeff D5 algorithm)
        for match in PATTERN_AADHAAR.finditer(text):
            candidate = match.group(1)
            if is_valid_aadhaar(candidate):
                add_finding("AADHAAR", candidate, match.start(1), match.end(1), 1.0)

        # 5. PAN Cards (Exact structure validation)
        for match in PATTERN_PAN.finditer(text):
            candidate = match.group(1)
            add_finding("PAN", candidate, match.start(1), match.end(1), 0.98)

        # 6. Credit / Debit Cards (Verified strictly with Luhn algorithm)
        for match in PATTERN_CREDIT_CARD.finditer(text):
            candidate = match.group(0)
            if validate_luhn(candidate):
                add_finding("CREDIT_CARD", candidate, match.start(), match.end(), 0.99)

        # 7. Indian Vehicle Registration Plates
        for match in PATTERN_VEHICLE_PLATE.finditer(text):
            candidate = match.group(1)
            add_finding("VEHICLE_PLATE", candidate, match.start(1), match.end(1), 0.95)

        # 8. UPI Virtual Payment Addresses (prioritized before general emails)
        for match in PATTERN_UPI.finditer(text):
            candidate = match.group(1)
            add_finding("UPI_ID", candidate, match.start(1), match.end(1), 0.95)

        # 9. API Keys & Credentials
        for match in PATTERN_AWS_KEY.finditer(text):
            add_finding("API_KEY_AWS", match.group(1), match.start(1), match.end(1), 0.99)

        for match in PATTERN_GITHUB_TOKEN.finditer(text):
            add_finding("API_KEY_GITHUB", match.group(1), match.start(1), match.end(1), 0.99)

        for match in PATTERN_GOOGLE_API_KEY.finditer(text):
            add_finding("API_KEY_GOOGLE", match.group(1), match.start(1), match.end(1), 0.98)

        for match in PATTERN_OPENAI_KEY.finditer(text):
            add_finding("API_KEY_OPENAI", match.group(1), match.start(1), match.end(1), 0.99)

        for match in PATTERN_SLACK_TOKEN.finditer(text):
            add_finding("API_KEY_SLACK", match.group(1), match.start(1), match.end(1), 0.99)

        for match in PATTERN_JWT.finditer(text):
            add_finding("JWT_TOKEN", match.group(1), match.start(1), match.end(1), 0.95)

        # 10. Secondary Indian Documents
        for match in PATTERN_INDIAN_PASSPORT.finditer(text):
            add_finding("PASSPORT", match.group(1), match.start(1), match.end(1), 0.90)

        for match in PATTERN_INDIAN_VOTER_ID.finditer(text):
            add_finding("VOTER_ID", match.group(1), match.start(1), match.end(1), 0.90)

        for match in PATTERN_INDIAN_DL.finditer(text):
            add_finding("DRIVING_LICENCE", match.group(1), match.start(1), match.end(1), 0.90)

        # 11. Contact PII: Phone & General Email
        for match in PATTERN_INDIAN_PHONE.finditer(text):
            candidate = match.group(0).strip()
            digits = re.sub(r"\D", "", candidate)
            if 10 <= len(digits) <= 12:
                add_finding("PHONE", candidate, match.start(), match.end(), 0.90)

        for match in PATTERN_EMAIL.finditer(text):
            add_finding("EMAIL", match.group(0), match.start(), match.end(), 0.95)

        # 12. High-Entropy Secret Assignments
        for match in PATTERN_SECRET_ASSIGNMENT.finditer(text):
            candidate = match.group(1)
            entropy = calculate_shannon_entropy(candidate)
            if entropy >= self.min_secret_entropy and len(candidate) >= 16:
                add_finding(
                    "HIGH_ENTROPY_SECRET",
                    candidate,
                    match.start(1),
                    match.end(1),
                    min(0.70 + (entropy / 10.0), 0.95),
                )

        # Sort findings by start position
        findings.sort(key=lambda f: f.start)

        # Build tokenized text, masked text, and mapping table
        tokenized_parts: list[str] = []
        masked_parts: list[str] = []
        synthetic_mappings: dict[str, str] = {}
        last_index = 0

        for f in findings:
            tokenized_parts.append(text[last_index : f.start])
            tokenized_parts.append(f.synthetic_token)

            masked_parts.append(text[last_index : f.start])
            masked_parts.append(f.masked_value)

            synthetic_mappings[f.synthetic_token] = f.raw_value
            last_index = f.end

        tokenized_parts.append(text[last_index:])
        masked_parts.append(text[last_index:])

        tokenized_text = "".join(tokenized_parts)
        masked_text = "".join(masked_parts)

        return DLPScanResult(
            original_text=text,
            findings=findings,
            tokenized_text=tokenized_text,
            masked_text=masked_text,
            synthetic_mappings=synthetic_mappings,
        )

    def mask(self, text: str) -> str:
        """Convenience method returning masked string."""
        return self.scan(text).masked_text

    def tokenize(self, text: str) -> tuple[str, dict[str, str]]:
        """Convenience method returning synthetic string and token mappings."""
        result = self.scan(text)
        return result.tokenized_text, result.synthetic_mappings
