"""
S.H.A.D.E. — Deterministic DLP Pattern Suite
Defines compiled regular expressions, entropy calculators, and synthetic token formatters.

Conforms to S.H.A.D.E. Local-First Specification:
- Deterministic regex matching (Zero cloud reliance)
- Synthetic token placeholder formatting: exactly 12 characters (SHD_XXXXXXXX)
- Shannon entropy evaluation for high-entropy secret detection
"""

import hashlib
import math
import re
from typing import Final, Optional
from urllib.parse import parse_qsl, urlsplit, urlunsplit

# ============================================================================
# 1. INDIAN PII REGULAR EXPRESSIONS
# ============================================================================

# Indian Aadhaar 12-digit number (supports spaced/hyphenated formats)
# Note: First digit must be 2-9 (0 and 1 are invalid per UIDAI).
PATTERN_AADHAAR: Final[re.Pattern[str]] = re.compile(
    r"\b([2-9]\d{3}[\s-]?(?:\d{4}[\s-]?)\d{4})\b"
)

# Indian Permanent Account Number (PAN)
# Format: 5 uppercase letters + 4 digits + 1 uppercase letter
# (4th character represents entity: P=Person, C=Company, H=HUF, F=Firm, etc.)
PATTERN_PAN: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Z]{5}\d{4}[A-Z])\b"
)

# Indian Phone Numbers (Mobile: Starts with 6, 7, 8, or 9; optional +91/91/0 prefix)
PATTERN_INDIAN_PHONE: Final[re.Pattern[str]] = re.compile(
    r"(?:\b|(?<=\s))(?:(?:\+91[\-\s]?|91[\-\s]?|0)?[6-9]\d{9})(?=\b|[^\d]|$)"
)

# Indian Passport Number (1 uppercase letter + 7 digits, 2nd digit is not 0)
PATTERN_INDIAN_PASSPORT: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Z][1-9]\d{7})\b"
)

# Indian Voter ID (EPIC Number)
PATTERN_INDIAN_VOTER_ID: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Z]{3}\d{7})\b"
)

# Indian Driving Licence (State code 2 letters + 2 digit RTO + year/sequence)
PATTERN_INDIAN_DL: Final[re.Pattern[str]] = re.compile(
    r"\b([A-Z]{2}[-\s]?\d{2}[-\s]?\d{11})\b"
)

# Indian Vehicle Registration Number Plate
# Format: 2-letter state code + 1-2 digit RTO + 1-3 letters series + 4 digits
_INDIAN_STATE_CODES: Final[str] = (
    "AN|AP|AR|AS|BR|CH|CG|DN|DD|DL|GA|GJ|HR|HP|JK|JH|KA|KL|LA|LD|MP|MH|MN|ML|MZ|NL|OD|PB|PY|RJ|SK|TN|TS|TR|UP|UK|WB|BH"
)
PATTERN_VEHICLE_PLATE: Final[re.Pattern[str]] = re.compile(
    rf"\b((?:{_INDIAN_STATE_CODES})[\s-]?[0-9]{{1,2}}[\s-]?[A-Z]{{1,3}}[\s-]?[0-9]{{4}})\b"
)

# Unified Payments Interface (UPI) ID / VPA
# e.g., alice@okhdfcbank, mobile@upi, user@paytm, 9876543210@sbi
# Avoids matching standard email addresses that contain typical email TLDs (.com, .org, .net, etc.)
PATTERN_UPI: Final[re.Pattern[str]] = re.compile(
    r"\b([a-zA-Z0-9.\-_]{2,64}@"
    r"(?:upi|okaxis|okhdfcbank|oksbi|okicici|paytm|ybl|ibl|axl|apl|idfcbank|federal|barodampay|indus|kotak|pnb|citi|boi|cnrb|aubank|jupiteraxis|yesbank|freecharge|airtel|postbank|"
    r"(?![a-zA-Z0-9.\-_]*(?:\.com|\.org|\.net|\.io|\.gov|\.edu|\.co|\.mil|\.info|\.me|\.dev))[a-zA-Z0-9]{2,30}))\b",
    re.IGNORECASE,
)

# ============================================================================
# 2. FINANCIAL & GENERAL PII REGULAR EXPRESSIONS
# ============================================================================

# Credit / Debit Card Numbers (Visa, Mastercard, Amex, Discover, RuPay)
PATTERN_CREDIT_CARD: Final[re.Pattern[str]] = re.compile(
    r"\b(?:"
    r"4\d{3}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|"  # Visa
    r"5[1-5]\d{2}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|"  # Mastercard
    r"3[47]\d{2}[\s-]?\d{6}[\s-]?\d{5}|"  # Amex
    r"6(?:011|5\d{2})[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}|"  # Discover
    r"(?:508[5-9]|6069|607[0-9]|608[0-4]|6521|6522)\d{12}"  # RuPay
    r")\b"
)

# Email Address
PATTERN_EMAIL: Final[re.Pattern[str]] = re.compile(
    r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"
)

# IPv4 Address (excluding 0.0.0.0)
PATTERN_IPV4: Final[re.Pattern[str]] = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}"
    r"(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)

# ============================================================================
# 3. SECRETS, CREDENTIALS, API TOKENS & SENSITIVE URLS
# ============================================================================

# AWS Access Key ID (AKIA, ABIA, ACCA, ASIA)
PATTERN_AWS_KEY: Final[re.Pattern[str]] = re.compile(
    r"\b((?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16})\b"
)

# GitHub Personal Access Token / Fine-grained token
PATTERN_GITHUB_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,255})\b"
)

# Google API Key
PATTERN_GOOGLE_API_KEY: Final[re.Pattern[str]] = re.compile(
    r"\b(AIza[0-9A-Za-z\-_]{35})\b"
)

# OpenAI API Key
PATTERN_OPENAI_KEY: Final[re.Pattern[str]] = re.compile(
    r"\b(sk-(?:proj-|none-)?[A-Za-z0-9_\-]{32,64})\b"
)

# Slack API Token
PATTERN_SLACK_TOKEN: Final[re.Pattern[str]] = re.compile(
    r"\b(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,32})\b"
)

# JSON Web Token (JWT)
PATTERN_JWT: Final[re.Pattern[str]] = re.compile(
    r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"
)

# RSA / EC / DSA / OpenSSH Private Key Block
PATTERN_PRIVATE_KEY: Final[re.Pattern[str]] = re.compile(
    r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
)

# Password embedded in connection URI / URL (e.g., postgresql://user:pass@host)
PATTERN_URI_PASSWORD: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b[a-z]{3,10}:\/\/[^:\/\s]+:([^@\/\s]{3,})@[^\/\s]+"
)

# URL containing embedded secrets in query parameters
# e.g., https://example.com/api?token=SECRET_VALUE or ?password=XYZ
SENSITIVE_QUERY_PARAMS: Final[set[str]] = {
    "password",
    "passwd",
    "pwd",
    "token",
    "api_key",
    "apikey",
    "secret",
    "access_token",
    "auth",
    "authorization",
}

PATTERN_URL_SECRET: Final[re.Pattern[str]] = re.compile(
    r"\bhttps?:\/\/[^\s/?#]+[^\s]*?[?&](?:[^=\s&]+=(?:[^&\s]*&)*)?"
    r"(?:password|passwd|pwd|token|api_key|apikey|secret|access_token|auth|authorization)"
    r"=[^&\s]{4,}[^\s]*",
    re.IGNORECASE,
)

# Generic High-Entropy Secret assignments (e.g., api_secret = '...', password = '...')
PATTERN_SECRET_ASSIGNMENT: Final[re.Pattern[str]] = re.compile(
    r"(?i)\b(?:secret|password|api[_-]?key|access[_-]?token|auth[_-]?token|bearer)"
    r"[\s:=]+['\"]?([A-Za-z0-9_\-\.\/+=]{16,})['\"]?"
)


# ============================================================================
# 4. STATISTICAL & MATHEMATICAL HELPERS
# ============================================================================

def calculate_shannon_entropy(data: str) -> float:
    """
    Compute the Shannon entropy of a string.
    High entropy (typically > 3.5 for hex or > 4.5 for alphanumeric) indicates
    cryptographic keys, random tokens, or compressed/encrypted secrets.

    :param data: Input string.
    :return: Float Shannon entropy in bits per character.
    """
    if not data:
        return 0.0

    length = len(data)
    frequencies: dict[str, int] = {}
    for char in data:
        frequencies[char] = frequencies.get(char, 0) + 1

    entropy = 0.0
    for count in frequencies.values():
        p = count / length
        entropy -= p * math.log2(p)

    return entropy


def validate_luhn(card_number: str) -> bool:
    """
    Validate a card number string using the Luhn mod-10 algorithm.

    :param card_number: Candidate credit/debit card number.
    :return: True if valid Luhn checksum, False otherwise.
    """
    cleaned = card_number.replace(" ", "").replace("-", "")
    if not cleaned.isdigit() or len(cleaned) < 13 or len(cleaned) > 19:
        return False

    digits = [int(d) for d in cleaned]
    checksum = 0
    reverse_digits = digits[::-1]

    for idx, d in enumerate(reverse_digits):
        if idx % 2 == 1:
            doubled = d * 2
            checksum += doubled - 9 if doubled > 9 else doubled
        else:
            checksum += d

    return checksum % 10 == 0


def generate_synthetic_token(data_type_or_value: str, real_value: Optional[str] = None) -> str:
    """
    Generate an exact 12-character synthetic placeholder token (SHD_XXXXXXXX).

    Conforms to S.H.A.D.E. Product Requirements (Section 7 & 11.2):
    - Exact 12 characters length (len == 12)
    - Starts with 'SHD_' (4 chars)
    - Followed by 8 uppercase hexadecimal characters (XXXXXXXX)
    - Deterministic across identical sensitive values
    - Completely safe for external egress (contains zero plaintext data)

    :param data_type_or_value: Identifier category (e.g. 'AADHAAR') or target value.
    :param real_value: Real sensitive value if first argument is data_type.
    :return: 12-character synthetic token string (e.g. 'SHD_7F29B810').
    """
    target = real_value if real_value is not None else data_type_or_value
    cleaned_target = str(target).strip()
    # Compute deterministic SHA-256 digest
    digest = hashlib.sha256(cleaned_target.encode("utf-8")).hexdigest()[:8].upper()
    return f"SHD_{digest}"


def mask_sensitive_url(url: str) -> str:
    """
    Mask sensitive query parameters (password, token, etc.) within a URL
    while preserving the base protocol, domain, and safe query structure.
    """
    try:
        parts = urlsplit(url)
        if not parts.query:
            return url

        pairs = parse_qsl(parts.query, keep_blank_values=True)
        masked_pairs: list[tuple[str, str]] = []
        for key, val in pairs:
            if key.lower() in SENSITIVE_QUERY_PARAMS:
                masked_pairs.append((key, "[REDACTED_SECRET]"))
            else:
                masked_pairs.append((key, val))

        new_query = "&".join(f"{k}={v}" for k, v in masked_pairs)
        return urlunsplit((parts.scheme, parts.netloc, parts.path, new_query, parts.fragment))
    except Exception:
        # Fallback regex mask if urlsplit fails
        return re.sub(
            r"((?:password|passwd|pwd|token|api_key|apikey|secret|access_token|auth|authorization)=)([^&\s]+)",
            r"\1[REDACTED_SECRET]",
            url,
            flags=re.IGNORECASE,
        )
