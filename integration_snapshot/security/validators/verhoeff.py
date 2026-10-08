"""
S.H.A.D.E. — Mathematical Dihedral Group D5 Verhoeff Checksum Algorithm
Role: Member 2 — Security & DLP Engine

Implements the official Verhoeff checksum algorithm for 12-digit Indian Aadhaar validation.
Aadhaar numbers MUST pass this dihedral D5 permutation check to be classified as valid Aadhaar.
"""

from typing import Union


# The multiplication table (dihedral group D5)
_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

# The permutation table
_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]

# The inverse table
_INV = [0, 4, 3, 2, 1, 5, 6, 7, 8, 9]


def compute_checksum(number: Union[str, int]) -> int:
    """Compute the Verhoeff checksum digit for a given number string."""
    num_str = str(number).strip()
    c = 0
    reversed_digits = [int(x) for x in reversed(num_str)]
    for i, digit in enumerate(reversed_digits):
        c = _D[c][_P[(i + 1) % 8][digit]]
    return _INV[c]


def validate_verhoeff(number: Union[str, int]) -> bool:
    """
    Validate a number containing a Verhoeff check digit.
    Returns True if the check digit is valid according to D5 permutation.
    """
    num_str = str(number).strip()
    if not num_str.isdigit():
        return False

    c = 0
    reversed_digits = [int(x) for x in reversed(num_str)]
    for i, digit in enumerate(reversed_digits):
        c = _D[c][_P[i % 8][digit]]
    return c == 0


def validate_aadhaar_number(raw_aadhaar: str) -> bool:
    """
    Validate an Aadhaar number according to UIDAI specifications:
    1. Exactly 12 digits after stripping whitespace and hyphens.
    2. Does not start with '0' or '1'.
    3. Validates against the Dihedral D5 Verhoeff checksum.
    """
    clean = "".join(ch for ch in str(raw_aadhaar) if ch.isdigit())
    if len(clean) != 12:
        return False
    if clean[0] in ("0", "1"):
        return False
    return validate_verhoeff(clean)
