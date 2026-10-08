"""
S.H.A.D.E. — Mathematical Document Validators
Verhoeff Dihedral D5 Checksum Algorithm Implementation.

Uidai official specification for 12-digit Indian Aadhaar numbers.
Operates deterministically over the dihedral group D5.
"""

from typing import Final, Sequence

# Multiplication table (d) over dihedral group D5
_VERHOEFF_D: Final[tuple[tuple[int, ...], ...]] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 2, 3, 4, 0, 6, 7, 8, 9, 5),
    (2, 3, 4, 0, 1, 7, 8, 9, 5, 6),
    (3, 4, 0, 1, 2, 8, 9, 5, 6, 7),
    (4, 0, 1, 2, 3, 9, 5, 6, 7, 8),
    (5, 9, 8, 7, 6, 0, 4, 3, 2, 1),
    (6, 5, 9, 8, 7, 1, 0, 4, 3, 2),
    (7, 6, 5, 9, 8, 2, 1, 0, 4, 3),
    (8, 7, 6, 5, 9, 3, 2, 1, 0, 4),
    (9, 8, 7, 6, 5, 4, 3, 2, 1, 0),
)

# Permutation table (p) over indices 0..7
_VERHOEFF_P: Final[tuple[tuple[int, ...], ...]] = (
    (0, 1, 2, 3, 4, 5, 6, 7, 8, 9),
    (1, 5, 7, 6, 2, 8, 3, 0, 9, 4),
    (5, 8, 0, 3, 7, 9, 6, 1, 4, 2),
    (8, 9, 1, 6, 0, 4, 3, 5, 2, 7),
    (9, 4, 5, 3, 1, 2, 6, 8, 7, 0),
    (4, 2, 8, 6, 5, 7, 3, 9, 0, 1),
    (2, 7, 9, 3, 8, 0, 6, 4, 1, 5),
    (7, 0, 4, 6, 9, 1, 3, 2, 5, 8),
)

# Inverse table (inv) over elements 0..9
_VERHOEFF_INV: Final[tuple[int, ...]] = (0, 4, 3, 2, 1, 5, 6, 7, 8, 9)


def validate_verhoeff(number: str | Sequence[int]) -> bool:
    """
    Validate a numeric string or sequence using the Verhoeff checksum algorithm.

    :param number: The number string (including check digit).
    :return: True if the checksum evaluates to 0, False otherwise.
    """
    if isinstance(number, str):
        cleaned = number.strip().replace(" ", "").replace("-", "")
        if not cleaned.isdigit() or len(cleaned) == 0:
            return False
        digits = [int(ch) for ch in cleaned]
    else:
        digits = list(number)
        if not digits:
            return False

    c = 0
    # Process digits in reverse order (right-to-left)
    for i, digit in enumerate(reversed(digits)):
        if digit < 0 or digit > 9:
            return False
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][digit]]

    return c == 0


def generate_check_digit(number: str | Sequence[int]) -> int:
    """
    Calculate the Verhoeff check digit for a given base number.

    :param number: Numeric string or integer sequence without check digit.
    :return: An integer check digit (0-9).
    :raises ValueError: If input contains invalid characters.
    """
    if isinstance(number, str):
        cleaned = number.strip().replace(" ", "").replace("-", "")
        if not cleaned.isdigit() or len(cleaned) == 0:
            raise ValueError(f"Invalid numeric input for Verhoeff check digit: {number!r}")
        digits = [int(ch) for ch in cleaned]
    else:
        digits = list(number)
        if not digits:
            raise ValueError("Empty sequence provided for Verhoeff check digit generation.")

    c = 0
    # Process in reverse order with permutation offset by 1
    for i, digit in enumerate(reversed(digits)):
        if digit < 0 or digit > 9:
            raise ValueError(f"Digit out of bounds: {digit}")
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][digit]]

    return _VERHOEFF_INV[c]


def is_valid_aadhaar(number: str) -> bool:
    """
    Verify whether a string is a structurally and mathematically valid 12-digit Indian Aadhaar number.

    Validation criteria according to UIDAI:
    1. Exactly 12 digits (ignoring whitespace and hyphens).
    2. First digit must NOT be '0' or '1' (must be in range 2..9).
    3. Satisfies the Verhoeff D5 dihedral checksum algorithm.

    :param number: Candidate Aadhaar string (e.g., '2345 6789 0123' or '234567890123').
    :return: True if valid, False otherwise.
    """
    if not isinstance(number, str):
        return False

    cleaned = number.strip().replace(" ", "").replace("-", "")
    if len(cleaned) != 12 or not cleaned.isdigit():
        return False

    # UIDAI specification: First digit of Aadhaar is never 0 or 1
    if cleaned[0] in ("0", "1"):
        return False

    return validate_verhoeff(cleaned)
