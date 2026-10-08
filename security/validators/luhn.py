"""
S.H.A.D.E. — Luhn (Mod 10) Checksum Algorithm
Role: Member 2 — Security & DLP Engine

Used for validating credit and debit card number formats.
"""


def validate_luhn(card_number: str) -> bool:
    """Validate a card number using the Luhn algorithm (Mod 10)."""
    digits = [int(c) for c in str(card_number) if c.isdigit()]
    if len(digits) < 10 or len(digits) > 19:
        return False

    checksum = 0
    parity = len(digits) % 2
    for i, digit in enumerate(digits):
        if i % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0
