"""
S.H.A.D.E. — Unit Tests for Verhoeff Checksum & Aadhaar Validation
"""

import unittest

from security.validators.verhoeff import (
    generate_check_digit,
    is_valid_aadhaar,
    validate_verhoeff,
)


class TestVerhoeffAlgorithm(unittest.TestCase):
    """Test suite for dihedral group D5 Verhoeff checksum algorithm."""

    def test_verhoeff_checksum_known_values(self):
        # Known valid numbers under Verhoeff algorithm
        # Number: 236 -> check digit calculation:
        # e.g., 2363 is valid
        check_digit = generate_check_digit("236")
        self.assertTrue(validate_verhoeff(f"236{check_digit}"))

        # Number: 142857
        cd = generate_check_digit("142857")
        self.assertTrue(validate_verhoeff(f"142857{cd}"))

    def test_verhoeff_detects_single_digit_transposition(self):
        # Generate valid number
        base = "98765432101"
        cd = generate_check_digit(base)
        valid_num = f"{base}{cd}"
        self.assertTrue(validate_verhoeff(valid_num))

        # Transposition error: swap adjacent digits '98' -> '89'
        transposed = f"89{valid_num[2:]}"
        self.assertFalse(validate_verhoeff(transposed))

    def test_verhoeff_detects_single_digit_replacement(self):
        base = "34567891234"
        cd = generate_check_digit(base)
        valid_num = f"{base}{cd}"
        self.assertTrue(validate_verhoeff(valid_num))

        # Single digit corruption
        corrupted = valid_num[:-1] + str((cd + 1) % 10)
        self.assertFalse(validate_verhoeff(corrupted))

    def test_aadhaar_validation_rules(self):
        # Rule 1: First digit cannot be 0 or 1
        base_starting_zero = "01234567890"
        cd_zero = generate_check_digit(base_starting_zero)
        self.assertFalse(is_valid_aadhaar(f"{base_starting_zero}{cd_zero}"))

        base_starting_one = "12345678901"
        cd_one = generate_check_digit(base_starting_one)
        self.assertFalse(is_valid_aadhaar(f"{base_starting_one}{cd_one}"))

        # Rule 2: Must be exactly 12 digits
        base_valid = "23456789012"
        cd_valid = generate_check_digit(base_valid)
        valid_aadhaar = f"{base_valid}{cd_valid}"
        self.assertTrue(is_valid_aadhaar(valid_aadhaar))

        # Spaced format: '2345 6789 012X'
        spaced_aadhaar = f"{valid_aadhaar[:4]} {valid_aadhaar[4:8]} {valid_aadhaar[8:]}"
        self.assertTrue(is_valid_aadhaar(spaced_aadhaar))

        # Hyphenated format: '2345-6789-012X'
        hyphen_aadhaar = f"{valid_aadhaar[:4]}-{valid_aadhaar[4:8]}-{valid_aadhaar[8:]}"
        self.assertTrue(is_valid_aadhaar(hyphen_aadhaar))

        # Too short (11 digits)
        self.assertFalse(is_valid_aadhaar(valid_aadhaar[:-1]))

        # Non-numeric
        self.assertFalse(is_valid_aadhaar("23456789ABCD"))


if __name__ == "__main__":
    unittest.main()
