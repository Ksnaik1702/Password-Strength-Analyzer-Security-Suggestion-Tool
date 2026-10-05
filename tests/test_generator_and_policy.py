"""
Unit Tests: Secure Generator, Policy Validation, and Hashing Demo
Covers:
- Test 27: Secure password generation
- NIST SP 800-63B policy checks
- Salted hashing and verification
"""

import pytest
from backend.services.password_generator import generate_complex_password, generate_passphrase
from backend.services.policy_checker import check_policy_compliance
from backend.services.hashing_demo import demonstrate_hashing, verify_password_hash

def test_27_secure_password_generation():
    # Test complex password generator
    pw = generate_complex_password(length=20, include_upper=True, include_lower=True, include_digits=True, include_symbols=True)
    assert len(pw) == 20
    assert any(c.isupper() for c in pw)
    assert any(c.islower() for c in pw)
    assert any(c.isdigit() for c in pw)

    # Test passphrase generator
    phrase = generate_passphrase(words_count=4, separator="-")
    parts = phrase.split("-")
    assert len(parts) == 4
    for p in parts:
        assert len(p) >= 3

def test_policy_compliance():
    # Pass policy
    res_pass = check_policy_compliance("Correct-Horse-Battery-Staple-2026", min_length=12)
    assert res_pass["policy_passed"] is True
    assert res_pass["status"] == "POLICY PASS"

    # Fail policy (too short)
    res_fail = check_policy_compliance("Short1!", min_length=12)
    assert res_fail["policy_passed"] is False
    assert res_fail["status"] == "POLICY FAIL"

def test_hashing_and_verification():
    secret = "TestSyntheticSecretPass2026!"
    demo = demonstrate_hashing(secret)
    assert demo["algorithm"] == "PBKDF2-HMAC-SHA256"
    assert demo["iterations"] == 600000
    assert len(demo["salt_hex"]) == 32  # 16 bytes = 32 hex chars

    stored_format = demo["stored_hash_format"]

    # Verify matching password
    assert verify_password_hash(secret, stored_format) is True

    # Verify non-matching password
    assert verify_password_hash("WrongPassword123!", stored_format) is False
