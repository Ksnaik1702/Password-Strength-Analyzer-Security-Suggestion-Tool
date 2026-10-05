"""
Unit Tests: Password Analyzer & Character/Length Handling
Covers:
- Test 1: Empty password
- Test 2: One-character password
- Test 3: Short numeric password
- Test 4: Common password
- Test 5: Long repeated password
- Test 6: Lowercase only
- Test 7: Uppercase only
- Test 8: Numbers only
- Test 9: Symbols only
- Test 10: Mixed characters
- Test 21: Long passphrase-like input
- Test 22: Unicode handling
- Test 23: Space handling
- Test 24: Maximum accepted length
"""

import pytest
from backend.services.password_analyzer import analyze_password
from backend.services.length_analyzer import analyze_length
from backend.services.character_analyzer import analyze_characters

def test_01_empty_password():
    res = analyze_password("")
    assert res["score"] == 0
    assert res["classification"] == "VERY WEAK"
    assert res["metrics"]["length"] == 0

def test_02_one_character_password():
    res = analyze_password("x")
    assert res["score"] <= 15
    assert res["classification"] == "VERY WEAK"
    assert res["metrics"]["length"] == 1

def test_03_short_numeric_password():
    res = analyze_password("12345")
    assert res["score"] <= 20
    assert res["classification"] == "VERY WEAK"

def test_04_common_password():
    res = analyze_password("password")
    assert res["score"] <= 20
    assert res["classification"] == "VERY WEAK"
    assert any(f["type"] == "common_password" for f in res["findings"])

def test_05_long_repeated_password():
    res = analyze_password("aaaaaaaaaaaaaaaa")
    # Even though 16 chars, repetition should heavily penalize it
    assert res["score"] <= 35
    assert res["classification"] in ["VERY WEAK", "WEAK"]
    assert any(f["type"] == "repetition" for f in res["findings"])

def test_06_lowercase_only():
    res = analyze_password("supersecretproject")
    char_info = analyze_characters("supersecretproject")
    assert char_info["has_lower"] is True
    assert char_info["has_upper"] is False
    assert char_info["character_type_count"] == 1

def test_07_uppercase_only():
    char_info = analyze_characters("SUPERSECRET")
    assert char_info["has_upper"] is True
    assert char_info["has_lower"] is False
    assert char_info["has_digits"] is False

def test_08_numbers_only():
    char_info = analyze_characters("839201948201")
    assert char_info["has_digits"] is True
    assert char_info["has_symbols"] is False
    assert char_info["character_type_count"] == 1

def test_09_symbols_only():
    char_info = analyze_characters("!@#$%^&*()")
    assert char_info["has_symbols"] is True
    assert char_info["has_digits"] is False

def test_10_mixed_characters():
    res = analyze_password("K7#mQ9!vX2$wZ8@p")
    assert res["metrics"]["character_type_count"] == 4
    assert res["score"] >= 75
    assert res["classification"] in ["STRONG", "VERY STRONG"]

def test_21_long_passphrase():
    res = analyze_password("velvet-harbor-drift-galaxy")
    assert res["metrics"]["length"] >= 20
    assert res["score"] >= 65
    assert res["classification"] in ["STRONG", "VERY STRONG"]

def test_22_unicode_handling():
    res = analyze_password("München-Über-Café-2026!")
    assert res["metrics"]["length"] > 0
    assert isinstance(res["score"], int)

def test_23_space_handling():
    res = analyze_password("correct horse battery staple")
    assert res["metrics"]["has_spaces"] is True
    assert res["score"] >= 60

def test_24_maximum_accepted_length():
    long_pw = "A1!" + "x" * 200
    res = analyze_password(long_pw)
    assert res["metrics"]["length"] == 203
    assert res["score"] > 0
