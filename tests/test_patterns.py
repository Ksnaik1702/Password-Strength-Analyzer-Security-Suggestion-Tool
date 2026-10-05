"""
Unit Tests: Pattern, Sequence, Keyboard, and Context Detection
Covers:
- Test 11: Sequential numbers
- Test 12: Reverse numeric sequence
- Test 13: Sequential letters
- Test 14: Keyboard sequence
- Test 15: Repeated characters
- Test 16: Repeated substring
- Test 17: Common word + number
- Test 18: Word + year
- Test 19: Personal name overlap
- Test 20: Birth year overlap
"""

import pytest
from backend.services.sequence_detector import detect_sequences
from backend.services.keyboard_detector import detect_keyboard_patterns
from backend.services.repetition_detector import detect_repetition
from backend.services.pattern_detector import detect_predictable_structure
from backend.services.password_analyzer import analyze_password

def test_11_sequential_numbers():
    res = detect_sequences("pass1234word")
    assert res["has_sequence"] is True
    assert any("1234" in s for s in res["detected_sequences"])

def test_12_reverse_numeric_sequence():
    res = detect_sequences("safe9876code")
    assert res["has_sequence"] is True
    assert any("9876" in s for s in res["detected_sequences"])

def test_13_sequential_letters():
    res = detect_sequences("myabcdpass")
    assert res["has_sequence"] is True
    assert any("abcd" in s for s in res["detected_sequences"])

def test_14_keyboard_sequence():
    res = detect_keyboard_patterns("myqwertytest")
    assert res["has_keyboard_pattern"] is True
    assert any("qwerty" in p for p in res["detected_patterns"])

def test_15_repeated_characters():
    res = detect_repetition("hellloooo999")
    assert res["has_repetition"] is True
    assert len(res["repeated_characters"]) > 0

def test_16_repeated_substring():
    res = detect_repetition("ababab1212")
    assert res["has_repetition"] is True
    assert len(res["repeated_substrings"]) > 0

def test_17_common_word_plus_number():
    res = detect_predictable_structure("welcome123")
    assert res["has_predictable_structure"] is True
    assert res["has_word_number"] is True

def test_18_word_plus_year():
    res = detect_predictable_structure("admin2026!")
    assert res["has_year"] is True
    assert any("2026" in f for f in res["detected_features"])

def test_19_personal_name_overlap():
    context = {"first_name": "Rahul"}
    res = detect_predictable_structure("Rahul@123", personal_context=context)
    assert res["has_personal_info"] is True
    assert "First Name" in res["personal_matches"]

def test_20_birth_year_overlap():
    context = {"birth_year": "1998"}
    res = detect_predictable_structure("SecurePass1998!", personal_context=context)
    assert res["has_personal_info"] is True
    assert "Birth Year" in res["personal_matches"]
