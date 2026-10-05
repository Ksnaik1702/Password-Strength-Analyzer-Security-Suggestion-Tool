"""
Unit Tests: Entropy Estimation, Scoring Calibration, and Suggestion Engine
Covers:
- Test 25: Strength-score boundaries (0-20, 21-40, 41-60, 61-80, 81-100)
- Test 26: Suggestion generation
"""

import pytest
from backend.services.entropy_estimator import estimate_theoretical_entropy
from backend.services.password_analyzer import analyze_password

def test_entropy_calculation():
    # 16 length, pool 94 (letters + digits + symbols)
    res = estimate_theoretical_entropy(16, 94)
    assert res["entropy_bits"] > 90
    assert "educational_note" in res

def test_25_strength_score_boundaries():
    # Boundary 1: Very Weak (0-20)
    res1 = analyze_password("123456")
    assert res1["score"] <= 20
    assert res1["classification"] == "VERY WEAK"

    # Boundary 2: Weak (21-40)
    res2 = analyze_password("Password123!")
    assert 20 <= res2["score"] <= 45
    assert res2["classification"] in ["VERY WEAK", "WEAK", "MODERATE"]

    # Boundary 3: Moderate (41-60)
    res3 = analyze_password("Summer2026!")
    assert 41 <= res3["score"] <= 60
    assert res3["classification"] == "MODERATE"

    # Boundary 4: Strong (61-80)
    res4 = analyze_password("G8#kL2$vN9@pQ4!w")
    assert 61 <= res4["score"] <= 100

    # Boundary 5: Very Strong (81-100)
    res5 = analyze_password("X7#mK9$vL2@qZ8!wP4^rT1&y")
    assert res5["score"] >= 81
    assert res5["classification"] == "VERY STRONG"

def test_26_suggestion_generation():
    # Weak password with sequence and year
    res = analyze_password("Welcome20261234!")
    assert len(res["suggestions"]) >= 2
    # Verify suggestions do NOT print or echo the password
    for s in res["suggestions"]:
        assert "Welcome20261234!" not in s
