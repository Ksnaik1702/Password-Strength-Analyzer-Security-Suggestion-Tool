"""
Length Analysis Module
Evaluates password length and returns metrics, educational band, and base points.

Industry context:
Length is the single most significant factor in expanding the keyspace against
brute-force attacks. However, length alone is insufficient if the password is
repetitive or predictable (e.g. 'aaaaaaaaaaaaaaaa' is 16 chars but trivial to crack).
"""

from typing import Dict, Any

def analyze_length(password: str) -> Dict[str, Any]:
    """
    Analyzes the length of a password.
    
    Bands:
      < 8    : Very Short (High Risk)
      8-11   : Short (Needs Improvement)
      12-15  : Better Length (Moderate/Good baseline)
      16+    : Strong Length (Recommended baseline for high-value credentials)
    """
    length = len(password)
    
    if length == 0:
        return {
            "length": 0,
            "band": "Empty",
            "score_contribution": 0,
            "description": "Password is empty.",
            "is_acceptable_minimum": False
        }
    elif length < 8:
        band = "Very Short"
        score_contribution = min(10, length * 1.2)
        is_acceptable = False
        desc = "Critically short. Modern offline brute-force attacks can crack <8 characters quickly."
    elif 8 <= length <= 11:
        band = "Short"
        # 8 chars gives ~15, 11 chars gives ~22
        score_contribution = 15 + (length - 8) * 2.5
        is_acceptable = False
        desc = "Meets legacy minimums, but vulnerable to fast parallel dictionary attacks."
    elif 12 <= length <= 15:
        band = "Better Length"
        # 12 chars gives ~26, 15 chars gives ~32
        score_contribution = 25 + (length - 12) * 2.3
        is_acceptable = True
        desc = "Good length. Provides solid resistance when combined with unpredictability."
    else:  # 16+
        band = "Strong Length"
        # 16 chars gives 35 (max length contribution)
        score_contribution = 35.0
        is_acceptable = True
        desc = "Excellent length. Passphrases or long generated passwords provide strong defense."

    return {
        "length": length,
        "band": band,
        "score_contribution": round(score_contribution, 1),
        "description": desc,
        "is_acceptable_minimum": is_acceptable
    }
