"""
Repetition Detector Module
Identifies character runs (e.g. 'aaaa', '1111') and repeating chunk patterns (e.g. 'ababab', 'abcabc').

Industry context:
Users often satisfy minimum length policies by simply repeating a single character
or repeating short syllables. Repetition drastically reduces information entropy.
"""

import re
from typing import Dict, Any, List

def detect_repetition(password: str) -> Dict[str, Any]:
    """
    Detects repeated single characters (>=3 in a row) and repeated substrings (>=2 chars repeated >=2 times).
    """
    if len(password) < 3:
        return {
            "has_repetition": False,
            "repeated_characters": [],
            "repeated_substrings": [],
            "penalty": 0.0
        }

    pw_lower = password.lower()
    repeated_chars = []
    repeated_substrings = []

    # 1. Single character runs (3 or more)
    char_runs = re.findall(r"(.)\1{2,}", pw_lower)
    if char_runs:
        for c in set(char_runs):
            # find full matching strings like 'aaaa'
            matches = re.findall(rf"({re.escape(c)}{{3,}})", pw_lower)
            repeated_chars.extend(matches)

    # 2. Repeated multi-character patterns (e.g., 'abab', 'abcabc', '1212', 'passpass')
    # Regex: capture group of length 2 to 6 repeated at least twice
    chunk_matches = re.finditer(r"(.{2,6}?)\1{1,}", pw_lower)
    for m in chunk_matches:
        full_match = m.group(0)
        chunk = m.group(1)
        # Avoid counting things like 'aaaa' as chunks if it's already captured
        if len(set(chunk)) > 1 and len(full_match) >= 4:
            repeated_substrings.append(full_match)

    has_rep = bool(repeated_chars or repeated_substrings)

    # Calculate penalty
    penalty = 0.0
    if repeated_chars:
        # e.g., 'aaaaaaaa' has severe penalty
        max_run = max(len(r) for r in repeated_chars)
        penalty += min(20.0, 5.0 + (max_run - 2) * 3.0)
    if repeated_substrings:
        penalty += min(15.0, len(repeated_substrings) * 6.0)

    return {
        "has_repetition": has_rep,
        "repeated_characters": list(set(repeated_chars)),
        "repeated_substrings": list(set(repeated_substrings)),
        "penalty": min(25.0, penalty)
    }
