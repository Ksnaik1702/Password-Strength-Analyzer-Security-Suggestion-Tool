"""
Sequence Detector Module
Detects ascending and descending sequential patterns in numbers and alphabetic characters.

Examples:
- Ascending numbers: '1234', '5678', '0123'
- Descending numbers: '9876', '4321'
- Ascending letters: 'abcd', 'bcde', 'wxyz'
- Descending letters: 'fedc', 'zyxw'

Industry context:
Sequences are among the first rule-based substitutions attacker masks and wordlists test
(e.g., Hashcat masks -m 1000 -a 3 ?d?d?d?d).
"""

from typing import List, Dict, Any

def detect_sequences(password: str, min_length: int = 3) -> Dict[str, Any]:
    """
    Scans for numeric and alphabetic sequential runs of at least min_length.
    """
    if len(password) < min_length:
        return {
            "has_sequence": False,
            "detected_sequences": [],
            "penalty": 0.0
        }

    detected = []
    pw_lower = password.lower()

    # Numeric sequence check
    digits_asc = "012345678901"
    digits_desc = "987654321098"

    for seq_len in range(min_length, 7):
        for i in range(len(digits_asc) - seq_len + 1):
            sub = digits_asc[i:i + seq_len]
            if sub in pw_lower and sub not in detected:
                detected.append(sub)
        for i in range(len(digits_desc) - seq_len + 1):
            sub = digits_desc[i:i + seq_len]
            if sub in pw_lower and sub not in detected:
                detected.append(sub)

    # Alphabetic sequence check
    alpha_asc = "abcdefghijklmnopqrstuvwxyz"
    alpha_desc = "zyxwvutsrqponmlkjihgfedcba"

    for seq_len in range(min_length, 6):
        for i in range(len(alpha_asc) - seq_len + 1):
            sub = alpha_asc[i:i + seq_len]
            if sub in pw_lower and sub not in detected:
                detected.append(sub)
        for i in range(len(alpha_desc) - seq_len + 1):
            sub = alpha_desc[i:i + seq_len]
            if sub in pw_lower and sub not in detected:
                detected.append(sub)

    # Clean redundant substrings (e.g. if '1234' is present, don't double count '123')
    filtered = []
    for item in sorted(detected, key=len, reverse=True):
        if not any(item != other and item in other for other in filtered):
            filtered.append(item)

    # Calculate penalty
    # 1 sequence = -8 pts, 2+ = -15 pts
    penalty = 0.0
    if len(filtered) == 1:
        penalty = 8.0
    elif len(filtered) > 1:
        penalty = min(20.0, 8.0 + (len(filtered) - 1) * 6.0)

    return {
        "has_sequence": len(filtered) > 0,
        "detected_sequences": filtered,
        "penalty": penalty
    }
