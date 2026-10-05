"""
Keyboard Pattern Detector Module
Detects keyboard walk patterns across standard QWERTY layouts (horizontal and vertical).

Examples:
- Horizontal walks: 'qwerty', 'asdfgh', 'zxcvbn', 'poiuy'
- Vertical walks: '1qaz', '2wsx', '3edc', 'zaq1'

Industry context:
Keyboard patterns appear intuitively easy for humans to type and remember,
making them one of the highest-frequency weaknesses in enterprise password leaks.
"""

from typing import List, Dict, Any

KEYBOARD_HORIZONTAL = [
    "1234567890-=",
    "qwertyuiop[]\\",
    "asdfghjkl;'",
    "zxcvbnm,./"
]

KEYBOARD_VERTICAL = [
    "1qaz",
    "2wsx",
    "3edc",
    "4rfv",
    "5tgb",
    "6yhn",
    "7ujm",
    "8ik,",
    "9ol.",
    "0p;/"
]

def detect_keyboard_patterns(password: str, min_length: int = 4) -> Dict[str, Any]:
    """
    Detects horizontal and vertical keyboard walks (forward and reverse).
    """
    if len(password) < min_length:
        return {
            "has_keyboard_pattern": False,
            "detected_patterns": [],
            "penalty": 0.0
        }

    detected = []
    pw_lower = password.lower()

    # Horizontal walks
    for row in KEYBOARD_HORIZONTAL:
        for l in range(min_length, 8):
            for i in range(len(row) - l + 1):
                fwd = row[i:i + l]
                rev = fwd[::-1]
                if fwd in pw_lower and fwd not in detected:
                    detected.append(fwd)
                if rev in pw_lower and rev not in detected:
                    detected.append(rev)

    # Vertical walks
    for col in KEYBOARD_VERTICAL:
        for l in range(min_length, len(col) + 1):
            for i in range(len(col) - l + 1):
                fwd = col[i:i + l]
                rev = fwd[::-1]
                if fwd in pw_lower and fwd not in detected:
                    detected.append(fwd)
                if rev in pw_lower and rev not in detected:
                    detected.append(rev)

    # Filter substrings
    filtered = []
    for item in sorted(detected, key=len, reverse=True):
        if not any(item != other and item in other for other in filtered):
            filtered.append(item)

    penalty = 0.0
    if len(filtered) == 1:
        penalty = 12.0
    elif len(filtered) > 1:
        penalty = min(25.0, 12.0 + (len(filtered) - 1) * 8.0)

    return {
        "has_keyboard_pattern": len(filtered) > 0,
        "detected_patterns": filtered,
        "penalty": penalty
    }
