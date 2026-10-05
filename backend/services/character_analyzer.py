"""
Character Analysis Module
Evaluates character variety, charset presence, unique characters, and diversity ratios.

Industry context:
While character diversity expands the search space, composition rules
(uppercase + lowercase + number + symbol) are often gamed by predictable substitutions
such as capitalizing the first letter and appending '1!' at the end (e.g. 'Password123!').
"""

import string
from typing import Dict, Any

def analyze_characters(password: str) -> Dict[str, Any]:
    """
    Analyzes character types and diversity within the password.
    """
    length = len(password)
    if length == 0:
        return {
            "has_lower": False,
            "has_upper": False,
            "has_digits": False,
            "has_symbols": False,
            "has_spaces": False,
            "character_type_count": 0,
            "unique_character_count": 0,
            "unique_character_ratio": 0.0,
            "diversity_score": 0.0,
            "character_pool_size": 0
        }

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digits = any(c.isdigit() for c in password)
    has_symbols = any(c in string.punctuation for c in password)
    has_spaces = any(c.isspace() for c in password)

    # Count character types present
    type_flags = [has_lower, has_upper, has_digits, has_symbols]
    character_type_count = sum(type_flags)

    # Unique characters
    unique_chars = set(password)
    unique_character_count = len(unique_chars)
    unique_character_ratio = round(unique_character_count / length, 3)

    # Calculate theoretical character pool size
    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digits:
        pool_size += 10
    if has_symbols:
        pool_size += 32
    if has_spaces:
        pool_size += 1

    # Base diversity contribution (up to 15 points)
    # 1 type: 3 pts, 2 types: 7 pts, 3 types: 11 pts, 4 types: 15 pts
    type_score_map = {0: 0.0, 1: 3.0, 2: 7.0, 3: 11.0, 4: 15.0}
    diversity_score = type_score_map.get(character_type_count, 15.0)

    # Unique character bonus (up to 10 points based on ratio)
    unique_ratio_score = round(min(10.0, unique_character_ratio * 10.0), 1)

    return {
        "has_lower": has_lower,
        "has_upper": has_upper,
        "has_digits": has_digits,
        "has_symbols": has_symbols,
        "has_spaces": has_spaces,
        "character_type_count": character_type_count,
        "unique_character_count": unique_character_count,
        "unique_character_ratio": unique_character_ratio,
        "diversity_score": diversity_score,
        "unique_ratio_score": unique_ratio_score,
        "character_pool_size": pool_size
    }
