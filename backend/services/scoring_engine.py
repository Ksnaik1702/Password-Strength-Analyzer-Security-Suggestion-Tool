"""
Scoring Engine Module
Calculates a balanced 0-100 password strength score and assigns classification:
- 0-20   : VERY WEAK
- 21-40  : WEAK
- 41-60  : MODERATE
- 61-80  : STRONG
- 81-100 : VERY STRONG

Important Philosophy:
Password strength is NOT a single formulaic guarantee. We emphasize:
LENGTH + UNPREDICTABILITY + PATTERN RESISTANCE + COMMON-PASSWORD CHECKS + CONTEXT
"""

from typing import Dict, Any, List

def calculate_score(
    length_result: Dict[str, Any],
    char_result: Dict[str, Any],
    common_result: Dict[str, Any],
    sequence_result: Dict[str, Any],
    keyboard_result: Dict[str, Any],
    repetition_result: Dict[str, Any],
    structure_result: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Computes total score and detailed point breakdown.
    """
    length = length_result.get("length", 0)
    if length == 0:
        return {
            "score": 0,
            "classification": "VERY WEAK",
            "breakdown": {
                "base_score": 0,
                "length_points": 0,
                "diversity_points": 0,
                "uniqueness_points": 0,
                "pattern_resistance_bonus": 0,
                "non_common_bonus": 0,
                "total_penalties": 0
            }
        }

    # 1. Positive Contributions
    length_pts = length_result.get("score_contribution", 0.0)      # up to 35
    diversity_pts = char_result.get("diversity_score", 0.0)         # up to 15
    uniqueness_pts = char_result.get("unique_ratio_score", 0.0)     # up to 10
    
    # Non-common bonus (10 points if not in common list AND length >= 8)
    if length >= 8 and not (common_result.get("is_common") or common_result.get("is_breached")):
        non_common_bonus = 10.0
    elif length >= 6 and not (common_result.get("is_common") or common_result.get("is_breached")):
        non_common_bonus = 5.0
    else:
        non_common_bonus = 0.0

    # Pattern resistance bonus (up to 20 points if no sequences, keyboard walks, or repetitions)
    # ONLY awarded if password is of sufficient length (>= 8 chars)
    has_any_pattern = (
        sequence_result.get("has_sequence") or
        keyboard_result.get("has_keyboard_pattern") or
        repetition_result.get("has_repetition") or
        structure_result.get("has_predictable_structure")
    )
    if length >= 12 and not has_any_pattern:
        pattern_resistance_bonus = 20.0
    elif length >= 8 and not has_any_pattern:
        pattern_resistance_bonus = 10.0
    else:
        pattern_resistance_bonus = 0.0

    # Additional unpredictability bonus (up to 10 points for good length + high diversity + no patterns)
    unpredictability_bonus = 0.0
    if length >= 14 and char_result.get("character_type_count", 0) >= 3 and not has_any_pattern:
        unpredictability_bonus = 10.0
    elif length >= 12 and not has_any_pattern:
        unpredictability_bonus = 5.0

    total_positive = (
        length_pts +
        diversity_pts +
        uniqueness_pts +
        non_common_bonus +
        pattern_resistance_bonus +
        unpredictability_bonus
    )

    # 2. Penalties
    penalties = (
        common_result.get("penalty", 0.0) +
        sequence_result.get("penalty", 0.0) +
        keyboard_result.get("penalty", 0.0) +
        repetition_result.get("penalty", 0.0) +
        structure_result.get("penalty", 0.0)
    )

    raw_score = total_positive - penalties

    # Strict caps based on fundamental flaws:
    # A) Very short passwords (< 6 chars) can NEVER exceed 15 (VERY WEAK)
    if length < 6:
        final_score = min(15, max(0, int(round(raw_score))))
    # B) Short passwords (< 8 chars) can NEVER exceed 25 (WEAK / VERY WEAK)
    elif length < 8:
        final_score = min(25, max(0, int(round(raw_score))))
    # C) Explicit common or breached password: cap at 15 (VERY WEAK)
    elif common_result.get("is_common") or common_result.get("is_breached"):
        final_score = min(15, max(0, int(round(raw_score))))
    # D) Severe repetition: cap at 30
    elif repetition_result.get("penalty", 0) >= 18:
        final_score = min(30, max(0, int(round(raw_score))))
    else:
        final_score = max(0, min(100, int(round(raw_score))))

    # 3. Classification
    if final_score <= 20:
        classification = "VERY WEAK"
    elif final_score <= 40:
        classification = "WEAK"
    elif final_score <= 60:
        classification = "MODERATE"
    elif final_score <= 80:
        classification = "STRONG"
    else:
        classification = "VERY STRONG"

    return {
        "score": final_score,
        "classification": classification,
        "breakdown": {
            "length_points": length_pts,
            "diversity_points": diversity_pts,
            "uniqueness_points": uniqueness_pts,
            "non_common_bonus": non_common_bonus,
            "pattern_resistance_bonus": pattern_resistance_bonus,
            "unpredictability_bonus": unpredictability_bonus,
            "total_positive": round(total_positive, 1),
            "total_penalties": round(penalties, 1)
        }
    }
