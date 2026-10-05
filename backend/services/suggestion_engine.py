"""
Security Suggestion Engine Module
Generates constructive, actionable, and defensive recommendations based on detected weaknesses.

SECURITY / PRIVACY MANDATE:
Suggestions MUST NEVER echo or print the user's actual password in recommendations.
"""

from typing import List, Dict, Any

def generate_suggestions(
    length_result: Dict[str, Any],
    char_result: Dict[str, Any],
    common_result: Dict[str, Any],
    sequence_result: Dict[str, Any],
    keyboard_result: Dict[str, Any],
    repetition_result: Dict[str, Any],
    structure_result: Dict[str, Any],
    final_score: int
) -> List[str]:
    """
    Evaluates analysis components and returns prioritized, actionable security tips.
    """
    suggestions = []

    # 1. Critical: Common password / breached check
    if common_result.get("is_common") or common_result.get("is_breached"):
        suggestions.append(
            "CRITICAL: This password matches a commonly used dictionary password or public breach pattern. "
            "Change it immediately and never reuse it."
        )

    # 2. Length suggestions
    length = length_result.get("length", 0)
    if length < 8:
        suggestions.append("Your password is too short. Increase length to at least 12–16 characters.")
    elif 8 <= length < 12:
        suggestions.append("Length is minimal. Expanding to 14+ characters significantly increases brute-force resistance.")

    # 3. Character diversity suggestions
    type_count = char_result.get("character_type_count", 0)
    if type_count < 3 and length > 0:
        missing = []
        if not char_result.get("has_lower"): missing.append("lowercase letters")
        if not char_result.get("has_upper"): missing.append("uppercase letters")
        if not char_result.get("has_digits"): missing.append("numbers")
        if not char_result.get("has_symbols"): missing.append("symbols (!@#$)")
        if missing:
            suggestions.append(f"Enhance character variety by naturally incorporating {', '.join(missing)}.")

    # 4. Repetition suggestions
    if repetition_result.get("has_repetition"):
        suggestions.append(
            "Avoid repeated characters or repeating syllable chunks (such as 'aaaa' or 'abab'), "
            "as they significantly reduce effective entropy."
        )

    # 5. Sequence suggestions
    if sequence_result.get("has_sequence"):
        suggestions.append(
            "Avoid sequential numbers or alphabetic runs (such as '1234' or 'abcd'). "
            "Attack tools test sequential patterns first."
        )

    # 6. Keyboard patterns
    if keyboard_result.get("has_keyboard_pattern"):
        suggestions.append(
            "Avoid keyboard walk patterns (such as 'qwerty' or 'asdf'). "
            "Spatial keyboard walks are easily guessed by dictionary masks."
        )

    # 7. Predictable compound structure (year, dates, word+digits)
    if structure_result.get("has_year"):
        suggestions.append("Avoid appending four-digit years (such as 2024, 2025, 2026), as this is a standard attacker wordlist rule.")
    if structure_result.get("has_date") or structure_result.get("has_phone"):
        suggestions.append("Remove full dates and phone numbers from passwords.")
    if structure_result.get("has_word_number"):
        suggestions.append("Avoid simply appending digits to a common base word (like 'Welcome123'). Consider a 4-word random passphrase.")

    # 8. Personal information warning
    if structure_result.get("has_personal_info"):
        matches = ", ".join(structure_result.get("personal_matches", []))
        suggestions.append(
            f"ALERT: Detected overlap with user-provided personal context ({matches}). "
            "Never include personal names, birth years, or organization names in passwords."
        )

    # 9. General best practices (always reinforce good habits)
    if final_score >= 80 and not suggestions:
        suggestions.append("Excellent password strength! Ensure this credential is used exclusively for one service.")
    
    suggestions.append("Use a trusted password manager (e.g. Bitwarden, 1Password) to generate and store unique credentials.")
    suggestions.append("Enable Multi-Factor Authentication (MFA / 2FA) wherever available for layered defense.")

    # Deduplicate while preserving order
    return list(dict.fromkeys(suggestions))
