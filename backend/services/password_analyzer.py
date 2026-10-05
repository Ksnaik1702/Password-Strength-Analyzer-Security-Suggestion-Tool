"""
Password Analyzer Module
The central analysis engine orchestrating all detection and scoring services.

Data Flow:
Input Password (transient in memory)
  ↓
Length Analysis + Character Diversity + Uniqueness
  ↓
Pattern Analysis:
  ├── Common Dictionary & Demo Breach Hash Check
  ├── Sequential Numbers & Letters
  ├── Keyboard Walk Detection
  ├── Character Repetition & Syllables
  ├── Compound Structure (Word + Numbers/Years/Dates)
  └── Personal Context Overlap
  ↓
Theoretical Entropy Estimation
  ↓
Balanced Strength Scoring (0-100) & Classification
  ↓
Actionable Security Suggestions
"""

from typing import Dict, Any, List, Optional
from backend.services.length_analyzer import analyze_length
from backend.services.character_analyzer import analyze_characters
from backend.services.sequence_detector import detect_sequences
from backend.services.keyboard_detector import detect_keyboard_patterns
from backend.services.repetition_detector import detect_repetition
from backend.services.common_password_checker import get_common_password_checker
from backend.services.pattern_detector import detect_predictable_structure
from backend.services.entropy_estimator import estimate_theoretical_entropy
from backend.services.scoring_engine import calculate_score
from backend.services.suggestion_engine import generate_suggestions

def analyze_password(
    password: str,
    personal_context: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Analyzes a password transiently in memory and produces comprehensive findings,
    metrics, strength score, and security suggestions.
    
    SECURITY GUARANTEE:
    This function processes input in-memory only. It does not write to logs or disk.
    """
    pw = password or ""
    length = len(pw)

    # 1. Component Analyses
    length_res = analyze_length(pw)
    char_res = analyze_characters(pw)
    
    common_checker = get_common_password_checker()
    common_res = common_checker.check_common_and_breach(pw)
    
    seq_res = detect_sequences(pw)
    kb_res = detect_keyboard_patterns(pw)
    rep_res = detect_repetition(pw)
    struct_res = detect_predictable_structure(pw, personal_context)

    # 2. Entropy Estimation
    entropy_res = estimate_theoretical_entropy(length, char_res["character_pool_size"])

    # 3. Strength Score & Classification
    score_res = calculate_score(
        length_result=length_res,
        char_result=char_res,
        common_result=common_res,
        sequence_result=seq_res,
        keyboard_result=kb_res,
        repetition_result=rep_res,
        structure_result=struct_res
    )

    final_score = score_res["score"]
    classification = score_res["classification"]

    # 4. Consolidate Findings
    findings: List[Dict[str, Any]] = []

    # Positive findings
    if length >= 16:
        findings.append({
            "type": "length",
            "severity": "info",
            "status": "positive",
            "title": "Strong Password Length",
            "description": f"Excellent length of {length} characters creates a high search-space baseline."
        })
    elif length >= 12:
        findings.append({
            "type": "length",
            "severity": "info",
            "status": "positive",
            "title": "Good Length Baseline",
            "description": f"Password has a decent length of {length} characters."
        })
    else:
        findings.append({
            "type": "length",
            "severity": "high",
            "status": "negative",
            "title": "Insufficient Length",
            "description": f"Password is only {length} characters. Minimum recommendation is 12–16 characters."
        })

    if char_res["character_type_count"] >= 3:
        findings.append({
            "type": "diversity",
            "severity": "info",
            "status": "positive",
            "title": "Character Diversity",
            "description": f"Password incorporates {char_res['character_type_count']} distinct character categories."
        })

    # Negative findings
    if common_res["is_common"] or common_res["is_breached"]:
        findings.append({
            "type": "common_password",
            "severity": "critical",
            "status": "negative",
            "title": "Common / Compromised Password",
            "description": "Matches a top common dictionary password or publicly breached credential list."
        })

    if rep_res["has_repetition"]:
        rep_items = rep_res["repeated_characters"] + rep_res["repeated_substrings"]
        findings.append({
            "type": "repetition",
            "severity": "medium",
            "status": "negative",
            "title": "Repeated Character Runs",
            "description": f"Detected repeating characters or chunks: {', '.join(rep_items[:3])}"
        })

    if seq_res["has_sequence"]:
        findings.append({
            "type": "sequence",
            "severity": "medium",
            "status": "negative",
            "title": "Sequential Patterns",
            "description": f"Detected ascending/descending character sequences: {', '.join(seq_res['detected_sequences'][:3])}"
        })

    if kb_res["has_keyboard_pattern"]:
        findings.append({
            "type": "keyboard_pattern",
            "severity": "high",
            "status": "negative",
            "title": "Keyboard Walk Sequence",
            "description": f"Detected keyboard walk patterns: {', '.join(kb_res['detected_patterns'][:3])}"
        })

    if struct_res["has_predictable_structure"]:
        for feat in struct_res["detected_features"]:
            findings.append({
                "type": "predictable_structure",
                "severity": "medium",
                "status": "negative",
                "title": "Predictable Structure",
                "description": feat
            })

    # 5. Security Suggestions
    suggestions = generate_suggestions(
        length_result=length_res,
        char_result=char_res,
        common_result=common_res,
        sequence_result=seq_res,
        keyboard_result=kb_res,
        repetition_result=rep_res,
        structure_result=struct_res,
        final_score=final_score
    )

    # 6. Structured Output
    metrics = {
        "length": length,
        "length_band": length_res["band"],
        "has_lower": char_res["has_lower"],
        "has_upper": char_res["has_upper"],
        "has_digits": char_res["has_digits"],
        "has_symbols": char_res["has_symbols"],
        "has_spaces": char_res["has_spaces"],
        "character_type_count": char_res["character_type_count"],
        "unique_characters": char_res["unique_character_count"],
        "unique_character_ratio": char_res["unique_character_ratio"],
        "character_pool_size": char_res["character_pool_size"],
        "entropy_bits": entropy_res["entropy_bits"],
        "entropy_rating": entropy_res["rating"],
        "crack_time_educational": entropy_res["crack_time_educational"],
        "score_breakdown": score_res["breakdown"],
        "weakness_count": len([f for f in findings if f["status"] == "negative"])
    }

    return {
        "score": final_score,
        "classification": classification,
        "findings": findings,
        "suggestions": suggestions,
        "metrics": metrics,
        "entropy_info": entropy_res
    }
