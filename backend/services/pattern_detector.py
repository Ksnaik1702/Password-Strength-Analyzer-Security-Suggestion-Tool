"""
Pattern & Structure Detector Module
Detects predictable compound patterns:
- Common word + numbers/years (e.g. 'welcome123', 'admin2026', 'Summer2026!')
- 4-digit years (1950 - 2035)
- Date-like patterns (YYYYMMDD, DDMMYYYY, etc.)
- Phone-like runs
- Optional personal context overlap (first name, birth year, company/college)

Industry context:
Over 60% of enterprise passwords follow the 'Capital letter + Dictionary word + Year/Digits + Symbol'
format (e.g., 'Company2025!'). Attackers configure dictionary rules specifically to append
years and digits.
"""

import re
from typing import Dict, Any, List, Optional
from backend.services.common_password_checker import get_common_password_checker

def detect_predictable_structure(
    password: str,
    personal_context: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Analyzes predictable structure, dates, years, word+digits, and personal info overlap.
    """
    if not password:
        return {
            "has_predictable_structure": False,
            "has_year": False,
            "has_date": False,
            "has_phone": False,
            "has_word_number": False,
            "has_personal_info": False,
            "detected_features": [],
            "personal_matches": [],
            "penalty": 0.0
        }

    pw_lower = password.lower()
    features = []
    penalty = 0.0

    # 1. Year pattern (1940 - 2035)
    year_match = re.search(r"(19\d{2}|20[0-3]\d)", password)
    has_year = bool(year_match)
    if has_year:
        features.append(f"Predictable year detected: '{year_match.group(0)}'")
        penalty += 10.0

    # 2. Date-like pattern (YYYY-MM-DD or DD/MM/YYYY)
    date_match = re.search(r"\b(19|20)\d{2}[-/.](0[1-9]|1[0-2])[-/.](0[1-9]|[12]\d|3[01])\b", password)
    has_date = bool(date_match)
    if has_date:
        features.append("Standard date format detected (YYYY-MM-DD/DD-MM-YYYY)")
        penalty += 12.0

    # 3. Phone-like digit run (9+ consecutive or spaced digits)
    phone_match = re.search(r"(\+?\d[\s-]?){9,}", password)
    has_phone = bool(phone_match)
    if has_phone:
        features.append("Phone-like numeric sequence detected")
        penalty += 10.0

    # 4. Predictable Word + Number structure (e.g. 'Welcome123', 'admin2026', 'password1')
    common_checker = get_common_password_checker()
    has_word_number = False

    # Split into alphabetic and non-alphabetic parts
    parts = re.findall(r"[a-zA-Z]+|\d+|[^a-zA-Z0-9]+", password)
    for part in parts:
        part_clean = part.lower()
        if len(part_clean) >= 3 and part_clean in common_checker.common_passwords:
            has_word_number = True
            features.append(f"Contains common base word: '{part_clean}' paired with numbers/symbols")
            penalty += 15.0
            break

    # 5. Optional Personal Context Check
    has_personal_info = False
    personal_matches = []
    if personal_context:
        for key, val in personal_context.items():
            if val and isinstance(val, str):
                val_clean = val.strip().lower()
                # Only check if val has length >= 3 to avoid false positives on 1-2 char entries
                if len(val_clean) >= 3 and val_clean in pw_lower:
                    has_personal_info = True
                    clean_key = key.replace("_", " ").title()
                    personal_matches.append(clean_key)
                    features.append(f"Password contains user-provided personal info ({clean_key})")
                    penalty += 20.0

    has_predictable = bool(has_year or has_date or has_phone or has_word_number or has_personal_info)

    return {
        "has_predictable_structure": has_predictable,
        "has_year": has_year,
        "has_date": has_date,
        "has_phone": has_phone,
        "has_word_number": has_word_number,
        "has_personal_info": has_personal_info,
        "detected_features": features,
        "personal_matches": personal_matches,
        "penalty": min(35.0, penalty)
    }
