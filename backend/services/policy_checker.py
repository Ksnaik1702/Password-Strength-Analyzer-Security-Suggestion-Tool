"""
Password Policy Checker Module
Evaluates whether a password satisfies modern enterprise identity policies
(aligned with NIST SP 800-63B Digital Identity Guidelines and OWASP ASVS).

Key NIST Guidance Principles:
1. Minimum length of at least 8 (recommended 12+ for enterprise).
2. Allow up to at least 64 characters (recommended 128+).
3. Allow all printable characters, including spaces.
4. NO arbitrary periodic expiration (avoids predictable substitutions like Fall2025!).
5. Reject passwords found on commonly used or compromised blocklists.
6. Policy compliance != strength score (a password can technically pass policy yet be weak).
"""

from typing import Dict, Any, List, Optional
from backend.services.common_password_checker import get_common_password_checker

def check_policy_compliance(
    password: str,
    min_length: int = 12,
    max_length: int = 128,
    disallow_common: bool = True,
    personal_context: Optional[Dict[str, str]] = None
) -> Dict[str, Any]:
    """
    Evaluates password against organizational policy rules.
    """
    failures = []
    checks = []

    # 1. Length check
    length = len(password)
    length_passed = length >= min_length
    checks.append({
        "rule": f"Minimum length of {min_length} characters",
        "passed": length_passed,
        "detail": f"Provided length is {length} characters."
    })
    if not length_passed:
        failures.append(f"Password must be at least {min_length} characters long.")

    max_passed = length <= max_length
    checks.append({
        "rule": f"Maximum length up to {max_length} characters",
        "passed": max_passed,
        "detail": "Allows long passphrases."
    })
    if not max_passed:
        failures.append(f"Password exceeds maximum allowed length of {max_length} characters.")

    # 2. Common password blocklist check
    common_checker = get_common_password_checker()
    if disallow_common:
        is_common = common_checker.is_common_password(password)
        checks.append({
            "rule": "Not in common or compromised password dictionary",
            "passed": not is_common,
            "detail": "Checks against NIST-recommended common password list."
        })
        if is_common:
            failures.append("Password matches a known common or compromised password.")

    # 3. Personal context check (if provided)
    if personal_context:
        pw_lower = password.lower()
        context_viol = False
        for key, val in personal_context.items():
            if val and len(val.strip()) >= 3 and val.strip().lower() in pw_lower:
                context_viol = True
                failures.append(f"Password must not contain personal details ({key.replace('_', ' ')}).")
        checks.append({
            "rule": "Free of personal identifiable attributes",
            "passed": not context_viol,
            "detail": "Verifies password does not reuse user attributes."
        })

    # Policy status
    policy_passed = len(failures) == 0

    return {
        "policy_passed": policy_passed,
        "status": "POLICY PASS" if policy_passed else "POLICY FAIL",
        "failures": failures,
        "checks": checks,
        "educational_note": (
            "Policy Compliance vs. Password Strength: A password may comply with standard policy "
            "rules (e.g. length >= 12) while still possessing predictable patterns. Conversely, "
            "a complex 11-character password may be mathematically strong but fail a strict 12-character policy."
        )
    }
