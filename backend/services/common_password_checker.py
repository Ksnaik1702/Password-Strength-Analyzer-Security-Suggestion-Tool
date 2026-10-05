"""
Common Password & Breach Checker Module
Checks passwords against local common dictionary passwords and simulated breach hash sets.

Industry context:
NIST SP 800-63B Section 5.1.1.2 explicitly mandates that verifiers SHALL compare prospective
passwords against lists of commonly used, expected, or compromised values.
"""

import hashlib
from pathlib import Path
from typing import Dict, Any, Set

class CommonPasswordChecker:
    def __init__(self, common_path: str = None, breach_path: str = None):
        base_dir = Path(__file__).resolve().parent.parent.parent
        self.common_path = Path(common_path) if common_path else base_dir / "data" / "common_passwords.txt"
        self.breach_path = Path(breach_path) if breach_path else base_dir / "data" / "breached_sha1_demo.txt"
        
        self.common_passwords: Set[str] = set()
        self.breach_hashes: Set[str] = set()
        self._load_data()

    def _load_data(self):
        if self.common_path.exists():
            for line in self.common_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                clean = line.strip().lower()
                if clean:
                    self.common_passwords.add(clean)

        if self.breach_path.exists():
            for line in self.breach_path.read_text(encoding="utf-8", errors="ignore").splitlines():
                clean = line.strip().upper()
                if clean:
                    self.breach_hashes.add(clean)

    def is_common_password(self, password: str) -> bool:
        """Checks if exact password (case-insensitive) is in common password list."""
        return password.strip().lower() in self.common_passwords

    def check_common_and_breach(self, password: str) -> Dict[str, Any]:
        """
        Evaluates whether the password matches a known common password or demo breach hash.
        Never transmits or leaks the plaintext password.
        """
        pw_clean = password.strip().lower()
        if not pw_clean:
            return {
                "is_common": False,
                "is_breached": False,
                "penalty": 0.0,
                "message": ""
            }

        is_common = pw_clean in self.common_passwords

        # Compute SHA1 hash locally for privacy-preserving breach check simulation
        sha1_hash = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
        is_breached = sha1_hash in self.breach_hashes

        penalty = 0.0
        message = ""
        if is_common or is_breached:
            penalty = 45.0  # Massive penalty
            message = "Your password matches a commonly used or compromised password pattern and should not be used."

        return {
            "is_common": is_common,
            "is_breached": is_breached,
            "penalty": penalty,
            "message": message
        }

# Global singleton instance
_checker_instance = None

def get_common_password_checker() -> CommonPasswordChecker:
    global _checker_instance
    if _checker_instance is None:
        _checker_instance = CommonPasswordChecker()
    return _checker_instance
