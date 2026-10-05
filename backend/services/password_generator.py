"""
Cryptographically Secure Password & Passphrase Generator
Generates high-entropy passwords and passphrases using Python's 'secrets' CSPRNG module.

SECURITY NOTICE:
- Uses 'secrets' module (SystemRandom backed by OS entropy: CryptGenRandom / /dev/urandom),
  NEVER the pseudo-random 'random' module.
- Generated passwords are generated transiently and NEVER stored or logged.
"""

import secrets
import string
from typing import List, Dict, Any

# Curated educational wordlist for Diceware-style passphrase generation
PASSPHRASE_WORDS = [
    "amber", "anchor", "arrow", "autumn", "beacon", "breeze", "bridge", "canyon",
    "cedar", "cipher", "citadel", "clover", "comet", "coral", "crystal", "current",
    "dagger", "delta", "drift", "echo", "eclipse", "ember", "falcon", "feather",
    "forest", "fossil", "frost", "galaxy", "glacier", "granite", "harbor", "horizon",
    "island", "jasper", "jungle", "lagoon", "lantern", "legend", "lunar", "meadow",
    "meteor", "nebula", "nexus", "oasis", "ocean", "orbit", "orchid", "pathway",
    "pebble", "phoenix", "photon", "pioneer", "planet", "prairie", "prism", "quartz",
    "radiant", "ripple", "river", "saffron", "shadow", "shuttle", "silver", "solar",
    "summit", "timber", "titan", "torrent", "turtle", "valiant", "vector", "velvet",
    "vessel", "vortex", "voyage", "willow", "winter", "zenith", "zephyr"
]

def generate_complex_password(
    length: int = 16,
    include_upper: bool = True,
    include_lower: bool = True,
    include_digits: bool = True,
    include_symbols: bool = True
) -> str:
    """
    Generates a cryptographically strong random password guaranteed to include
    at least one character from each requested category.
    """
    length = max(8, min(128, length))
    
    char_pool = ""
    guaranteed = []

    if include_lower:
        char_pool += string.ascii_lowercase
        guaranteed.append(secrets.choice(string.ascii_lowercase))
    if include_upper:
        char_pool += string.ascii_uppercase
        guaranteed.append(secrets.choice(string.ascii_uppercase))
    if include_digits:
        char_pool += string.digits
        guaranteed.append(secrets.choice(string.digits))
    if include_symbols:
        symbols = "!@#$%^&*()-_=+[]{}<>?"
        char_pool += symbols
        guaranteed.append(secrets.choice(symbols))

    # Fallback to lower+upper+digits if all unchecked
    if not char_pool:
        char_pool = string.ascii_letters + string.digits
        guaranteed = [secrets.choice(char_pool)]

    # Fill remaining characters
    remaining_length = max(0, length - len(guaranteed))
    random_chars = [secrets.choice(char_pool) for _ in range(remaining_length)]
    
    # Combine and shuffle securely
    combined = guaranteed + random_chars
    # Fisher-Yates shuffle using secrets.randbelow
    for i in range(len(combined) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        combined[i], combined[j] = combined[j], combined[i]

    return "".join(combined)

def generate_passphrase(words_count: int = 4, separator: str = "-") -> str:
    """
    Generates a memorable, high-entropy passphrase using cryptographically selected words.
    Example: 'velvet-harbor-drift-galaxy'
    """
    words_count = max(3, min(8, words_count))
    selected = [secrets.choice(PASSPHRASE_WORDS) for _ in range(words_count)]
    return separator.join(selected)
