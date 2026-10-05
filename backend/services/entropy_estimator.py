"""
Entropy Estimator Module
Calculates theoretical password entropy (in bits) and provides educational explanations
highlighting the difference between mathematical randomness and human predictability.

Formula:
  Entropy (bits) = L * log2(N)
  where:
    L = password length
    N = theoretical character pool size

Limitations:
This formula assumes that each character was drawn uniformly at random from pool N.
Human-generated passwords (e.g. 'Password123!') violate this assumption drastically,
often yielding a high theoretical entropy while having very low empirical entropy.
"""

import math
from typing import Dict, Any

def estimate_theoretical_entropy(length: int, pool_size: int) -> Dict[str, Any]:
    """
    Computes theoretical entropy in bits and estimates crack difficulty under an assumed rate.
    """
    if length == 0 or pool_size == 0:
        return {
            "entropy_bits": 0.0,
            "rating": "None",
            "educational_note": "Empty password provides zero bits of entropy.",
            "estimated_search_space": "0 combinations",
            "crack_time_educational": "< 1 second"
        }

    # H = L * log2(N)
    entropy_bits = length * math.log2(pool_size)
    entropy_bits = round(entropy_bits, 1)

    if entropy_bits < 28:
        rating = "Very Low"
    elif entropy_bits < 40:
        rating = "Low"
    elif entropy_bits < 60:
        rating = "Moderate"
    elif entropy_bits < 80:
        rating = "High"
    else:
        rating = "Very High"

    # Search space ~ 2^bits
    if entropy_bits > 80:
        search_space = f"~ 2^{int(entropy_bits)} (> 10^24) combinations"
        crack_time = "Centuries / Millennia (Theoretically impractical to brute force)"
    else:
        combinations = pool_size ** length
        search_space = f"{combinations:,.0f} theoretical combinations"
        # Educational crack time assuming a powerful offline GPU cluster (10 billion guesses/sec)
        guesses_per_sec = 1e10
        total_guesses = 2 ** entropy_bits
        seconds = total_guesses / guesses_per_sec

        if seconds < 1:
            crack_time = "< 1 millisecond (Instant)"
        elif seconds < 60:
            crack_time = f"{seconds:.1f} seconds"
        elif seconds < 3600:
            crack_time = f"{seconds/60:.1f} minutes"
        elif seconds < 86400:
            crack_time = f"{seconds/3600:.1f} hours"
        elif seconds < 31536000:
            crack_time = f"{seconds/86400:.1f} days"
        elif seconds < 31536000 * 1000:
            crack_time = f"{seconds/31536000:.1f} years"
        else:
            crack_time = "Centuries / Millennia (Theoretically impractical to brute force)"

    educational_note = (
        "Educational Note: Theoretical entropy assumes truly random character selection. "
        "Real-world passwords with predictable words (like 'Password123!') have far lower "
        "effective entropy because attackers use dictionary heuristics rather than pure brute force."
    )

    return {
        "entropy_bits": entropy_bits,
        "rating": rating,
        "search_space": search_space,
        "crack_time_educational": crack_time,
        "educational_note": educational_note
    }
