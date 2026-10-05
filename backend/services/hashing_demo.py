"""
Password Hashing Demonstration Module
Provides an educational demonstration of one-way salted password hashing and verification
using NIST-approved key-stretching functions (PBKDF2-HMAC-SHA256 and Scrypt).

IMPORTANT DEFENSIVE CYBERSECURITY DISTINCTIONS:
1. Hashing vs. Encryption:
   - Encryption is a TWO-WAY operation: Plaintext + Key -> Ciphertext -> (Decryption Key) -> Plaintext.
   - Hashing is a ONE-WAY mathematical trapdoor: Input -> Hash. The original input cannot be mathematically reversed.
2. Why Fast Hashes (MD5, SHA-1, SHA-256) are Unsafe for Passwords:
   - Fast hashes are designed for file integrity verification (billions of hashes/sec on GPUs).
   - High speed enables rapid offline cracking when hash databases leak.
3. Key Stretching (PBKDF2, bcrypt, scrypt, Argon2id):
   - Deliberately consume CPU time and memory (work factor) to thwart parallel offline cracking.
4. Salting:
   - A cryptographically random unique value prepended/appended to each password prior to hashing.
   - Prevents rainbow table lookups and prevents identical passwords from producing identical hashes.
"""

import hashlib
import os
import secrets
from typing import Dict, Any

def demonstrate_hashing(password: str = "DemoSyntheticPass123!") -> Dict[str, Any]:
    """
    Demonstrates the generation of a 16-byte random cryptographic salt and
    derivation of a secure PBKDF2-HMAC-SHA256 hash with 600,000 iterations (OWASP recommendation).
    """
    # 1. Generate 16-byte cryptographically secure salt
    salt = secrets.token_bytes(16)
    salt_hex = salt.hex()

    # 2. Key stretching using PBKDF2
    iterations = 600000
    derived_key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        iterations
    )
    hash_hex = derived_key.hex()

    # Formatted storage representation: algorithm$iterations$salt$hash
    stored_hash_format = f"pbkdf2:sha256:{iterations}${salt_hex}${hash_hex}"

    # Also compute an insecure fast hash (e.g. single SHA-256) to visually contrast
    insecure_fast_hash = hashlib.sha256(password.encode('utf-8')).hexdigest()

    return {
        "algorithm": "PBKDF2-HMAC-SHA256",
        "iterations": iterations,
        "salt_hex": salt_hex,
        "salt_length_bytes": len(salt),
        "hash_hex": hash_hex,
        "stored_hash_format": stored_hash_format,
        "insecure_fast_sha256": insecure_fast_hash,
        "educational_comparison": {
            "fast_hash_sha256_speed": "~ 10,000,000,000 guesses/sec (GPU)",
            "stretched_pbkdf2_speed": "~ 5,000 guesses/sec (GPU at 600k iterations)",
            "offline_attack_slowdown_factor": "2,000,000x harder for attacker"
        }
    }

def verify_password_hash(password: str, stored_hash_format: str) -> bool:
    """
    Verifies a password against a stored format: pbkdf2:sha256:iterations$salt$hash
    Uses constant-time comparison (secrets.compare_digest) to prevent timing side-channel attacks.
    """
    try:
        parts = stored_hash_format.split("$")
        if len(parts) != 3:
            return False
        header, salt_hex, expected_hash_hex = parts
        _, _, iterations_str = header.split(":")
        iterations = int(iterations_str)
        salt = bytes.fromhex(salt_hex)

        # Re-derive key with identical parameters
        derived_key = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt,
            iterations
        )
        calculated_hash_hex = derived_key.hex()

        # Constant-time comparison
        return secrets.compare_digest(calculated_hash_hex, expected_hash_hex)
    except Exception:
        return False
