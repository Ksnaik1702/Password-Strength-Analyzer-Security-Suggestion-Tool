# REST API Specification & Endpoint Documentation

Interactive Swagger documentation is automatically accessible at `http://127.0.0.1:8000/docs` when the backend is running.

---

## 1. POST `/api/analyze`
Analyzes a candidate password transiently in memory and evaluates multiple defensive heuristics.

### Request
- **Method**: `POST`
- **Content-Type**: `application/json`

```json
{
  "password": "Summer2026!Password",
  "first_name": "Rahul",
  "birth_year": "1998",
  "organization": "AcmeCorp"
}
```

### Response (`200 OK`)
```json
{
  "score": 52,
  "classification": "MODERATE",
  "findings": [
    {
      "type": "length",
      "severity": "info",
      "status": "positive",
      "title": "Strong Password Length",
      "description": "Excellent length of 19 characters creates a high search-space baseline."
    },
    {
      "type": "predictable_structure",
      "severity": "medium",
      "status": "negative",
      "title": "Predictable Structure",
      "description": "Predictable year detected: '2026'"
    }
  ],
  "suggestions": [
    "Avoid appending four-digit years (such as 2024, 2025, 2026), as this is a standard attacker wordlist rule.",
    "Use a trusted password manager (e.g. Bitwarden, 1Password) to generate and store unique credentials.",
    "Enable Multi-Factor Authentication (MFA / 2FA) wherever available for layered defense."
  ],
  "metrics": {
    "length": 19,
    "length_band": "Strong Length",
    "has_lower": true,
    "has_upper": true,
    "has_digits": true,
    "has_symbols": true,
    "has_spaces": false,
    "character_type_count": 4,
    "unique_characters": 14,
    "unique_character_ratio": 0.737,
    "character_pool_size": 94,
    "entropy_bits": 124.5,
    "entropy_rating": "Very High",
    "crack_time_educational": "Centuries / Millennia (Theoretically impractical to brute force)",
    "score_breakdown": {
      "length_points": 35.0,
      "diversity_points": 15.0,
      "uniqueness_points": 7.4,
      "non_common_bonus": 10.0,
      "pattern_resistance_bonus": 0.0,
      "unpredictability_bonus": 0.0,
      "total_positive": 67.4,
      "total_penalties": 15.0
    },
    "weakness_count": 1
  },
  "entropy_info": {
    "entropy_bits": 124.5,
    "rating": "Very High",
    "search_space": "~ 2^124 (> 10^24) combinations",
    "crack_time_educational": "Centuries / Millennia (Theoretically impractical to brute force)",
    "educational_note": "Educational Note: Theoretical entropy assumes truly random character selection. Real-world passwords with predictable words (like 'Password123!') have far lower effective entropy because attackers use dictionary heuristics rather than pure brute force."
  }
}
```

---

## 2. POST `/api/generate`
Generates cryptographically random passwords or passphrases using Python's `secrets` module.

### Request
```json
{
  "mode": "complex",
  "length": 20,
  "include_upper": true,
  "include_lower": true,
  "include_digits": true,
  "include_symbols": true
}
```

### Response (`200 OK`)
```json
{
  "mode": "complex",
  "generated_password": "k9#M$vP2!wL8@zR4*yQ1",
  "length": 20,
  "bits_estimate": 131.1
}
```

---

## 3. POST `/api/policy/check`
Evaluates compliance against NIST SP 800-63B policy rules.

### Request
```json
{
  "password": "ShortPass1!",
  "min_length": 12,
  "max_length": 128,
  "disallow_common": true
}
```

### Response (`200 OK`)
```json
{
  "policy_passed": false,
  "status": "POLICY FAIL",
  "failures": [
    "Password must be at least 12 characters long."
  ],
  "checks": [
    {
      "rule": "Minimum length of 12 characters",
      "passed": false,
      "detail": "Provided length is 10 characters."
    },
    {
      "rule": "Maximum length up to 128 characters",
      "passed": true,
      "detail": "Allows long passphrases."
    },
    {
      "rule": "Not in common or compromised password dictionary",
      "passed": true,
      "detail": "Checks against NIST-recommended common password list."
    }
  ],
  "educational_note": "Policy Compliance vs. Password Strength: A password may comply with standard policy rules while still possessing predictable patterns."
}
```

---

## 4. POST `/api/hashing/demonstrate`
Educational endpoint that generates a 16-byte random cryptographic salt and performs 600,000 PBKDF2-HMAC-SHA256 iterations.

### Request
```json
{
  "password": "DemoSyntheticPass123!"
}
```

### Response (`200 OK`)
```json
{
  "algorithm": "PBKDF2-HMAC-SHA256",
  "iterations": 600000,
  "salt_hex": "4a7b9c1d...",
  "salt_length_bytes": 16,
  "hash_hex": "8f3e2a...",
  "stored_hash_format": "pbkdf2:sha256:600000$4a7b9c1d...$8f3e2a...",
  "insecure_fast_sha256": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
  "educational_comparison": {
    "fast_hash_sha256_speed": "~ 10,000,000,000 guesses/sec (GPU)",
    "stretched_pbkdf2_speed": "~ 5,000 guesses/sec (GPU at 600k iterations)",
    "offline_attack_slowdown_factor": "2,000,000x harder for attacker"
  }
}
```

---

## 5. POST `/api/hashing/verify`
Performs constant-time password verification using `secrets.compare_digest`.

### Request
```json
{
  "password": "DemoSyntheticPass123!",
  "stored_hash_format": "pbkdf2:sha256:600000$salt_hex$hash_hex"
}
```

### Response (`200 OK`)
```json
{
  "is_valid": true,
  "status": "MATCH",
  "description": "Password matches hash verification."
}
```

---

## 6. GET `/api/dashboard/stats`
Returns anonymous aggregate telemetry for Chart.js dashboard rendering.

### Response (`200 OK`)
```json
{
  "total_analyses": 45,
  "average_score": 58.4,
  "classifications": {
    "VERY WEAK": 12,
    "WEAK": 10,
    "MODERATE": 8,
    "STRONG": 9,
    "VERY STRONG": 6
  },
  "weakness_frequency": [
    { "type": "sequence", "count": 18 },
    { "type": "keyboard_pattern", "count": 14 }
  ],
  "length_distribution": {
    "< 8 (Very Short)": 14,
    "8-11 (Short)": 12,
    "12-15 (Better)": 11,
    "16+ (Strong)": 8
  },
  "recent_analyses": [
    {
      "analysis_id": "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
      "score": 74,
      "classification": "STRONG",
      "password_length": 16,
      "weakness_count": 0,
      "created_at": "2026-10-05T12:00:00Z"
    }
  ]
}
```
