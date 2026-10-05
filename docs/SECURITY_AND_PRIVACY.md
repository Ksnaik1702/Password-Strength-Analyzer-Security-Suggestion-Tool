# Defensive Security & Privacy Architecture

## 1. Threat Model & Design Principles
Password strength analyzers handle sensitive authentication material. An improperly engineered strength meter introduces high-risk vulnerabilities, including:
- Credential harvesting via persistent access logs.
- Unintentional database storage of user passwords.
- Third-party data leakage over unencrypted network channels.
- Browser persistence via caching or client storage (`localStorage` / `sessionStorage`).

### Defensive Posture Checklist

| Defensive Rule | Implementation in Project | Security Rationale |
|---|---|---|
| **Zero Plaintext Persistence** | Database tables contain no password fields. | If the backend database file is exfiltrated, zero user credentials exist. |
| **No Password Logging** | Python `logging` formatters explicitly suppress request bodies. | Prevents exposure in centralized SIEM, log aggregators, or disk logs. |
| **No Passwords in URLs** | All queries use HTTP POST with JSON body. | Passwords never appear in browser history, proxy logs, or Referer headers. |
| **No Password Echoing** | API responses and suggestions never include the submitted password. | Eliminates accidental DOM reflection or response leakage. |
| **No Client Caching** | Response headers set `Cache-Control: no-store, no-cache, must-revalidate`. | Prevents browsers or intermediate proxies from caching sensitive inputs. |
| **No Browser Storage** | Javascript explicitly avoids `localStorage` and `sessionStorage`. | Defeats cross-site scripting (XSS) credential scraping. |
| **Constant-Time Verification**| Employs `secrets.compare_digest` in hash verification. | Mitigates timing side-channel attacks on verification endpoints. |
| **Cryptographic Randomness** | Password generation uses `secrets` (OS entropy source), never `random`. | Predictable pseudo-random generators (PRNG) enable attacker keyspace reduction. |

---

## 2. Database Schema Audit
The application uses SQLite solely for anonymous, aggregate educational telemetry.

```sql
-- ANALYSES TABLE: Strictly mathematical metadata
CREATE TABLE analyses (
    analysis_id TEXT PRIMARY KEY,
    score INTEGER NOT NULL,
    classification TEXT NOT NULL,
    password_length INTEGER NOT NULL,
    unique_character_ratio REAL NOT NULL,
    weakness_count INTEGER NOT NULL,
    created_at TEXT NOT NULL
);

-- FINDINGS TABLE: Categorical detection types
CREATE TABLE findings (
    finding_id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id TEXT NOT NULL,
    finding_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    description TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses (analysis_id)
);
```

> **Audit Note:** Notice the complete absence of `password`, `plaintext`, `salt`, `hash`, or `user_id` columns. Even in the event of a full SQL injection or physical server theft, zero credentials can be recovered.

---

## 3. Cryptographic Key Stretching vs. Fast Hashing

### The Danger of Fast Hashes
Cryptographic hash functions like **MD5**, **SHA-1**, and **SHA-256** were engineered for rapid file integrity verification. 
- A modern GPU cluster (e.g., 8x NVIDIA RTX 4090s) can compute over **100 billion raw SHA-256 hashes per second**.
- If a database storing raw or salted SHA-256 hashes is compromised, an attacker can brute force complex 8-10 character passwords in hours.

### Modern Password Hashing Functions
Dedicated password hashing algorithms introduce a **work factor** (iteration count, memory hardness, and parallelism) that drastically slows down the computation:

1. **Argon2id**: The winner of the Password Hashing Competition (PHC). Provides resistance against GPU and ASIC cracking via memory-hard loops.
2. **PBKDF2-HMAC-SHA256**: Approved by NIST SP 800-63B and OWASP. OWASP recommends at least **600,000 iterations** for SHA-256.
3. **bcrypt**: Adaptive hashing function based on the Blowfish cipher with configurable work factor ($2^{cost}$ rounds).
4. **scrypt**: Memory-hard key derivation function designed to defeat custom hardware implementations.

---

## 4. Constant-Time Verification & Timing Attacks
When comparing a computed hash against a stored hash, standard string equality operators (`==`) compare character-by-character and abort at the first mismatched byte. An attacker measuring network round-trip latency at microsecond resolution can deduce the correct hash byte-by-byte.

This project implements:
```python
import secrets
is_valid = secrets.compare_digest(calculated_hash_hex, expected_hash_hex)
```
`secrets.compare_digest` runs in **constant time**, executing the exact same number of operations regardless of where or whether characters differ.
