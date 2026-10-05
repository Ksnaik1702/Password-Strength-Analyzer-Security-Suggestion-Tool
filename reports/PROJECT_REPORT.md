# Academic & Engineering Project Report

## Project Title
**Password Strength Analyzer & Security Suggestion Tool: A Privacy-Preserving Defensive Cybersecurity Assessment Platform**

**Author / Candidate:** Cybersecurity Student & Application Security Researcher  
**Course:** Advanced Cybersecurity & Identity and Access Management (IAM)  
**Date:** October 2026  

---

### Abstract
Weak, predictable, and reused passwords remain the single most pervasive root cause of enterprise security breaches and credential stuffing incidents. Traditional password strength meters rely predominantly on rudimentary composition heuristics (e.g., verifying whether a password contains an uppercase letter, lowercase letter, digit, and symbol). Such mechanisms frequently endorse vulnerable, predictable passwords such as `Password123!` while rejecting mathematically robust passphrases. 

This project engineers an end-to-end, privacy-preserving defensive cybersecurity platform that evaluates password resilience in real time. The system couples length heuristics, character diversity, and Shannon theoretical entropy with multi-vector pattern detectors for sequential runs, spatial keyboard walks, character repetition, compound word-year structures, dictionary matches, and optional personal context overlap. Implemented using Python, FastAPI, and vanilla modern web technologies, the platform enforces a zero-storage transient memory model where candidate credentials are never written to disk, access logs, or persistent databases. The platform also provides an NIST SP 800-63B policy validator, an interactive PBKDF2-HMAC-SHA256 salted hashing laboratory, and an anonymous aggregate telemetry dashboard.

---

### 1. Introduction
Identity and Access Management (IAM) serves as the primary defensive perimeter for modern enterprise networks, cloud platforms, and consumer applications. Despite widespread adoption of multi-factor authentication (MFA), passwords remain the foundational authenticator for billions of digital interactions. 

However, humans are inherently poor random number generators. Cognitive constraints lead individuals to choose memorable strings structured around dictionary words, common substitutions (e.g., `@` for `a`), keyboard walks (`qwerty`), and personal milestones (birthdays, children's names). To counter this, organizations traditionally implemented rigid composition rules. Unfortunately, these rules failed to curtail predictable structures while significantly degrading user experience. This project bridges the gap between academic cryptography, enterprise IAM standards, and real-world user coaching.

---

### 2. Problem Statement
Existing client-side password meters suffer from three critical flaws:
1. **Flawed Composition Metrics:** Standard meters treat character diversity as a proxy for unpredictability. A string such as `Admin2026!` achieves high diversity scores despite being trivial for dictionary attack engines (e.g., Hashcat with `best64` rules).
2. **Privacy and Exposure Risks:** Many web-based password checkers transmit credentials over unencrypted channels or store prospective passwords in backend analytics databases, inadvertently creating centralized high-value targets.
3. **Absence of Actionable Coaching:** Conventional tools indicate failure without explaining *why* a password is weak or how to construct robust, memorable passphrases.

---

### 3. Objectives
The technical and pedagogical objectives of this project are:
- Build an in-memory, zero-retention analysis engine capable of evaluating password resilience across multiple defensive dimensions.
- Implement specialized detection algorithms for alphanumeric sequences, horizontal/vertical keyboard walks, character repetition, and predictable suffix patterns.
- Implement an offline dictionary matching service and local simulated breach lookup using SHA-1 hashes.
- Calculate theoretical Shannon entropy while explicitly educating users regarding its practical limitations when applied to human choices.
- Deliver prioritized, constructive, non-echoing security suggestions and an NIST SP 800-63B policy compliance auditor.
- Build an educational cryptographic laboratory demonstrating salted password hashing (PBKDF2-HMAC-SHA256 with 600,000 rounds) and constant-time verification.
- Provide an anonymous aggregate dashboard tracking population-level weakness frequencies without persisting credentials.

---

### 4. Theoretical Background & Authentication Fundamentals

#### 4.1 Authentication vs. Authorization
- **Authentication (AuthN):** The verification of an entity's claimed identity ("Who are you?").
- **Authorization (AuthZ):** The verification of an entity's access privileges ("What resources are you permitted to interact with?").

#### 4.2 Plaintext Passwords vs. Password Hashes
Production authentication systems must never store plaintext passwords. Storing plaintext credentials turns any database compromise into an immediate catastrophic breach. Instead, modern systems store **salted, key-stretched hashes**.

#### 4.3 Why General-Purpose Fast Hashes are Inadequate
Fast cryptographic hash algorithms such as MD5, SHA-1, and SHA-256 were designed for rapid file integrity verification, processing gigabytes per second. When applied to passwords, their speed enables attackers to compute billions of guesses per second on consumer graphics cards (GPUs). Password storage necessitates dedicated **slow, key-stretching functions** (Argon2id, PBKDF2, bcrypt, scrypt) that enforce high CPU and memory costs per verification attempt.

#### 4.4 The Role of Cryptographic Salts
A salt is a cryptographically unique random sequence generated for each user credential. Salting ensures that:
1. Identical passwords chosen by different users produce distinct stored hashes.
2. Precomputed dictionary lookup tables (Rainbow Tables) are completely neutralized, forcing adversaries to crack each hash individually.

---

### 5. System Architecture & Component Design
The system follows a decoupled, service-oriented architecture:
1. **Interactive Client UI (HTML5, CSS3, ES6 JavaScript):** Provides real-time debounced evaluation (200ms latency), show/hide toggles, CSPRNG credential generation, and Chart.js telemetry charts.
2. **FastAPI Web Application:** Implements RESTful endpoints, CORS controls, and security headers (`X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Cache-Control: no-store`).
3. **Core Analysis Pipeline:**
   - `LengthAnalyzer`: Evaluates length against critical resistance bands (<8, 8-11, 12-15, 16+).
   - `CharacterAnalyzer`: Quantifies charset pool size and uniqueness ratios.
   - `SequenceDetector`: Scans for ascending/descending runs (`1234`, `abcd`, `9876`).
   - `KeyboardDetector`: Detects spatial QWERTY horizontal walks and vertical columns.
   - `RepetitionDetector`: Flags consecutive identical characters and repeating chunk syllables (`aaaa`, `abab`).
   - `CommonPasswordChecker`: Scans offline top-password lists and demo breach sets.
   - `PatternDetector`: Identifies compound structures (word + year/date/phone) and personal context overlap.
   - `EntropyEstimator`: Calculates theoretical Shannon bits ($H = L \cdot \log_2 N$).
   - `ScoringEngine`: Balances positive weights against deductions to produce a 0-100 score.
   - `SuggestionEngine`: Synthesizes defensive remediation guidance.
4. **Privacy-Safe SQLite Database:** Records strictly anonymous telemetry (`analysis_id`, `score`, `classification`, `length`, `weakness_count`, `created_at`). Contains zero password columns.

---

### 6. Mathematical Model & Scoring Calibration
The scoring model balances positive search-space contributions against structural predictability penalties:

$$\text{Raw Score} = (\text{Length Pts} + \text{Diversity Pts} + \text{Uniqueness Pts} + \text{Bonuses}) - \sum \text{Penalties}$$

- **Length Points:** Up to 35 points (graduated scaling, reaching maximum at 16+ characters).
- **Diversity Points:** Up to 15 points based on presence of lowercase, uppercase, digits, and symbols.
- **Uniqueness Ratio:** Up to 10 points based on unique characters divided by length.
- **Pattern Resistance Bonus:** Up to 20 points if no sequences, keyboard walks, or repetitions exist (contingent on length $\ge 8$).
- **Non-Common Bonus:** 10 points if absent from dictionary and breach corpora.
- **Unpredictability Bonus:** Up to 10 points for length $\ge 14$ with high diversity and zero patterns.

**Penalties & Guardrail Caps:**
- If length $< 6$, final score is strictly capped at 15 (VERY WEAK).
- If length $< 8$, final score is strictly capped at 25 (WEAK).
- If found in common password or breach list: -45 penalty and capped at 15 (VERY WEAK).
- Severe repetition run: -20 penalty and capped at 30.

---

### 7. Experimental Results & Verification

| Test Scenario | Sample Input | Score | Classification | Primary Findings Triggered |
|---|---|---|---|---|
| **Scenario 1: Trivial Numeric** | `123456` | **0** | **VERY WEAK** | Common password, sequence `123456`, length < 8 |
| **Scenario 2: False Security** | `Password123!` | **36** | **WEAK** | Common base word `password`, sequence `123`, year/predictable digits |
| **Scenario 3: Long Repetition** | `aaaaaaaaaaaaaaaa` | **30** | **WEAK** | Severe repetition `aaaa`, single charset, low unique ratio |
| **Scenario 4: Keyboard Walk** | `qwerty2026!` | **35** | **WEAK** | Keyboard walk `qwerty`, predictable year `2026` |
| **Scenario 5: Moderate Complex** | `Summer2026!` | **46** | **MODERATE** | Good variety, but contains predictable word + year |
| **Scenario 6: Robust Mixed** | `Orange#77Secure` | **74** | **STRONG** | Length 15, 4 charsets, high uniqueness, zero walks |
| **Scenario 7: 4-Word Passphrase** | `velvet-harbor-drift-galaxy`| **85** | **VERY STRONG** | Length 26, high entropy baseline, zero common sequences |
| **Scenario 8: CSPRNG 20-Char** | `X7#mK9$vL2@qZ8!wP4^r` | **100** | **VERY STRONG** | Maximum diversity, high uniqueness, total pattern resistance |

---

### 8. Defensive Security Audit & Testing
The system was evaluated through an automated test suite comprising 40 unit and integration tests across 6 specialized modules:
- `test_analyzer.py`: Validated boundary inputs (empty, 1-char, max length 200+, unicode, spaces).
- `test_patterns.py`: Validated sequences, reverse runs, QWERTY walks, syllable repeats, and personal context.
- `test_entropy_and_scoring.py`: Verified entropy bit math, overflow prevention, and scoring calibration.
- `test_generator_and_policy.py`: Verified CSPRNG randomness, NIST SP 800-63B policy rules, and salt generation.
- `test_security_and_privacy.py`: Inspected SQLite tables using `PRAGMA table_info` to mathematically verify zero password or hash columns exist in the database.
- `test_api_endpoints.py`: Verified HTTP response contracts, security headers, and absence of credential reflection.

**Result:** 40 / 40 test cases passed with zero regressions.

---

### 9. Limitations & Defensive Constraints
1. **Offline Dictionary Scope:** The local dictionary contains ~100 common passwords for rapid local demonstration. In enterprise production, integration with a privacy-preserving k-anonymity API (such as HaveIBeenPwned API v3) is recommended.
2. **Context Scope:** Personal context detection relies on voluntary user input and cannot detect unsupplied biographical facts.
3. **Crack Time Estimation:** Theoretical crack times assume uniform random offline brute forcing. In real-world attacks, specialized rule-based dictionary attacks crack structured passwords significantly faster.

---

### 10. Future Scope
- **Enterprise IAM SSO Integration:** Integration with Okta, Azure AD, or Keycloak as a pre-registration validation webhook.
- **Passkey & WebAuthn Education:** Adding interactive modules demonstrating FIDO2 passwordless authentication.
- **k-Anonymity Remote Breach API:** Querying remote breach APIs using 5-character SHA-1 hash prefixes to maintain user privacy over the wire.

---

### 11. Conclusion
The **Password Strength Analyzer & Security Suggestion Tool** demonstrates that effective credential defense requires analyzing length, unpredictability, spatial patterns, and dictionary heuristics rather than relying on legacy composition rules. By coupling real-time analysis with an uncompromising zero-storage privacy model, the application serves as a benchmark defensive cybersecurity project demonstrating applied cryptography, secure software architecture, and IAM engineering.
