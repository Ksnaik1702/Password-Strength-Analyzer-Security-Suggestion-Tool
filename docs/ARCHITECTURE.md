# System Architecture & Technical Specification

## 1. High-Level Architecture Overview

The **Password Strength Analyzer & Security Suggestion Tool** is architected as a privacy-preserving, defensive cybersecurity assessment application. It operates on a strict **zero-storage, in-memory transient processing model**.

```
+-------------------------------------------------------------------------+
|                              USER INTERFACE                             |
|    Real-Time Password Meter | CSPRNG Generator | NIST Policy Checker    |
|               Hashing Laboratory | Anonymous Telemetry Dashboard        |
+-------------------------------------------------------------------------+
                                     |
               HTTP POST /api/analyze (JSON over TLS/Localhost)
               [Zero URL Parameters - Payload in Request Body]
                                     |
                                     v
+-------------------------------------------------------------------------+
|                           FASTAPI WEB BACKEND                           |
|        Security Middleware (X-Frame-Options, No-Cache, No-Store)        |
+-------------------------------------------------------------------------+
                                     |
                                     v
+-------------------------------------------------------------------------+
|                     PASSWORD ANALYSIS ENGINE (RAM ONLY)                 |
|                                                                         |
|  +--------------------+  +---------------------+  +------------------+  |
|  |   Length Analyzer  |  |  Character Analyzer |  | Entropy Estimator|  |
|  |   (Bands <8..16+)  |  |  (Charset & Pool)   |  | (Shannon/Pool)   |  |
|  +--------------------+  +---------------------+  +------------------+  |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                 Multi-Vector Pattern Detectors                    |  |
|  |  * Sequential Runs (0123, 9876, abcd, dcba)                       |  |
|  |  * Spatial Keyboard Walks (qwerty, asdf, 1qaz, 2wsx)              |  |
|  |  * Character Repetition & Syllables (aaaa, ababab)                |  |
|  |  * Predictable Structures (Base Words + Years/Dates/Phones)       |  |
|  |  * Personal Context Overlap (Name, Birth Year, Org/College)       |  |
|  |  * Common Dictionary & Local Breached Hash Blocklist              |  |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                   Balanced Scoring Engine (0-100)                 |  |
|  |  Positive Contributions - Pattern Deductions -> Capped Scores     |  |
|  |  Classifications: VERY WEAK | WEAK | MODERATE | STRONG | VERY STRONG |
|  +-------------------------------------------------------------------+  |
|                                                                         |
|  +-------------------------------------------------------------------+  |
|  |                  Actionable Suggestion Engine                     |  |
|  |  Constructive, tailored tips (Never echoes plaintext credentials)  |  |
|  +-------------------------------------------------------------------+  |
+-------------------------------------------------------------------------+
             |                                              |
             | Transient RAM Output                         | Anonymous Telemetry
             v                                              v
+-----------------------------+           +-------------------------------+
|      API JSON RESPONSE      |           |     SQLITE ANALYTICS DB       |
| Score, Class, Findings,     |           | Table: analyses               |
| Suggestions, Entropy Metrics|           | (length, score, weakness_cnt) |
| [NO PLAINTEXT / NO HASHES]  |           | [STRICTLY NO PASSWORD FIELDS] |
+-----------------------------+           +-------------------------------+
```

## 2. In-Memory Processing & Privacy Guarantee
In traditional web applications, user inputs may be logged by reverse proxies, captured in debug traces, or inserted into persistence tables. 

This project enforces:
1. **Zero Logging**: Logging formatters explicitly omit request payloads.
2. **Ephemeral Garbage Collection**: The candidate password string exists solely within the activation record of the FastAPI worker thread and is released immediately following response dispatch.
3. **Database Schema Isolation**: The SQLite analytics database schema contains no columns capable of holding credentials or password hashes.

## 3. Modular Service Architecture

| Service Component | Module Path | Purpose & Responsibility |
|---|---|---|
| **Length Analyzer** | `backend/services/length_analyzer.py` | Categorizes length into 4 risk tiers (<8, 8-11, 12-15, 16+) and calculates base search-space contribution (up to +35 pts). |
| **Character Analyzer** | `backend/services/character_analyzer.py` | Analyzes charset presence (lower, upper, digits, symbols), character pool size $N$, and unique character ratio. |
| **Sequence Detector** | `backend/services/sequence_detector.py` | Detects ascending/descending alphanumeric runs (e.g. `1234`, `9876`, `abcd`, `zyxw`). |
| **Keyboard Walk Detector** | `backend/services/keyboard_detector.py` | Detects horizontal QWERTY row walks (`qwerty`, `asdf`) and vertical column walks (`1qaz`, `2wsx`). |
| **Repetition Detector** | `backend/services/repetition_detector.py` | Identifies character runs (`aaaa`, `1111`) and repeating multi-character chunks (`ababab`, `testtest`). |
| **Common Password Checker**| `backend/services/common_password_checker.py` | Validates against curated offline common password dictionary and demo SHA-1 breach corpus. |
| **Pattern Detector** | `backend/services/pattern_detector.py` | Detects compound words + years (`Summer2026!`), dates, and optional personal context overlap. |
| **Entropy Estimator** | `backend/services/entropy_estimator.py` | Computes theoretical Shannon entropy ($L \times \log_2(N)$) and provides educational limitations. |
| **Scoring Engine** | `backend/services/scoring_engine.py` | Blends bonuses and penalties into calibrated 0-100 score and five strength tiers. |
| **Suggestion Engine** | `backend/services/suggestion_engine.py` | Produces prioritized, specific recommendations without echoing passwords. |
| **Secure Generator** | `backend/services/password_generator.py` | CSPRNG password and Diceware passphrase generator using Python `secrets`. |
| **Policy Checker** | `backend/services/policy_checker.py` | Evaluates compliance against NIST SP 800-63B guidelines (Pass/Fail). |
| **Hashing Laboratory** | `backend/services/hashing_demo.py` | Demonstrates PBKDF2-HMAC-SHA256 (600,000 iterations) salting and constant-time verification. |
