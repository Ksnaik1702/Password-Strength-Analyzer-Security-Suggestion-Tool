# 🛡️ Password Strength Analyzer & Security Suggestion Tool
> **Privacy-Preserving Defensive Cybersecurity & IAM Assessment Platform**  
> *Aligned with NIST SP 800-63B Guidelines, OWASP ASVS, and Zero-Storage Privacy Architecture.*

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?logo=python&logoColor=white)](https://python.org)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.110%2B-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![Tests](https://img.shields.io/badge/Tests-40%2F40%20Passing-emerald?logo=pytest&logoColor=white)](#testing)
[![Defense](https://img.shields.io/badge/Defensive%20Security-NIST%20SP%20800--63B-purple)](#password-policy-checker)
[![Privacy](https://img.shields.io/badge/Privacy-Zero--Storage%20In--Memory-success)](#privacy-design)
[![License](https://img.shields.io/badge/License-MIT-lightgrey)](LICENSE)

---

## 📖 Overview
The **Password Strength Analyzer & Security Suggestion Tool** is an industry-grade, defensive cybersecurity project designed to assess password resilience in real time. Rather than relying on outdated composition checks (e.g. *uppercase + lowercase + number + symbol*), the platform evaluates passwords across multi-dimensional criteria: **length, structural unpredictability, pattern resistance, spatial keyboard walks, dictionary matches, and personal context overlap**.

The platform is engineered with a strict **Zero-Storage Privacy Architecture**—passwords are analyzed transiently in volatile RAM and are **never** logged, persisted to disk, or transmitted to third-party endpoints.

---

## 🎯 Problem Statement
Most commercial registration forms and legacy IAM portals employ simplistic regex composition rules. Consequently, passwords such as:
```text
Password123!
```
pass traditional checks despite being among the fastest cracked credentials in offline dictionary attacks. Conversely, long, high-entropy passphrases (e.g., `velvet-harbor-drift-galaxy`) are frequently rejected because they omit arbitrary punctuation.

This disconnect leaves user accounts vulnerable to:
- **Credential Stuffing Attacks**: Automated bots replaying leaked credentials.
- **Rule-Based Dictionary Attacks**: Attacker tools (Hashcat, John the Ripper) appending predictable digits and years to common base words.
- **Keyboard Walk Exploitation**: Sequential key combinations (`qwerty`, `1qaz2wsx`).

---

## 🚀 Key Features

| Capability | Defensive Description |
|---|---|
| **🔍 Real-Time Live Meter** | Dynamic debounced keystroke evaluation (200ms) with animated color-coded strength transitions and score (0–100). |
| **📏 Length & Pool Analytics** | Evaluates length against critical resistance bands (<8, 8-11, 12-15, 16+) and calculates pool size $N$. |
| **🧠 Multi-Vector Pattern Detection** | Detects sequential runs (`1234`, `abcd`), reverse runs (`9876`), QWERTY walks (`qwerty`, `asdf`), and repetitions (`aaaa`, `ababab`). |
| **📕 Common Password & Breach Lookup** | Offline blocklist validation comparing against common passwords and SHA-1 breach digests. |
| **👤 Personal Context Warning** | Optional social-engineering simulation warning users if credentials contain names, birth years, or employers. |
| **💡 Actionable Suggestion Engine** | Prioritized coaching tips tailored to specific weaknesses that **never** echo the user's password. |
| **🎲 CSPRNG Credential Generator** | Cryptographically secure random password and Diceware passphrase generator powered by Python's `secrets` module. |
| **📋 NIST SP 800-63B Policy Checker**| Evaluates organizational compliance independently of the strength score. |
| **🔐 Interactive Hashing Laboratory** | Hands-on demonstration of 16-byte cryptographic salts, PBKDF2-HMAC-SHA256 (600,000 rounds), and constant-time verification. |
| **📊 Anonymous Telemetry Dashboard** | Interactive Chart.js charts rendering population trends with strictly zero credential storage. |

---

## 🏗️ System Architecture

```
User Input (Password + Optional Context)
                   │
                   ▼ (HTTP POST /api/analyze in RAM)
┌─────────────────────────────────────────────────────────────┐
│                 FASTAPI IN-MEMORY ENGINE                    │
│                                                             │
│  [Length Analyzer]  [Character Analyzer]  [Entropy Model]   │
│         │                  │                    │           │
│         └───────────┬──────┴────────────────────┘           │
│                     ▼                                       │
│        [Multi-Vector Pattern Detectors]                     │
│         ├── Sequence Runs (1234, abcd)                      │
│         ├── Keyboard Walks (qwerty, 1qaz)                   │
│         ├── Character Repetition (aaaa, abab)               │
│         ├── Common Words + Years (Summer2026!)              │
│         ├── Personal Info Overlap (Name, Birth Year)        │
│         └── Common Password & Breach Hash Match             │
│                     │                                       │
│                     ▼                                       │
│        [Balanced Scoring Engine (0-100)]                    │
│         └── Tier: VERY WEAK | WEAK | MODERATE | STRONG...   │
│                     │                                       │
│                     ▼                                       │
│        [Security Suggestion Engine]                         │
└─────────────────────┬───────────────────────────────────────┘
                      │
           ┌──────────┴──────────┐
           ▼                     ▼
 ┌───────────────────┐ ┌──────────────────────────────────┐
 │  JSON API Output  │ │    SQLite Telemetry (RAM/DB)     │
 │  Score, Findings, │ │ Table: analyses                  │
 │  Suggestions      │ │ (score, length, weakness_count)  │
 │  [NO PLAINTEXT]   │ │ [STRICTLY NO PASSWORD FIELDS]    │
 └───────────────────┘ └──────────────────────────────────┘
```

---

## 🛠️ Technology Stack

- **Backend Framework:** Python 3.10+, FastAPI (Asynchronous, High-Performance REST API)
- **ASGI Server:** Uvicorn
- **Cryptographic Services:** Python standard library `secrets` (CSPRNG) & `hashlib` (PBKDF2-HMAC-SHA256, SHA-1, SHA-256)
- **Data Validation & Contracts:** Pydantic v2
- **Database (Anonymous Telemetry):** SQLite3
- **Frontend Architecture:** Modern Semantic HTML5, CSS3 Custom Properties (Dark Mode Theme), Vanilla ES6+ JavaScript
- **Visual Analytics:** Chart.js
- **Automated Testing:** Pytest, Starlette TestClient, AnyIO

---

## 📐 Scoring Calibration & Rubric (0–100)

Password strength cannot be represented by a single simplistic formula. Our rubric balances positive contributions with penalizing deductions:

### Positive Score Contributions
- **Length Contribution:** Up to **+35 pts** (Graduated curve reaching maximum at 16+ characters).
- **Character Diversity:** Up to **+15 pts** (Presence of lowercase, uppercase, digits, and symbols).
- **Unique Character Ratio:** Up to **+10 pts** ($\text{unique} / \text{length}$).
- **Non-Common Bonus:** **+10 pts** (Absent from common dictionary and breach list).
- **Pattern Resistance Bonus:** Up to **+20 pts** (Zero sequences, keyboard walks, or repetitions).
- **Unpredictability Bonus:** Up to **+10 pts** (Length $\ge 14$ with high diversity and no patterns).

### Penalties & Guardrail Limits
- **Length $< 6$ characters:** Final score strictly capped at **15** (VERY WEAK).
- **Length $< 8$ characters:** Final score strictly capped at **25** (WEAK).
- **Common or Breached match:** **-45 penalty** and capped at **15** (VERY WEAK).
- **Keyboard Walk (`qwerty`, `1qaz`):** **-12 to -25 pts**.
- **Sequential Runs (`1234`, `abcd`):** **-8 to -20 pts**.
- **Character Repetition (`aaaa`, `abab`):** **-10 to -25 pts**.
- **Personal Context Overlap:** **-20 pts**.
- **Compound Word + Year (`Admin2026!`):** **-15 pts**.

### Classification Bands
- **0 – 20:** `VERY WEAK`
- **21 – 40:** `WEAK`
- **41 – 60:** `MODERATE`
- **61 – 80:** `STRONG`
- **81 – 100:** `VERY STRONG`

---

## 🔒 Privacy & Defensive Architecture

This project was built from the ground up under a **Zero-Storage Privacy Mandate**:
1. **No Plaintext Persistence:** The SQLite schema contains zero password, hash, or username columns.
2. **No Logging:** Application logs explicitly suppress request payloads.
3. **No URL Leaks:** All API requests use HTTP POST with body payloads, preventing passwords from leaking into server access logs, browser histories, or proxies.
4. **No Browser Storage:** JavaScript avoids `localStorage` and `sessionStorage` entirely to protect against XSS exfiltration.
5. **No Password Reflection:** Suggestions and API responses never echo or reproduce the submitted password.
6. **Constant-Time Verification:** Verification endpoints utilize `secrets.compare_digest` to prevent microsecond-level timing attacks.

---

## 💻 Installation & Setup

### Prerequisites
- Python 3.10 or higher
- Git

### Step 1: Clone Repository
```bash
git clone https://github.com/yourusername/Password-Strength-Analyzer-Security-Tool.git
cd Password-Strength-Analyzer-Security-Tool
```

### Step 2: Create and Activate Virtual Environment
```bash
# Windows (PowerShell)
python -m venv venv
.\venv\Scripts\Activate.ps1

# Linux / macOS
python3 -m venv venv
source venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4: Launch Application
```bash
python run.py
```
*The script will initialize the database and automatically open your default browser at `http://127.0.0.1:8000`.*

---

## 🧪 Testing Suite

The project includes **40 automated tests** covering unit heuristics, pattern detectors, entropy calculations, NIST policy rules, and security audits.

```bash
# Run full automated test suite with verbose output
python -m pytest tests -v
```

### Test Suite Modules
- `tests/test_analyzer.py`: Validates boundaries (empty, 1-char, passphrases, unicode, max-length 200+).
- `tests/test_patterns.py`: Validates sequence detectors, reverse runs, keyboard walks, and personal context.
- `tests/test_entropy_and_scoring.py`: Validates theoretical bits, overflow safety, and 5-tier scoring boundaries.
- `tests/test_generator_and_policy.py`: Validates CSPRNG randomness, NIST SP 800-63B policy rules, and PBKDF2 salting.
- `tests/test_security_and_privacy.py`: Queries SQLite table metadata (`PRAGMA table_info`) to mathematically verify absence of credential storage.
- `tests/test_api_endpoints.py`: Validates REST endpoint status codes, JSON schemas, and security headers.

---

## 📊 Safe Demonstration Scenarios

Use these synthetic test cases for demonstrations and coursework submissions:

| Scenario | Input | Score | Tier | Why it Scores This Way |
|---|---|---|---|---|
| **1. Trivial Numeric** | `123456` | **0** | `VERY WEAK` | Listed in top dictionary passwords; contains ascending sequence `123456`; length $< 8$. |
| **2. False Complexity** | `Password123!` | **36** | `WEAK` | Has 4 character types, but relies on common word `password` + predictable sequence `123`. |
| **3. Long Repetition** | `aaaaaaaaaaaaaaaa` | **30** | `WEAK` | 16 characters long, but heavily penalized due to consecutive single-character repetition. |
| **4. Spatial Walk** | `qwerty2026!` | **35** | `WEAK` | QWERTY horizontal row walk combined with predictable four-digit year `2026`. |
| **5. Moderate Hybrid**| `Summer2026!` | **46** | `MODERATE` | Decent baseline variety, but contains calendar season word + current year pattern. |
| **6. High Variety** | `Orange#77Secure` | **74** | `STRONG` | 15 characters, 4 character categories, high uniqueness ratio, zero sequential runs. |
| **7. 4-Word Passphrase**| `velvet-harbor-drift-galaxy`| **85** | `VERY STRONG`| High length baseline (26 chars), memorable, resistant to standard dictionary masks. |
| **8. Generated CSPRNG** | `X7#mK9$vL2@qZ8!wP4^r` | **100** | `VERY STRONG`| Maximum diversity, high uniqueness ratio, zero patterns, cryptographically random. |

---

## 📚 10 Golden Rules of Password & Identity Hygiene
1. **Length Beats Complexity:** Prioritize 14–16+ character passphrases over short, complex words.
2. **Never Reuse Credentials:** Credential stuffing compromises every account sharing a leaked password.
3. **Avoid Personal Attributes:** Never include birth years, names, pet names, or employer names.
4. **Eliminate Keyboard Walks:** Avoid spatial walks like `qwerty`, `asdf`, and `1qaz`.
5. **Use a Password Manager:** Generate and store high-entropy unique credentials for every account.
6. **Enforce Multi-Factor Authentication (MFA):** FIDO2/WebAuthn hardware tokens and TOTP apps defeat 99% of automated account takeover (ATO) attacks.
7. **Eliminate Forced Periodic Rotation:** NIST SP 800-63B recommends changing passwords only upon suspected compromise.
8. **Never Share Plaintext Credentials:** Never send credentials via unencrypted email or chat.
9. **Beware of Phishing:** The strongest password is ineffective if submitted to a fraudulent clone site.
10. **Monitor Breach Disclosures:** Check compromised credential indices and rotate exposed passwords promptly.

---

## 🎓 Learning Outcomes
- Understanding the mathematical and structural limitations of legacy composition rules.
- Hands-on experience implementing defensive string inspection algorithms (sequences, walks, repetitions).
- Applied knowledge of NIST SP 800-63B Digital Identity Guidelines and OWASP ASVS standards.
- Deep comprehension of password hashing, salt uniqueness, key stretching, and constant-time equality comparisons.
- Designing and implementing privacy-first architectures with zero plaintext retention.

---

## ⚖️ Security Disclaimer
*This application is developed strictly for educational, defensive, and security-awareness purposes. It is engineered to analyze passwords locally and assist users in selecting resilient credentials. It does not provide password-cracking, credential-harvesting, or unauthorized exploitation capabilities. All testing must be conducted using synthetic test passwords.*

---

## 👤 Author & Acknowledgments
- **Project Lead:** Cybersecurity & Application Security Student
- **Coursework:** Identity and Access Management & Secure Software Engineering
- **Built With:** Python, FastAPI, Chart.js, and Modern Web Standards.
