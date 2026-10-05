# Visual Proof & Screenshot Checklist

Use this guide to capture professional screenshots for your GitHub repository, project report, LinkedIn showcase, and course submission portfolio.

## Screenshot Capture Inventory

| ID | Recommended Filename | UI Section / Command | Description & Synthetic Input |
|---|---|---|---|
| **01** | `01_project_tree_structure.png` | Terminal / IDE Explorer | Clean folder structure showing `backend/`, `frontend/`, `tests/`, `docs/`, `data/`. |
| **02** | `02_architecture_diagram.png` | Architecture Document | High-level dataflow diagram illustrating in-memory transient processing. |
| **03** | `03_analyzer_landing_clean.png` | Live Analyzer Tab | Clean landing view showing empty input field and waiting status badge. |
| **04** | `04_show_hide_toggle.png` | Password Input Field | Demonstrate the eye button revealing masked password text. |
| **05** | `05_scenario_very_weak.png` | Live Analyzer | Synthetic input: `123456`. Score 0/100, VERY WEAK badge, common password warning. |
| **06** | `06_scenario_weak.png` | Live Analyzer | Synthetic input: `Password123!`. Demonstrates why composition rules alone fail. |
| **07** | `07_scenario_moderate.png` | Live Analyzer | Synthetic input: `Summer2026!`. Demonstrates compound word + year penalty. |
| **08** | `08_scenario_strong.png` | Live Analyzer | Synthetic input: `Orange#77Secure`. Score 61-75/100, STRONG classification. |
| **09** | `09_scenario_very_strong.png` | Live Analyzer | Synthetic input: `X7#mK9$vL2@qZ8!w`. Score 85-100/100, VERY STRONG badge. |
| **10** | `10_length_analysis_breakdown.png` | Metrics Cards | Showing length categorization chip (<8, 8-11, 12-15, 16+). |
| **11** | `11_sequence_detection.png` | Findings List | Highlighting detection of ascending/descending runs (`1234`, `9876`, `abcd`). |
| **12** | `12_keyboard_walk_detection.png`| Findings List | Highlighting detection of spatial keyboard walks (`qwerty`, `asdf`, `1qaz`). |
| **13** | `13_repetition_detection.png` | Findings List | Input `aaaaaaaaaaaaaaaa` demonstrating severe repetition deduction. |
| **14** | `14_common_password_warning.png`| Findings List | Red critical alert: matches known dictionary or breached hash list. |
| **15** | `15_security_recommendations.png`| Suggestions Section | Actionable coaching tips generated dynamically based on vulnerabilities. |
| **16** | `16_entropy_nuance_callout.png` | Live Analyzer | Educational box explaining why theoretical entropy is misleading for human inputs. |
| **17** | `17_secure_generator_complex.png`| Generator Tab | Generating a 20-character CSPRNG password with one-click clipboard copy. |
| **18** | `18_secure_generator_passphrase.png`| Generator Tab | Generating a 4-word Diceware passphrase (`velvet-harbor-drift-galaxy`). |
| **19** | `19_policy_checker_pass.png` | Policy Validator Tab | Evaluation of `Correct-Horse-Battery-Staple` showing green POLICY PASS. |
| **20** | `20_policy_checker_fail.png` | Policy Validator Tab | Evaluation of `Short1!` showing red POLICY FAIL with rule checklist. |
| **21** | `21_hashing_lab_salt_pbkdf2.png`| Hashing Lab Tab | Interactive computation of 16-byte salt and 600,000-iteration PBKDF2 hash. |
| **22** | `22_hashing_lab_verify_match.png`| Hashing Lab Tab | Constant-time verification test showing SUCCESS: Match verified. |
| **23** | `23_dashboard_aggregate_overview.png`| Dashboard Tab | Top counter cards: Total analyses, average score, weak %, strong %. |
| **24** | `24_dashboard_chart_classifications.png`| Dashboard Tab | Chart.js doughnut chart showing strength distribution percentages. |
| **25** | `25_dashboard_chart_weaknesses.png`| Dashboard Tab | Horizontal bar chart illustrating frequency of detected vulnerability types. |
| **26** | `26_automated_unit_tests_pass.png`| Terminal / Powershell | Command `pytest tests -v` displaying 40/40 passed tests in green. |
| **27** | `27_privacy_db_schema_audit.png`| SQLite Terminal / DBeaver | Schema inspection of `analyses` table proving complete absence of password columns. |
| **28** | `28_api_swagger_docs.png` | Browser at `/docs` | Interactive FastAPI OpenAPI documentation displaying all tested routes. |
