# Password Security Analysis Engine


A Python-based password security analysis tool that evaluates password strength using multiple security checks, explainable scoring, theoretical entropy analysis, and predictable-pattern detection.

The project also includes a cryptographically secure password generator and an automated test suite.

## About the Project

Password complexity does not necessarily mean password security.

For example:

```text
Password123!
```

contains uppercase and lowercase letters, numbers, and symbols, but remains highly predictable.

Password Security Analysis Engine was developed to explore this problem by evaluating not only password composition, but also patterns commonly associated with weak or predictable passwords.

The project focuses on practical concepts related to Python development, defensive cybersecurity, password security, pattern detection, secure random generation, and automated testing.

## Features

The analyzer evaluates several characteristics of a password:

- Length and character composition
- Uppercase and lowercase characters
- Numbers and symbols
- Common weak patterns
- Keyboard patterns
- Sequential characters
- Repeated characters
- Predictable leetspeak substitutions
- Common-password matches
- Dictionary-based constructions
- Theoretical entropy
- Estimated brute-force search time

The program also generates security recommendations according to the weaknesses detected.

## Pattern Detection

Password Security Analysis Engine identifies several types of predictable constructions.

### Weak Patterns

Examples:

```text
password
admin
welcome
123456
abc123
```

### Keyboard Patterns

Examples:

```text
qwerty
asdf
zxcv
qaz
wsx
```

### Sequential Characters

Both forward and reverse sequences can be detected.

Examples:

```text
abc
cba
123
321
```

### Repeated Characters

Examples:

```text
aaa
111
!!!
```

## Leetspeak Detection

Predictable character substitutions are also analyzed.

Examples:

```text
P@ssw0rd
Adm1n
```

The normalization system recognizes substitutions including:

```text
0 -> o
1 -> i
3 -> e
4 -> a
5 -> s
7 -> t
@ -> a
$ -> s
```

The analyzer attempts to distinguish actual substitutions from ordinary words to reduce duplicate detections.

## Common Password Detection

Passwords are compared against a local dataset stored in:

```text
common_passwords.txt
```

Matching is case-insensitive.

A direct match with the common-password list is treated as a significant security weakness regardless of the apparent complexity of the password.

## Dictionary-Based Detection

The analyzer also attempts to recognize passwords constructed from common words followed by predictable numbers or symbols.

Examples:

```text
Princess2026!
M0nkey2026!
P@ssw0rd2026!
```

This allows the engine to identify passwords that contain multiple character types but remain based on predictable words.

The detection method also avoids relying only on substring matching, helping reduce false positives.

## Explainable Security Score

Passwords receive a security score between:

```text
0 and 100
```

The final result is calculated in multiple stages:

```text
Password
   |
   v
Base Score
   |
   v
Security Penalties
   |
   v
Score Before Caps
   |
   v
Security Caps
   |
   v
Final Score
```

### Base Score

The base score considers:

- Password length
- Uppercase characters
- Lowercase characters
- Numbers
- Symbols
- Additional length for passwords with 16 or more characters

### Security Penalties

Points may be removed when the analyzer detects:

- Predictable password patterns
- Repeated characters
- Sequential characters
- Keyboard patterns
- Predictable leetspeak substitutions

### Security Caps

Some weaknesses limit the maximum possible final score.

A password found directly in the common-password dataset has a maximum score of:

```text
20 / 100
```

A password based on a recognized dictionary word has a maximum score of:

```text
50 / 100
```

These limits prevent predictable passwords from receiving high security scores simply because they are long or contain several character types.

## Password Classification

| Score | Classification |
| ---: | --- |
| 80-100 | VERY STRONG |
| 60-79 | STRONG |
| 40-59 | MEDIUM |
| 0-39 | WEAK |

## Score Breakdown

The scoring system exposes the individual stages used to calculate the final result.

Example:

```python
{
    "base_score": 90,
    "penalties": 15,
    "score_before_caps": 75,
    "applied_cap": 50,
    "final_score": 50
}
```

This makes the result easier to inspect and understand instead of returning only an unexplained strength classification.

## Theoretical Entropy

The engine calculates theoretical password entropy using:

```text
Entropy = Password Length x log2(Character Pool Size)
```

The estimated character pool depends on the character classes present in the password:

- Lowercase letters
- Uppercase letters
- Numbers
- Symbols

Entropy is expressed in bits.

### Entropy Limitation

This calculation represents theoretical search-space entropy and should not be interpreted as the actual randomness of a human-generated password.

For example:

```text
Password123456!
```

may have a relatively large theoretical character space while remaining highly predictable.

For this reason, theoretical entropy is presented separately from the practical security score.

## Theoretical Brute-Force Estimate

The program estimates brute-force search time using an assumed attack rate of:

```text
10,000,000,000 guesses per second
```

The result can be displayed in:

```text
seconds
minutes
hours
days
years
thousand years
million years
billion years
> 1 trillion years
```

The estimate is theoretical and does not represent how long a real attacker would necessarily require.

Real-world password attacks may use techniques such as:

- Dictionary attacks
- Rule-based cracking
- Leaked credential databases
- Password reuse
- Credential stuffing
- Targeted guessing
- Optimized cracking hardware

## Secure Password Generator

Password Security Analysis Engine includes a password generator based on Python's `secrets` module.

The `secrets` module is designed for generating cryptographically strong random values suitable for security-sensitive applications.

Generated passwords contain at least:

- One uppercase letter
- One lowercase letter
- One number
- One symbol

The minimum generated password length is:

```text
12 characters
```

Generated passwords are analyzed by the same security engine before being accepted.

A generated candidate must:

- Score at least 80
- Contain no detected weak pattern
- Contain no keyboard pattern
- Contain no detected leetspeak weakness
- Not appear in the common-password dataset
- Contain no detected dictionary base
- Contain no repeated-character weakness
- Contain no sequential-character weakness

## Security Recommendations

The program generates recommendations based on detected weaknesses.

Examples:

```text
Use at least 12 characters
Add at least one uppercase letter
Add at least one lowercase letter
Add at least one number
Add at least one symbol
Avoid keyboard patterns such as qwerty, asdf or zxcv
Avoid sequential characters such as abc, cba, 123 or 321
Avoid predictable substitutions such as @ for a, 0 for o, or 3 for e
Do not use passwords found in common password lists
Avoid building passwords from common words with predictable numbers or symbols
```

## Command-Line Interface

Run the application with:

```bash
python main.py
```

The main menu is displayed as:

```text
========================================
   PASSWORD SECURITY ANALYSIS ENGINE
========================================

1 - Analyze a password
2 - Generate a secure password
3 - Exit
```

Password input is masked in supported Python environments so the entered password is not directly displayed on screen.

## Security Report

After analyzing a password, the program produces a structured report containing:

```text
PASSWORD OVERVIEW
CHARACTER COMPOSITION
SECURITY CHECKS
SECURITY ISSUES
SCORE BREAKDOWN
THEORETICAL ENTROPY
THEORETICAL BRUTE-FORCE ESTIMATE
RECOMMENDATIONS
```

Example:

```text
========================================
   PASSWORD SECURITY ANALYSIS ENGINE
              SECURITY REPORT
========================================

PASSWORD OVERVIEW
  Length: 13 characters
  Strength: MEDIUM
  Final score: 50 / 100

SECURITY ISSUES
  - [-15] Predictable leetspeak substitution detected
  - [CAP 50] Password is based on a common dictionary word

SCORE BREAKDOWN
  Base score: 90 / 100
  Penalties: -15
  Score before caps: 75
  Security cap: 50
  Final score: 50 / 100
```

Actual results depend on the analyzed password and the current common-password dataset.

## Project Structure

```text
password-security-analysis-engine/
|
|-- analyzer.py
|-- main.py
|-- test_analyzer.py
|-- common_passwords.txt
|-- requirements.txt
|-- README.md
`-- .gitignore
```

### analyzer.py

Contains the core analysis engine, including:

- Character analysis
- Pattern detection
- Dictionary analysis
- Scoring logic
- Entropy calculation
- Brute-force estimation
- Security recommendations
- Secure password generation

### main.py

Provides the command-line interface and displays analysis results.

### test_analyzer.py

Contains the automated test suite built with `pytest`.

### common_passwords.txt

Contains the local dataset used for common-password and dictionary-based detection.

## Installation

Clone the repository:

```bash
git clone https://github.com/looarmusic-code/password-security-analysis-engine.git
```

Enter the project directory:

```bash
cd password-security-analysis-engine
```

Create a virtual environment.

### Windows

```powershell
python -m venv .venv
.venv\Scripts\activate
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install the dependencies:

```bash
python -m pip install -r requirements.txt
```

## Usage

Start the application:

```bash
python main.py
```

Then choose one of the available options:

```text
1 - Analyze a password
2 - Generate a secure password
3 - Exit
```

## Automated Tests

The project uses `pytest` for automated testing.

Run the complete test suite with:

```bash
python -m pytest -v
```

The tests cover:

- Character analysis
- Weak pattern detection
- Repetition detection
- Forward and reverse sequences
- Keyboard patterns
- Leetspeak normalization and detection
- Common-password detection
- Dictionary-based detection
- False-positive scenarios
- Entropy calculation
- Brute-force estimate formatting
- Base score calculation
- Security penalties
- Security caps
- Score breakdown
- Password classification
- Recommendations
- Secure password generation

## Architecture

The project separates the analysis engine from the command-line interface.

```text
                 User
                   |
                   v
               main.py
                   |
                   v
              analyzer.py
                   |
       +-----------+-----------+
       |           |           |
       v           v           v
    Pattern     Dictionary   Character
    Detection    Analysis     Analysis
       |           |           |
       +-----------+-----------+
                   |
                   v
            Security Scoring
                   |
          +--------+--------+
          |                 |
          v                 v
       Entropy       Recommendations
          |                 |
          +--------+--------+
                   |
                   v
             Security Report
```

Separating the analysis logic from the command-line interface makes individual components easier to test, maintain, and extend.

## Security Design

### Local Analysis

Password analysis is performed locally.

The program does not intentionally transmit analyzed passwords to an external service.

### Secure Random Generation

Password generation uses Python's `secrets` module instead of a general-purpose pseudo-random generator.

### Explainable Results

The scoring engine exposes:

```text
Base Score
Penalties
Score Before Caps
Security Caps
Final Score
```

rather than producing only an unexplained security classification.

### Layered Analysis

Password security is not evaluated solely through length or character complexity.

Multiple indicators of predictability are analyzed independently.

## Limitations

Password Security Analysis Engine is an educational cybersecurity project and is not intended to replace professional password auditing or password-cracking frameworks.

Current limitations include:

- The common-password dataset is relatively small
- Dictionary analysis is intentionally simplified
- Entropy calculations are theoretical
- Brute-force estimates depend on an assumed attack rate
- Contextual information about the password owner is not analyzed
- Breached-password databases are not currently queried
- Advanced probabilistic password models are not implemented
- Security scores are heuristic and do not guarantee password security

## Future Improvements

Possible future improvements include:

- Have I Been Pwned Pwned Passwords integration using k-anonymity
- Larger common-password datasets
- Improved dictionary analysis
- Configurable password policies
- JSON report output
- Command-line arguments
- Password strength visualization
- Additional keyboard-layout detection
- Unicode-aware analysis
- GitHub Actions continuous integration
- Python package distribution

## Technologies

- Python 3
- secrets
- math
- string
- pathlib
- getpass
- pytest

## Educational Purpose

Password Security Analysis Engine was developed as a practical Python and cybersecurity portfolio project.

The project explores concepts related to defensive security, password security, secure coding, pattern recognition, security heuristics, modular Python development, automated testing, and explainable security analysis.

## Disclaimer

Password strength cannot be determined perfectly from a single score.

The results generated by Password Security Analysis Engine are heuristic and intended for educational purposes.

Real-world password security depends on additional factors such as password uniqueness, credential breaches, password hashing algorithms, authentication architecture, rate limiting, multi-factor authentication, and attacker capabilities.

Do not enter real sensitive credentials when running software in an environment you do not trust.

## Author

Developed by Looar (Raul) as a Python and cybersecurity portfolio project.
