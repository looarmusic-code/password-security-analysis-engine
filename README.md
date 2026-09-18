Password Security Analyzer

A Python-based password security analysis tool that evaluates password strength using multiple security indicators.

Features

The analyzer evaluates:

- Password length
- Uppercase and lowercase characters
- Numbers and symbols
- Character distribution
- Common weak password patterns
- Repeated characters
- Sequential characters
- Estimated password entropy
- Estimated brute-force cracking time
- Overall security score from 0 to 100

How It Works

The program analyzes the structure of a password and calculates a security score based on its length and character diversity.

It also applies penalties when predictable patterns, repeated characters, or sequential characters are detected.

Password entropy is estimated using the size of the character pool and password length.

The brute-force estimate assumes an attack speed of 10 billion guesses per second. This value is used only as an educational approximation, since real cracking speeds depend on factors such as hashing algorithms, hardware, and attack methods.

Project Structure

password-analyzer/
├── analyzer.py
├── main.py
├── test_analyzer.py
├── README.md
├── requirements.txt
└── .gitignore

"analyzer.py" contains the password analysis logic.

"main.py" provides the command-line interface.

"test_analyzer.py" contains automated tests for the analyzer.

Installation

Clone the repository and enter the project directory.

git clone <repository-url>
cd password-analyzer

Install the dependencies:

pip install -r requirements.txt

Usage

Run:

python main.py

Enter a password when prompted.

Example:

Enter your password: CyberSecurity#2026

--- SECURITY RESULT ---
Score: 100 / 100
Strength: VERY STRONG

--- ENTROPY ---
Estimated entropy: 124.63 bits

Running Tests

Run the automated test suite with:

pytest -v

Security Note

The entropy and brute-force calculations are theoretical estimates. Human-generated passwords may contain predictable words and patterns that make them substantially weaker than their theoretical entropy suggests.

This project combines theoretical entropy with pattern detection and a custom scoring system to provide a broader educational assessment.

Future Improvements

Future versions may include:

- Larger databases of commonly used passwords
- Keyboard-pattern detection
- Improved sequence analysis
- Password recommendations
- Configurable attack speeds
- Command-line arguments
- Web interface

Purpose

This project was developed as a practical study of Python programming and cybersecurity concepts, including password strength, entropy, brute-force attacks, pattern detection, modular programming, and automated testing.