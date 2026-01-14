
# Python Security Log Analyzer

## Description
A Python tool that parses authentication logs and flags suspicious activity (e.g., repeated failed logins, noisy IPs). Built to practice security-focused scripting and basic log analysis.

## Features
- Counts failed login attempts
- Identifies top offending IP addresses
- Outputs a summary report (terminal)

## Tech
- Python 3
- Git/GitHub

## How to Run
1. Clone the repo
2. Add a log file to the project folder (example: `auth.log`)
3. Run:
   ```bash
   python analyzer.py sample_auth.log

