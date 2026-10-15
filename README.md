Advanced Log Analyzer

Advanced Log Analyzer is a Python-based cybersecurity tool that analyzes system and application logs to identify suspicious activity, authentication attacks, security events, and operational anomalies.

It automatically classifies events, correlates repeated authentication failures, detects threat indicators, and generates structured TXT and CSV security reports for further investigation.

Features

Authentication failure detection

Repeated failed login correlation

Brute-force attack identification

Security event classification

Detection of suspicious commands and attack indicators

Detection of encoded PowerShell commands

Detection of Base64 obfuscation attempts

Detection of suspicious curl | bash and wget | bash execution

Windows Event ID 4625 monitoring

IP address and user correlation

Security severity assessment

TXT security report generation

CSV report export

Command-line interface (CLI)

Cross-platform support (Linux, Windows, macOS)

Fully self-contained, no external services required

Detection Categories
Authentication Events
Failed passwords
Login failures
Invalid users
Authentication errors
Brute-force attacks
Suspicious Activity
Mimikatz indicators
Meterpreter indicators
Encoded PowerShell commands
Base64 encoded payloads
Suspicious remote script execution
Security Events
Access denied events
Permission violations
Firewall-related events
Security warnings
Authentication activity
Network Events
TCP activity
UDP activity
DNS events
HTTP events
Connection monitoring
Technologies

Python

Regular Expressions (Regex)

Dataclasses

Argparse

CSV Processing

Threat Detection

Security Log Analysis

Event Correlation

Example Usage
Shell
python analyzer.py auth.log
Shell
python analyzer.py auth.log security.log
Shell
python analyzer.py auth.log --failed-login-threshold 3
Output
log_analysis_report.txt
log_analysis_report.csv
Future Improvements

JSON report export

HTML dashboard reports

Real-time monitoring

MITRE ATT&CK mapping

SIEM integration

Docker support

Web dashboard

Author

Sviatoslav Volovnyk

GitHub: github.com/volovnyk
