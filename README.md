🛡️ Advanced Phishing & Malicious Link Analyzer

A lightweight cybersecurity tool that helps users identify potentially phishing or malicious links and filenames *before clicking them*.

This project uses heuristic-based analysis to detect common phishing and malware patterns and presents the results through an interactive dashboard.

---

## 🔍 What This Tool Does

- Scans URLs for phishing indicators like:
  - URL shorteners
  - Suspicious keywords (login, verify, secure, etc.)
  - IP-based URLs and unusual domain structures
- Analyzes filenames for malware patterns such as:
  - Dangerous extensions (.exe, .js, .scr, etc.)
  - Double extensions (example: invoice.pdf.exe)
- Assigns a **risk score (0–100)** and classifies it as:
  - 🟢 LOW
  - 🟡 MEDIUM
  - 🔴 HIGH
- Clearly explains *why* a link or file was flagged
- Maintains a session-based scan history

⚠️ This is a **demo and learning project**, not a replacement for enterprise security tools.

---

## 🧠 Why Phishing Detection Matters

Phishing is one of the most common attack vectors used to steal credentials, spread malware, and compromise systems.  
Many attacks rely on deceptive URLs and filenames that look legitimate at first glance.

This project demonstrates how basic detection logic can significantly improve user awareness.

---

## 🛠️ Tech Stack

- Python
- Streamlit
- Regular Expressions (Regex)
- Heuristic Scoring Logic

---

## ▶️ How to Run

1. Clone the repository
   ```bash
   git clone https://github.com/Aishwaryeahh-cy/Advanced-Phishing-Malicious-Link-Analyzer.git
   cd Advanced-Phishing-Malicious-Link-Analyzer
