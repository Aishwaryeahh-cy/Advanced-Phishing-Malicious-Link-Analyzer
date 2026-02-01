# Advanced Phishing & Malicious Link Analyzer

## Overview
This tool is a lightweight security scanner designed to detect common phishing and malware indicators in URLs and filenames. It uses heuristic analysis and regex patterns to assign a risk score, helping users decide whether a link or file is safe to interact with.

## Why Phishing Is Dangerous
Phishing is a method where attackers trick you into revealing sensitive info (passwords, credit cards) by pretending to be a trusted entity. Malicious links can also lead to malware downloads that infect your system.

## Features
- **URL Static Analysis**: Checks for suspicious keywords, TLDs, and IP-based links.
- **File Analysis**: Detects dangerous extensions and "double-extension" tricks.
- **Threat Scoring**: Provides a 0-100 score with LOW, MEDIUM, or HIGH risk ratings.
- **Scan History**: Keeps track of your recent scans in a session-based table.

## Tech Stack
- **Language**: Python 3.x
- **UI Framework**: Streamlit
- **Data Handling**: Pandas
- **Logic**: Regular Expressions (re)

## How to Run
1. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
2. Launch the application:
   ```bash
   streamlit run app.py
   ```
3. Open your browser to the local URL provided by Streamlit.
