# Failed Login Detector

## About the Project

This project analyzes authentication logs and detects suspicious login activity that may indicate brute-force attacks or account abuse.

The goal was to simulate a simplified security monitoring system that can identify abnormal behavior based on failed login patterns.

Instead of using machine learning, the system relies on clear, explainable rules and produces structured alerts with a risk score and severity level.

---

## What This Project Detects

The system identifies several types of suspicious behavior:

- Multiple failed login attempts from the same IP (possible brute-force attack)
- Repeated failed attempts targeting the same user account
- Password spraying (one IP trying many different usernames)
- Attacks against privileged accounts such as `admin` or `root`

---

## How It Works

1. Reads authentication logs from a CSV file  
2. Filters failed login attempts  
3. Groups activity by IP and username  
4. Applies detection rules within a time window (e.g. 5 minutes)  
5. Assigns a risk score to each alert  
6. Classifies alerts as `LOW`, `MEDIUM`, or `HIGH` severity  
7. Saves results to a structured output file  

---

## Example Alert
[HIGH] PASSWORD_SPRAYING | IP=203.0.113.50 | score=100 | failed=8


---

## Why This Project Matters

This project demonstrates how simple log analysis can be used to detect suspicious behavior without complex tools.

It focuses on:
- understanding patterns in authentication data
- building explainable detection logic
- structuring a small but realistic security workflow

---

## Project Structure
failed-login-detector/
│
├── data/
│ └── sample_logs.csv
│
├── src/
│ ├── config.py
│ ├── data_loader.py
│ ├── detectors.py
│ └── main.py
│
├── README.md
└── requirements.txt

---

## Configuration

Detection thresholds are configurable in `config.py`.

Example:
```python
TIME_WINDOW_MINUTES = 5
FAILED_THRESHOLD_IP = 5
FAILED_THRESHOLD_USER = 5
