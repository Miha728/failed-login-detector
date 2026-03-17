# Failed Login Detector

## Overview

This project implements a rule-based detection system for identifying suspicious authentication activity in log data. It focuses on detecting patterns consistent with brute-force attacks, such as multiple failed login attempts within a short time window.

The system processes structured log data and generates alerts based on configurable thresholds, simulating a simplified security monitoring workflow.

---

## Key Features

* Detection of suspicious IP addresses generating multiple failed login attempts
* Detection of targeted user accounts under potential attack
* Time-window based analysis (e.g. repeated failures within a defined interval)
* Configurable detection parameters via `config.py`
* Alert generation in both terminal output and structured CSV format

---

## Detection Logic

The system applies rule-based analysis on authentication logs:

* Aggregates failed login attempts
* Groups events by IP address and username
* Applies time-window constraints
* Flags entities exceeding defined thresholds

**Example rule:**

> ≥ 5 failed login attempts within 5 minutes → flagged as suspicious

---

## Project Structure

```
failed-login-detector/
│
├── data/
│   ├── sample_logs.csv        # Input dataset (simulated logs)
│   └── alerts.csv             # Generated alerts
│
├── src/
│   ├── main.py                # Core logic and execution
│   └── config.py              # Detection parameters
│
├── README.md
├── requirements.txt
```

---

## Example Output

```
[ALERT] IP 192.168.1.30 → 8 failed attempts
[ALERT] USER user1 → 8 failed attempts
```

---

## Configuration

Detection behavior is controlled via `config.py`:

```python
FAILED_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
```

These values define the sensitivity of the detection rules and can be adjusted without modifying the core logic.

---

## How to Run

```
python src/main.py
```

---

## Technical Notes

* The project uses **pandas** for data processing and time-based filtering
* Input data is simulated but structured to resemble real authentication logs
* The detection approach is deterministic (rule-based), not machine learning-based

---

## Use Case

This project demonstrates how log analysis can be used to identify suspicious authentication behavior and simulate a basic intrusion detection mechanism.

---

## Future Improvements

* Real-time log ingestion and monitoring
* Integration with alerting systems (e.g. email, Slack)
* Visualization of attack patterns
* Extension to anomaly detection techniques
