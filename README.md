# Failed Login Detector

## Overview

This project analyzes authentication logs and detects suspicious login activity, such as multiple failed login attempts within a short time window.

It simulates a basic security monitoring system used to identify potential brute-force attacks.

---

## Features

* Detects suspicious IP addresses based on failed login attempts
* Detects suspicious user accounts under attack
* Time-based detection (e.g. multiple failures within 5 minutes)
* Configurable thresholds via `config.py`
* Outputs alerts to both terminal and CSV file

---

## Project Structure

```
failed-login-detector/
│
├── data/
│   ├── sample_logs.csv
│   └── alerts.csv
│
├── src/
│   ├── main.py
│   └── config.py
│
├── README.md
├── requirements.txt
```

---

## How It Works

1. The system reads authentication logs from a CSV file
2. Filters failed login attempts
3. Groups activity by IP and username
4. Applies detection rules:

   * X failed attempts within Y minutes → alert
5. Outputs detected alerts

---

## Example Detection Rule

* 5 failed login attempts within 5 minutes → flagged as suspicious

---

## Example Output

```
[ALERT] IP 192.168.1.30 → 8 failed attempts
[ALERT] USER user1 → 8 failed attempts
```

---

## Configuration

You can adjust detection sensitivity in `config.py`:

```python
FAILED_THRESHOLD = 5
TIME_WINDOW_MINUTES = 5
```

---

## Requirements

* Python 3.x
* pandas

Install dependencies:

```
pip install pandas
```

---

## How to Run

```
python src/main.py
```

---

## Use Case

This project simulates a simplified intrusion detection mechanism and demonstrates how log analysis can be used to identify suspicious authentication patterns.

---

## Future Improvements

* Real-time log monitoring
* Integration with alerting systems (email, Slack)
* Visualization dashboard
* Machine learning-based anomaly detection
