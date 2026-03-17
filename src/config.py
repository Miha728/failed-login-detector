INPUT_FILE = "data/sample_logs.csv"
OUTPUT_FILE = "data/alerts.csv"

REQUIRED_COLUMNS = [
    "timestamp",
    "username",
    "ip_address",
    "status",
    "source_port",
    "country",
    "hostname",
    "auth_method",
    "log_type",
]

TIME_WINDOW_MINUTES = 5

FAILED_THRESHOLD_IP = 5
FAILED_THRESHOLD_USER = 5
UNIQUE_USERS_PER_IP_THRESHOLD = 5
FAILED_THRESHOLD_ADMIN = 4

ADMIN_USERNAMES = {"admin", "root", "administrator", "sysadmin"}

RISK_POINTS = {
    "BRUTE_FORCE_IP": 40,
    "BRUTE_FORCE_USER": 35,
    "PASSWORD_SPRAYING": 55,
    "ADMIN_TARGETING": 60,
}

EXTRA_POINTS_PER_FAILED = 3
EXTRA_POINTS_PER_UNIQUE_USER = 5

SEVERITY_THRESHOLDS = {
    "HIGH": 80,
    "MEDIUM": 50,
}

LOG_LEVEL = "INFO"
LOG_FORMAT = "%(asctime)s | %(levelname)s | %(message)s"