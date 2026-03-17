import logging
import pandas as pd
import config

logger = logging.getLogger(__name__)


def calculate_severity(score):
    if score >= config.SEVERITY_THRESHOLDS["HIGH"]:
        return "HIGH"
    if score >= config.SEVERITY_THRESHOLDS["MEDIUM"]:
        return "MEDIUM"
    return "LOW"


def build_risk_score(rule_name, failed_attempts, unique_users=0, is_admin=False):
    score = config.RISK_POINTS[rule_name]
    score += max(0, failed_attempts - 1) * config.EXTRA_POINTS_PER_FAILED
    score += unique_users * config.EXTRA_POINTS_PER_UNIQUE_USER

    if is_admin:
        score += 10

    return min(score, 100)


def get_best_failed_window(group_df, window_minutes):
    best_window = None
    best_count = 0

    group_df = group_df.sort_values("timestamp").reset_index(drop=True)

    for i in range(len(group_df)):
        start_time = group_df.iloc[i]["timestamp"]
        end_time = start_time + pd.Timedelta(minutes=window_minutes)

        window = group_df[
            (group_df["timestamp"] >= start_time) &
            (group_df["timestamp"] <= end_time)
        ]

        if len(window) > best_count:
            best_count = len(window)
            best_window = window.copy()

    return best_window, best_count


def detect_brute_force_ip(failed_df):
    alerts = []

    for ip, group in failed_df.groupby("ip_address"):
        best_window, failed_count = get_best_failed_window(group, config.TIME_WINDOW_MINUTES)

        if failed_count >= config.FAILED_THRESHOLD_IP:
            unique_users = best_window["username"].nunique()
            score = build_risk_score(
                "BRUTE_FORCE_IP",
                failed_attempts=failed_count,
                unique_users=unique_users
            )

            alerts.append({
                "rule_name": "BRUTE_FORCE_IP",
                "entity_type": "IP",
                "entity_value": ip,
                "window_start": best_window["timestamp"].min(),
                "window_end": best_window["timestamp"].max(),
                "failed_attempts": failed_count,
                "unique_users_targeted": unique_users,
                "country": best_window["country"].mode().iloc[0],
                "hostname": best_window["hostname"].mode().iloc[0],
                "risk_score": score,
                "severity": calculate_severity(score),
                "reason": f"IP {ip} generated {failed_count} failed logins within {config.TIME_WINDOW_MINUTES} minutes."
            })

    return alerts


def detect_brute_force_user(failed_df):
    alerts = []

    for user, group in failed_df.groupby("username"):
        best_window, failed_count = get_best_failed_window(group, config.TIME_WINDOW_MINUTES)

        if failed_count >= config.FAILED_THRESHOLD_USER:
            source_ips = best_window["ip_address"].nunique()
            is_admin = user.lower() in config.ADMIN_USERNAMES
            score = build_risk_score(
                "BRUTE_FORCE_USER",
                failed_attempts=failed_count,
                unique_users=0,
                is_admin=is_admin
            )

            alerts.append({
                "rule_name": "BRUTE_FORCE_USER",
                "entity_type": "USER",
                "entity_value": user,
                "window_start": best_window["timestamp"].min(),
                "window_end": best_window["timestamp"].max(),
                "failed_attempts": failed_count,
                "unique_users_targeted": source_ips,
                "country": "-",
                "hostname": best_window["hostname"].mode().iloc[0],
                "risk_score": score,
                "severity": calculate_severity(score),
                "reason": f"User {user} received {failed_count} failed login attempts within {config.TIME_WINDOW_MINUTES} minutes."
            })

    return alerts


def detect_password_spraying(failed_df):
    alerts = []

    for ip, group in failed_df.groupby("ip_address"):
        best_window, failed_count = get_best_failed_window(group, config.TIME_WINDOW_MINUTES)

        if best_window is None:
            continue

        unique_users = best_window["username"].nunique()

        if unique_users >= config.UNIQUE_USERS_PER_IP_THRESHOLD:
            score = build_risk_score(
                "PASSWORD_SPRAYING",
                failed_attempts=failed_count,
                unique_users=unique_users
            )

            alerts.append({
                "rule_name": "PASSWORD_SPRAYING",
                "entity_type": "IP",
                "entity_value": ip,
                "window_start": best_window["timestamp"].min(),
                "window_end": best_window["timestamp"].max(),
                "failed_attempts": failed_count,
                "unique_users_targeted": unique_users,
                "country": best_window["country"].mode().iloc[0],
                "hostname": best_window["hostname"].mode().iloc[0],
                "risk_score": score,
                "severity": calculate_severity(score),
                "reason": f"IP {ip} targeted {unique_users} different users within {config.TIME_WINDOW_MINUTES} minutes."
            })

    return alerts


def detect_admin_targeting(failed_df):
    alerts = []

    admin_df = failed_df[failed_df["username"].str.lower().isin(config.ADMIN_USERNAMES)]

    for user, group in admin_df.groupby("username"):
        best_window, failed_count = get_best_failed_window(group, config.TIME_WINDOW_MINUTES)

        if failed_count >= config.FAILED_THRESHOLD_ADMIN:
            source_ips = best_window["ip_address"].nunique()
            score = build_risk_score(
                "ADMIN_TARGETING",
                failed_attempts=failed_count,
                unique_users=source_ips,
                is_admin=True
            )

            alerts.append({
                "rule_name": "ADMIN_TARGETING",
                "entity_type": "USER",
                "entity_value": user,
                "window_start": best_window["timestamp"].min(),
                "window_end": best_window["timestamp"].max(),
                "failed_attempts": failed_count,
                "unique_users_targeted": source_ips,
                "country": "-",
                "hostname": best_window["hostname"].mode().iloc[0],
                "risk_score": score,
                "severity": calculate_severity(score),
                "reason": f"Privileged account {user} was targeted with {failed_count} failed attempts."
            })

    return alerts


def detect_all_alerts(df):
    failed_df = df[df["status"] == "FAILED"].copy()

    logger.info("Failed login events: %s", len(failed_df))

    alerts = []
    alerts.extend(detect_brute_force_ip(failed_df))
    alerts.extend(detect_brute_force_user(failed_df))
    alerts.extend(detect_password_spraying(failed_df))
    alerts.extend(detect_admin_targeting(failed_df))

    logger.info("Generated %s alerts", len(alerts))
    return alerts