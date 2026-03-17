import pandas as pd
import config


def load_data(file_path):
    df = pd.read_csv(file_path)
    return df


def detect_suspicious_ips(df, threshold=5, window_minutes=5):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    failed_df = df[df["status"] == "FAILED"]

    alerts = []

    for ip in failed_df["ip_address"].unique():
        ip_data = failed_df[failed_df["ip_address"] == ip].sort_values("timestamp")

        for i in range(len(ip_data)):
            start_time = ip_data.iloc[i]["timestamp"]
            end_time = start_time + pd.Timedelta(minutes=window_minutes)

            window = ip_data[
                (ip_data["timestamp"] >= start_time)
                & (ip_data["timestamp"] <= end_time)
            ]

            if len(window) >= threshold:
                alerts.append({
                    "type": "IP",
                    "value": ip,
                    "failed_attempts": len(window)
                })
                break

    return alerts


def detect_suspicious_users(df, threshold=5, window_minutes=5):
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    failed_df = df[df["status"] == "FAILED"]

    alerts = []

    for user in failed_df["username"].unique():
        user_data = failed_df[failed_df["username"] == user].sort_values("timestamp")

        for i in range(len(user_data)):
            start_time = user_data.iloc[i]["timestamp"]
            end_time = start_time + pd.Timedelta(minutes=window_minutes)

            window = user_data[
                (user_data["timestamp"] >= start_time)
                & (user_data["timestamp"] <= end_time)
            ]

            if len(window) >= threshold:
                alerts.append({
                    "type": "USER",
                    "value": user,
                    "failed_attempts": len(window)
                })
                break

    return alerts


def main():
    file_path = "data/sample_logs.csv"

    df = load_data(file_path)

    print("=== DATA PREVIEW ===")
    print(df.head())

    ip_alerts = detect_suspicious_ips(
        df,
        threshold=config.FAILED_THRESHOLD,
        window_minutes=config.TIME_WINDOW_MINUTES
    )

    user_alerts = detect_suspicious_users(
        df,
        threshold=config.FAILED_THRESHOLD,
        window_minutes=config.TIME_WINDOW_MINUTES
    )

    all_alerts = ip_alerts + user_alerts

    print("\n=== ALERTS ===")
    for alert in all_alerts:
        print(f"[ALERT] {alert['type']} {alert['value']} → {alert['failed_attempts']} failed attempts")

    alerts_df = pd.DataFrame(all_alerts)
    alerts_df.to_csv("data/alerts.csv", index=False)

    print("\nAlerts saved to data/alerts.csv")


if __name__ == "__main__":
    main()