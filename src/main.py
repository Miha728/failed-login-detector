import logging
import pandas as pd
import config
from data_loader import load_data, validate_data
from detectors import detect_all_alerts


logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL),
    format=config.LOG_FORMAT
)

logger = logging.getLogger(__name__)


def save_alerts(alerts, output_file):
    alerts_df = pd.DataFrame(alerts)

    if alerts_df.empty:
        alerts_df = pd.DataFrame(columns=[
            "rule_name",
            "entity_type",
            "entity_value",
            "window_start",
            "window_end",
            "failed_attempts",
            "unique_users_targeted",
            "country",
            "hostname",
            "risk_score",
            "severity",
            "reason",
        ])

    alerts_df.to_csv(output_file, index=False)
    logger.info("Alerts saved to %s", output_file)
    return alerts_df


def print_summary(df, alerts_df):
    print("\n=== SUMMARY ===")
    print(f"Total log events: {len(df)}")
    print(f"Failed logins: {(df['status'] == 'FAILED').sum()}")
    print(f"Alerts generated: {len(alerts_df)}")

    if not alerts_df.empty:
        print("\n=== ALERTS ===")
        for _, row in alerts_df.iterrows():
            print(
                f"[{row['severity']}] {row['rule_name']} | "
                f"{row['entity_type']}={row['entity_value']} | "
                f"score={row['risk_score']} | "
                f"failed={row['failed_attempts']} | "
                f"reason={row['reason']}"
            )


def main():
    logger.info("Starting Failed Login Detector")

    df = load_data(config.INPUT_FILE)
    df = validate_data(df)

    alerts = detect_all_alerts(df)
    alerts_df = save_alerts(alerts, config.OUTPUT_FILE)

    print_summary(df, alerts_df)

    logger.info("Detection process finished successfully")


if __name__ == "__main__":
    main()