import logging
import pandas as pd
import config

logger = logging.getLogger(__name__)


def load_data(file_path):
    df = pd.read_csv(file_path)
    logger.info("Loaded %s rows from %s", len(df), file_path)
    return df


def validate_data(df):
    missing_columns = [col for col in config.REQUIRED_COLUMNS if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")

    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    if df["timestamp"].isna().any():
        raise ValueError("Invalid timestamp values found in input data.")

    logger.info("Input data validation passed")
    return df