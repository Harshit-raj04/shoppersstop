import warnings
warnings.filterwarnings("ignore")

import os
import shutil
import kagglehub
import pandas as pd

# Local path inside the project repository
LOCAL_DATA_DIR = "data"
LOCAL_CSV_PATH = os.path.join(LOCAL_DATA_DIR, "transactions.csv")
KAGGLE_DATASET_NAME = "umuttuygurr/e-commerce-fraud-detection-dataset"


def get_dataset_path():
    """
    Ensures the dataset exists locally at 'data/transactions.csv'.
    If not present, downloads it via kagglehub and saves it into the local project folder.
    """
    if os.path.exists(LOCAL_CSV_PATH):
        return LOCAL_CSV_PATH

    print(f"[+] Local dataset not found. Downloading via KaggleHub ({KAGGLE_DATASET_NAME})...")
    os.makedirs(LOCAL_DATA_DIR, exist_ok=True)
    cache_path = kagglehub.dataset_download(KAGGLE_DATASET_NAME)
    source_csv = os.path.join(cache_path, "transactions.csv")

    if os.path.exists(source_csv):
        shutil.copy(source_csv, LOCAL_CSV_PATH)
        print(f"[✅] Merged dataset into local project folder: '{LOCAL_CSV_PATH}'")
        return LOCAL_CSV_PATH
    else:
        raise FileNotFoundError("Failed to locate downloaded transactions.csv file.")


def download_and_inspect_dataset():
    print("=" * 60)
    print("   AI Scam & Fraud Detection - Kaggle Dataset Downloader   ")
    print("=" * 60)

    csv_file_path = get_dataset_path()

    print(f"\n[+] Loading data from local project file '{csv_file_path}'...")
    df = pd.read_csv(csv_file_path)

    print("-" * 60)
    print(" 📊 DATASET OVERVIEW & METRICS:")
    print(f"   • Total Rows (Transactions) : {len(df):,}")
    print(f"   • Total Columns (Features)  : {len(df.columns)}")
    
    if 'is_fraud' in df.columns:
        fraud_count = int(df['is_fraud'].sum())
        legit_count = len(df) - fraud_count
        fraud_pct = (fraud_count / len(df)) * 100
        print(f"   • Fraudulent Transactions   : {fraud_count:,} ({fraud_pct:.2f}%) 🔴")
        print(f"   • Legitimate Transactions   : {legit_count:,} ({100 - fraud_pct:.2f}%) 🟢")

    print("-" * 60)
    print(" 📋 AVAILABLE FEATURE COLUMNS:")
    for idx, col in enumerate(df.columns, 1):
        print(f"   {idx:2d}. {col}")

    print("-" * 60)
    print(" 🔍 FIRST 5 SAMPLE ROWS:")
    print(df.head())
    print("=" * 60 + "\n")


if __name__ == "__main__":
    download_and_inspect_dataset()
