"""
AI Scam & Fraud Detection Platform - Multi-Model Trainer & Benchmark Suite
Author: AI & Python Development Team
Description: Trains and compares machine learning algorithms side-by-side on
             data/transactions.csv (Random Forest, LightGBM, XGBoost, Decision Tree, Logistic Regression),
             evaluates metrics, and saves the best model.
"""

import warnings
warnings.filterwarnings("ignore")

import os
import datetime
from typing import Dict, Any, List, Tuple
import pandas as pd
import numpy as np
import joblib

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score

try:
    import lightgbm as lgb
    HAS_LIGHTGBM = True
except ImportError:
    HAS_LIGHTGBM = False

try:
    import xgboost as xgb
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False

from download_dataset import get_dataset_path
import ai_fraud_classifier

MODEL_FILE = "fraud_detection_model.joblib"


def train_and_benchmark_all_models(sample_size: int = None) -> Tuple[Any, List[str], List[Dict[str, Any]]]:
    """
    Trains and benchmarks multiple AI classification algorithms.
    Returns: (best_model, feature_columns, benchmark_results_list)
    """
    print("\n" + "=" * 70)
    print(" 🤖 MULTI-MODEL AI FRAUD BENCHMARK & DATASET TRAINER 🤖 ")
    print("=" * 70)

    # Step 1: Load dataset
    df = ai_fraud_classifier.load_dataset()
    if sample_size and len(df) > sample_size:
        print(f"[+] Sampling {sample_size:,} records for fast benchmarking...")
        df = df.sample(n=sample_size, random_state=42)
    print(f"[+] Total transaction records in benchmark: {len(df):,}")

    # Step 2: Preprocess features
    X, y = ai_fraud_classifier.preprocess_data(df)
    print(f"[+] Feature matrix prepared with {X.shape[1]} columns.")

    # Step 3: Train / Test split
    print("[+] Splitting dataset (80% Train, 20% Test)...")
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    # Define algorithms to benchmark
    models = {
        "Random Forest": RandomForestClassifier(n_estimators=100, max_depth=12, random_state=42, n_jobs=-1),
        "Hist Gradient Boosting": HistGradientBoostingClassifier(max_iter=100, random_state=42),
        "Decision Tree": DecisionTreeClassifier(max_depth=10, random_state=42),
        "Logistic Regression": LogisticRegression(max_iter=500, random_state=42)
    }

    if HAS_LIGHTGBM:
        models["LightGBM"] = lgb.LGBMClassifier(n_estimators=100, random_state=42, verbose=-1)

    if HAS_XGBOOST:
        models["XGBoost"] = xgb.XGBClassifier(n_estimators=100, max_depth=6, random_state=42, eval_metric="logloss")

    results = []
    best_model = None
    best_f1 = -1.0
    best_model_name = ""

    print("\n[+] Training models and calculating evaluation metrics...\n")

    for name, model in models.items():
        t0 = datetime.datetime.now()
        try:
            model.fit(X_train, y_train)
            duration = (datetime.datetime.now() - t0).total_seconds()

            y_pred = model.predict(X_test)
            acc = float(accuracy_score(y_test, y_pred) * 100)
            prec = float(precision_score(y_test, y_pred, zero_division=0) * 100)
            rec = float(recall_score(y_test, y_pred, zero_division=0) * 100)
            f1 = float(f1_score(y_test, y_pred, zero_division=0) * 100)

            results.append({
                "name": name,
                "accuracy": round(acc, 2),
                "precision": round(prec, 2),
                "recall": round(rec, 2),
                "f1": round(f1, 2),
                "time": round(duration, 2),
                "model": model
            })

            if f1 > best_f1:
                best_f1 = f1
                best_model = model
                best_model_name = name
        except Exception as e:
            print(f"[-] Skipped {name} due to training error: {e}")

    # Step 4: Display Comparison Table
    print("=" * 70)
    print(" 📊 ALGORITHM PERFORMANCE BENCHMARK COMPARISON TABLE")
    print("=" * 70)
    print(f" {'Algorithm Name':<23} | {'Accuracy':<9} | {'Precision':<9} | {'Recall':<8} | {'F1-Score':<8} | {'Time (s)'}")
    print("-" * 70)

    for r in results:
        winner_tag = " ⭐ (Best)" if r["name"] == best_model_name else ""
        print(f" {r['name']:<23} | {r['accuracy']:6.2f}%   | {r['precision']:6.2f}%   | {r['recall']:5.2f}%   | {r['f1']:5.2f}%   | {r['time']:5.2f}s{winner_tag}")

    print("-" * 70)
    print(f" 🏆 WINNING MODEL : {best_model_name} (F1-Score: {best_f1:.2f}%)")
    print("-" * 70)

    # Step 5: Save best model to disk
    joblib.dump((best_model, X.columns.tolist()), MODEL_FILE)
    print(f"[✅] Best model '{best_model_name}' saved to '{MODEL_FILE}'")
    print("=" * 70 + "\n")

    return best_model, X.columns.tolist(), results


if __name__ == "__main__":
    train_and_benchmark_all_models()
