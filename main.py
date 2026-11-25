"""
AI Scam & Fraud Detection Platform - Master Unified Suite
Author: AI & Python Development Team
Description: Unified interactive master platform connecting:
             1. Website Threat Intelligence (SSL, WHOIS Domain Age, DNS MX, Brand Typosquatting)
             2. Merged Local E-Commerce Fraud Dataset (data/transactions.csv)
             3. Multi-Model AI Trainer & Benchmarks (Random Forest, LightGBM, XGBoost, etc.)
             4. Unified Multi-Layer Merged Audit (Combines URL + AI Transaction Risk)
             5. Interactive Streamlit Web Dashboard Launcher
             6. FastAPI REST Microservice Launcher
             7. SQLite Audit History Viewer
             8. Automated HTML Security Audit Report Generator
"""

import os
import sys
import subprocess
import warnings
import pandas as pd

warnings.filterwarnings("ignore")

import scam_detector
import download_dataset
import ai_fraud_classifier
import train_models
import database
import report_generator


def print_header():
    print("\n" + "=" * 70)
    print(" 🛡️  AI SCAM & FRAUD DETECTION PLATFORM - UNIFIED SUITE v2.0 🛡️ ")
    print("=" * 70)


def show_menu():
    print_header()
    print(" Select a platform module to run:")
    print("  [1] 🌐 Run Website Risk Detector (SSL, WHOIS Age, MX Records, Typosquatting)")
    print("  [2] 📥 Inspect Merged E-Commerce Fraud Dataset (data/transactions.csv)")
    print("  [3] 🤖 Train Dataset & Benchmark AI Models (Random Forest, LightGBM, XGBoost)")
    print("  [4] 🔗 Run Merged Multi-Layer Audit (Website URL + AI Transaction Risk)")
    print("  [5] 🖥️ Launch Interactive Web Dashboard (Streamlit)")
    print("  [6] 🚀 Launch REST API Microservice (FastAPI Swagger Docs)")
    print("  [7] 📜 View Persistent Audit History Logs (SQLite)")
    print("  [8] 📄 Generate Standalone HTML Security Audit Report")
    print("  [0] ❌ Exit Platform")
    print("=" * 70)


def run_merged_audit(url=None):
    print("\n" + "=" * 70)
    print(" 🔗 RUNNING MERGED MULTI-LAYER FRAUD DETECTION AUDIT")
    print("=" * 70)

    if not url or not str(url).strip():
        url = input("Enter Website URL to analyze (e.g. shoppersstop.com or http://fake-deal.store): ").strip()

    if not url or not str(url).strip():
        url = "suspicious-store.com"

    print(f"\n[+] Layer 1: Scanning Website Domain & Threat Intelligence...")
    url_res = scam_detector.audit_website(url, save_to_db=True)

    print(f"\n[+] Layer 2: Loading AI Transaction Fraud Model...")
    model, feature_cols = ai_fraud_classifier.get_or_load_model()

    print("\nEnter transaction details for AI Model evaluation (Press Enter to use defaults):")
    amount_str = input(" Transaction Amount in USD [Default: 1450]: ").strip()
    amount = float(amount_str) if amount_str else 1450.0

    account_age_str = input(" Customer Account Age in Days [Default: 3]: ").strip()
    account_age_days = int(account_age_str) if account_age_str else 3

    dist_str = input(" Shipping Distance in km [Default: 1250]: ").strip()
    shipping_dist = float(dist_str) if dist_str else 1250.0

    cvv_input = input(" CVV Security Match? (yes/no) [Default: no]: ").strip().lower()
    cvv_match = 1 if cvv_input == "yes" else 0

    tx_res = ai_fraud_classifier.predict_transaction_detailed(
        model=model,
        feature_columns=feature_cols,
        account_age_days=account_age_days,
        amount=amount,
        avg_amount_user=45.0,
        shipping_distance_km=shipping_dist,
        cvv_match=cvv_match,
        three_ds_flag=0,
        save_to_db=True
    )

    url_score = url_res["risk_score"]
    ai_fraud_prob = tx_res["fraud_probability"]
    unified_risk_score = round((url_score * 0.4) + (ai_fraud_prob * 0.6), 1)

    if unified_risk_score <= 35:
        unified_status = "LOW RISK 🟢 (Safe to proceed)"
    elif unified_risk_score <= 65:
        unified_status = "MEDIUM RISK 🟡 (Proceed with caution)"
    else:
        unified_status = "HIGH FRAUD RISK 🔴 (Immediate Action Required!)"

    # Save to SQLite
    database.log_unified_audit(
        domain=url_res["domain"],
        url_risk_score=url_score,
        ai_fraud_probability=ai_fraud_prob,
        unified_risk_score=unified_risk_score,
        verdict=unified_status
    )

    print("\n" + "=" * 70)
    print("        UNIFIED SCAM & FRAUD DETECTION AUDIT REPORT        ")
    print("=" * 70)
    print(f" Target Domain         : {url_res['domain']}")
    print(f" Website Risk Score    : {url_score} / 100 ({url_res['risk_level']})")
    print(f" AI Fraud Probability  : {ai_fraud_prob:.2f}%")
    print(f" Primary Risk Driver   : {tx_res['primary_risk_driver']}")
    print("-" * 70)
    print(f" 📊 UNIFIED RISK SCORE  : {unified_risk_score} / 100")
    print(f" 🚨 MERGED ASSESSMENT  : {unified_status}")
    print("=" * 70 + "\n")

    gen_report = input("Generate standalone HTML report for this audit? (yes/no) [Default: yes]: ").strip().lower()
    if gen_report != "no":
        html = report_generator.generate_html_security_report(
            domain=url_res["domain"],
            url_audit=url_res,
            tx_audit=tx_res,
            unified_risk_score=unified_risk_score,
            unified_status=unified_status
        )
        report_path = f"audit_report_{url_res['domain'].replace('.', '_')}.html"
        report_generator.save_report_to_file(html, report_path)
        print(f"[✅] HTML Security Audit Report saved to '{report_path}'. Open in any browser to view or print as PDF!\n")


def view_history():
    print("\n" + "=" * 70)
    print(" 📜 PERSISTENT AUDIT HISTORY (SQLITE DATABASE)")
    print("=" * 70)
    recent = database.get_recent_audits(limit=10)

    print("\n--- Recent Unified Audits ---")
    if recent["unified_audits"]:
        u_df = pd.DataFrame(recent["unified_audits"])
        print(u_df[["id", "timestamp", "domain", "unified_risk_score", "verdict"]].to_string(index=False))
    else:
        print("No unified audits recorded yet.")

    print("\n--- Recent Website URL Audits ---")
    if recent["url_audits"]:
        url_df = pd.DataFrame(recent["url_audits"])
        print(url_df[["id", "timestamp", "domain", "risk_score", "risk_level"]].to_string(index=False))
    else:
        print("No URL audits recorded yet.")

    print("=" * 70 + "\n")


def launch_web_dashboard():
    print("\n[+] Launching Streamlit Web Dashboard...")
    print("[+] Opening at http://localhost:8501 (Press Ctrl+C to stop)...")
    try:
        subprocess.run(["streamlit", "run", "app.py"])
    except KeyboardInterrupt:
        print("\n[+] Web dashboard stopped.")


def launch_api():
    print("\n[+] Launching FastAPI REST Microservice...")
    print("[+] API running at http://127.0.0.1:8000")
    print("[+] Interactive Swagger documentation at http://127.0.0.1:8000/docs")
    try:
        subprocess.run(["uvicorn", "api:app", "--host", "127.0.0.1", "--port", "8000", "--reload"])
    except KeyboardInterrupt:
        print("\n[+] API service stopped.")


def main():
    database.init_db()

    while True:
        show_menu()
        user_input = input("Enter your choice (0-8): ").strip()

        if not user_input:
            continue

        parts = user_input.split(maxsplit=1)
        choice = parts[0]
        extra_url = parts[1] if len(parts) > 1 else None

        if not choice.isdigit() and ("." in user_input or "http" in user_input):
            print(f"\n[+] Direct URL detected: '{user_input}'")
            scam_detector.main(url=user_input)
            continue

        if choice == "1":
            scam_detector.main(url=extra_url)
        elif choice == "2":
            download_dataset.download_and_inspect_dataset()
        elif choice == "3":
            model, feature_cols, _ = train_models.train_and_benchmark_all_models(sample_size=30000)
            ai_fraud_classifier.predict_sample_transaction(model, feature_cols)
        elif choice == "4":
            run_merged_audit(url=extra_url)
        elif choice == "5":
            launch_web_dashboard()
        elif choice == "6":
            launch_api()
        elif choice == "7":
            view_history()
        elif choice == "8":
            run_merged_audit(url="shoppersstop.com")
        elif choice == "0":
            print("\n[👋] Exiting AI Scam & Fraud Detection Platform. Goodbye!\n")
            sys.exit(0)
        else:
            print("\n[❌] Invalid selection. Please enter a number from 0 to 8.")


if __name__ == "__main__":
    main()
