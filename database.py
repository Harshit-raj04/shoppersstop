"""
AI Scam & Fraud Detection Platform - Database Layer
Author: AI & Python Development Team
Description: SQLite storage layer for persistent audit history of scanned websites,
             AI transaction evaluations, and merged risk assessments.
"""

import sqlite3
import datetime
from typing import List, Dict, Any, Optional

DB_FILE = "audit_history.db"


def get_connection():
    """Returns a SQLite database connection with row factory enabled."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes tables for audit history if they do not exist."""
    conn = get_connection()
    cursor = conn.cursor()

    # Table for Website URL Audits
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS url_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            domain TEXT NOT NULL,
            has_https INTEGER NOT NULL,
            age_days INTEGER,
            has_mx INTEGER,
            typosquatting_flag INTEGER,
            closest_brand TEXT,
            risk_score REAL NOT NULL,
            risk_level TEXT NOT NULL
        )
    """)

    # Table for AI Transaction Audits
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS transaction_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            amount REAL NOT NULL,
            user_avg_amount REAL,
            shipping_distance_km REAL,
            account_age_days INTEGER,
            cvv_match INTEGER,
            three_ds_flag INTEGER,
            fraud_probability REAL NOT NULL,
            primary_risk_driver TEXT
        )
    """)

    # Table for Unified Merged Audits
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS unified_audits (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            domain TEXT NOT NULL,
            url_risk_score REAL NOT NULL,
            ai_fraud_probability REAL NOT NULL,
            unified_risk_score REAL NOT NULL,
            verdict TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


def log_url_audit(
    domain: str,
    has_https: bool,
    age_days: Optional[int],
    has_mx: bool,
    typosquatting_flag: bool,
    closest_brand: Optional[str],
    risk_score: float,
    risk_level: str
) -> int:
    """Inserts a URL audit entry into the database."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO url_audits (
            timestamp, domain, has_https, age_days, has_mx,
            typosquatting_flag, closest_brand, risk_score, risk_level
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_iso, domain, 1 if has_https else 0, age_days,
        1 if has_mx else 0, 1 if typosquatting_flag else 0,
        closest_brand or "", risk_score, risk_level
    ))

    audit_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return audit_id


def log_transaction_audit(
    amount: float,
    user_avg_amount: float,
    shipping_distance_km: float,
    account_age_days: int,
    cvv_match: int,
    three_ds_flag: int,
    fraud_probability: float,
    primary_risk_driver: str
) -> int:
    """Inserts a Transaction audit entry into the database."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO transaction_audits (
            timestamp, amount, user_avg_amount, shipping_distance_km,
            account_age_days, cvv_match, three_ds_flag, fraud_probability,
            primary_risk_driver
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        now_iso, amount, user_avg_amount, shipping_distance_km,
        account_age_days, cvv_match, three_ds_flag,
        fraud_probability, primary_risk_driver
    ))

    audit_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return audit_id


def log_unified_audit(
    domain: str,
    url_risk_score: float,
    ai_fraud_probability: float,
    unified_risk_score: float,
    verdict: str
) -> int:
    """Inserts a Unified audit entry into the database."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()
    now_iso = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    cursor.execute("""
        INSERT INTO unified_audits (
            timestamp, domain, url_risk_score, ai_fraud_probability,
            unified_risk_score, verdict
        ) VALUES (?, ?, ?, ?, ?, ?)
    """, (
        now_iso, domain, url_risk_score, ai_fraud_probability,
        unified_risk_score, verdict
    ))

    audit_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return audit_id


def get_recent_audits(limit: int = 15) -> Dict[str, List[Dict[str, Any]]]:
    """Retrieves recent entries for all 3 audit tables."""
    init_db()
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM url_audits ORDER BY id DESC LIMIT ?", (limit,))
    url_records = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM transaction_audits ORDER BY id DESC LIMIT ?", (limit,))
    tx_records = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM unified_audits ORDER BY id DESC LIMIT ?", (limit,))
    unified_records = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {
        "url_audits": url_records,
        "transaction_audits": tx_records,
        "unified_audits": unified_records
    }


if __name__ == "__main__":
    init_db()
    print("[+] Database initialized successfully.")
