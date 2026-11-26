"""
AI Scam & Fraud Detection Platform - FastAPI REST Microservice
Author: AI & Python Development Team
Description: Production-ready RESTful API providing JSON endpoints for:
             - Website threat intelligence & brand typosquatting scan
             - Machine Learning transaction fraud scoring & Explainable AI (XAI)
             - Unified multi-layer fraud auditing
             - Batch transaction scoring
             - Historical audit retrieval
"""

import os
from typing import List, Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

import scam_detector
import ai_fraud_classifier
import database
import report_generator

app = FastAPI(
    title="AI Scam & Fraud Detection Platform API",
    description="Enterprise API providing multi-layer website threat intelligence, e-commerce brand spoofing checks, and AI transaction fraud risk scoring.",
    version="2.0.0"
)

# CORS middleware to allow integrations from any frontend or checkout system
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Global model cache
model_cache = None
feature_columns_cache = None


def get_model():
    global model_cache, feature_columns_cache
    if model_cache is None or feature_columns_cache is None:
        model_cache, feature_columns_cache = ai_fraud_classifier.get_or_load_model()
    return model_cache, feature_columns_cache


# ---------------------------------------------------------
# Request & Response Schemas
# ---------------------------------------------------------

class URLScanRequest(BaseModel):
    url: str = Field(..., example="shoppersstop.com", description="Target website URL or domain name to scan.")


class TransactionRequest(BaseModel):
    amount: float = Field(..., example=1450.0, description="Transaction amount in currency units.")
    avg_amount_user: float = Field(45.0, example=45.0, description="Customer's historic average spend.")
    shipping_distance_km: float = Field(1250.0, example=1250.0, description="Distance between billing and shipping locations in km.")
    account_age_days: int = Field(3, example=3, description="Age of the customer's account in days.")
    cvv_match: int = Field(0, example=0, description="1 if CVV matched, 0 if CVV check failed.")
    three_ds_flag: int = Field(0, example=0, description="1 if 3D-Secure 2FA OTP passed, 0 if bypassed/failed.")


class UnifiedAuditRequest(BaseModel):
    url: str = Field(..., example="suspicious-store.com", description="E-commerce website URL to evaluate.")
    transaction: TransactionRequest


class BatchTransactionItem(BaseModel):
    transaction_id: Optional[str] = Field(None, example="TX1001")
    amount: float = Field(..., example=500.0)
    avg_amount_user: float = Field(100.0, example=100.0)
    shipping_distance_km: float = Field(20.0, example=20.0)
    account_age_days: int = Field(180, example=180)
    cvv_match: int = Field(1, example=1)
    three_ds_flag: int = Field(1, example=1)


class BatchTransactionRequest(BaseModel):
    transactions: List[BatchTransactionItem]


# ---------------------------------------------------------
# API Endpoints
# ---------------------------------------------------------

@app.get("/api/v1/health", tags=["System"])
def health_check():
    """Returns platform operational health and loaded model status."""
    m, cols = get_model()
    return {
        "status": "healthy",
        "model_loaded": m is not None,
        "feature_count": len(cols) if cols else 0,
        "version": "2.0.0"
    }


@app.post("/api/v1/scan-url", tags=["Website Threat Intelligence"])
def scan_url_endpoint(req: URLScanRequest):
    """
    Scans a domain for SSL status, WHOIS domain age, MX mail records,
    brand typosquatting/phishing imitation, and deceptive page urgency patterns.
    """
    if not req.url or not req.url.strip():
        raise HTTPException(status_code=400, detail="Invalid URL specified.")

    result = scam_detector.audit_website(req.url, save_to_db=True)
    return result


@app.post("/api/v1/predict-transaction", tags=["Transaction Fraud AI"])
def predict_transaction_endpoint(req: TransactionRequest):
    """
    Evaluates e-commerce transaction parameters against the trained XGBoost AI model,
    returning fraud risk probability, risk level, and Explainable AI (XAI) feature attribution.
    """
    m, cols = get_model()
    result = ai_fraud_classifier.predict_transaction_detailed(
        model=m,
        feature_columns=cols,
        account_age_days=req.account_age_days,
        amount=req.amount,
        avg_amount_user=req.avg_amount_user,
        shipping_distance_km=req.shipping_distance_km,
        cvv_match=req.cvv_match,
        three_ds_flag=req.three_ds_flag,
        save_to_db=True
    )
    return result


@app.post("/api/v1/unified-audit", tags=["Multi-Layer Unified Audit"])
def unified_audit_endpoint(req: UnifiedAuditRequest):
    """
    Executes a merged multi-layer evaluation:
    - Layer 1: Website threat intelligence (40% weight)
    - Layer 2: AI transaction fraud score (60% weight)
    Logs outcome to SQLite and returns merged risk assessment.
    """
    url_res = scam_detector.audit_website(req.url, save_to_db=True)

    m, cols = get_model()
    tx_res = ai_fraud_classifier.predict_transaction_detailed(
        model=m,
        feature_columns=cols,
        account_age_days=req.transaction.account_age_days,
        amount=req.transaction.amount,
        avg_amount_user=req.transaction.avg_amount_user,
        shipping_distance_km=req.transaction.shipping_distance_km,
        cvv_match=req.transaction.cvv_match,
        three_ds_flag=req.transaction.three_ds_flag,
        save_to_db=True
    )

    url_score = url_res["risk_score"]
    ai_prob = tx_res["fraud_probability"]
    unified_score = round((url_score * 0.4) + (ai_prob * 0.6), 1)

    if unified_score <= 35:
        verdict = "LOW RISK 🟢 (Safe to proceed)"
    elif unified_score <= 65:
        verdict = "MEDIUM RISK 🟡 (Proceed with caution)"
    else:
        verdict = "HIGH FRAUD RISK 🔴 (Immediate Action Required!)"

    # Save to SQLite
    database.log_unified_audit(
        domain=url_res["domain"],
        url_risk_score=url_score,
        ai_fraud_probability=ai_prob,
        unified_risk_score=unified_score,
        verdict=verdict
    )

    return {
        "domain": url_res["domain"],
        "unified_risk_score": unified_score,
        "unified_verdict": verdict,
        "layer_1_website": url_res,
        "layer_2_transaction": tx_res
    }


@app.post("/api/v1/batch-predict", tags=["Transaction Fraud AI"])
def batch_predict_endpoint(req: BatchTransactionRequest):
    """
    Scores multiple transactions concurrently, returning fraud probability and primary risk drivers for each.
    """
    m, cols = get_model()
    results = []

    for tx in req.transactions:
        p = ai_fraud_classifier.predict_transaction(
            m, cols,
            account_age_days=tx.account_age_days,
            amount=tx.amount,
            avg_amount_user=tx.avg_amount_user,
            shipping_distance_km=tx.shipping_distance_km,
            cvv_match=tx.cvv_match,
            three_ds_flag=tx.three_ds_flag
        )
        driver, factors = ai_fraud_classifier.explain_transaction_factors(
            tx.account_age_days, tx.amount, tx.avg_amount_user,
            tx.shipping_distance_km, tx.cvv_match, tx.three_ds_flag, p
        )
        results.append({
            "transaction_id": tx.transaction_id,
            "fraud_probability": round(p, 2),
            "risk_level": "HIGH" if p >= 70 else ("MEDIUM" if p >= 40 else "LOW"),
            "primary_risk_driver": driver
        })

    return {"count": len(results), "scored_transactions": results}


@app.get("/api/v1/history", tags=["Audit Logs"])
def get_audit_history(limit: int = Query(15, ge=1, le=100)):
    """Returns recent audit logs stored in the SQLite database."""
    return database.get_recent_audits(limit=limit)


if __name__ == "__main__":
    import uvicorn
    print("[+] Starting FastAPI server at http://127.0.0.1:8000 (Swagger docs: http://127.0.0.1:8000/docs)...")
    uvicorn.run("api:app", host="127.0.0.1", port=8000, reload=True)
