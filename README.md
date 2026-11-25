# AI Scam & E-Commerce Fraud Detection Platform

A multi-layered AI & Threat Intelligence security platform designed to detect fraudulent e-commerce websites and high-risk transaction anomalies in real time.

---

## 🚀 Key Capabilities

1. **🌐 Website Threat Intelligence (`scam_detector.py`)**
   - Live SSL/HTTPS verification
   - WHOIS domain creation age analysis
   - DNS MX mail server validity checks
   - Brand typosquatting and homoglyph spoofing detection

2. **💳 AI Transaction Risk Simulator (`ai_fraud_classifier.py` & `train_models.py`)**
   - Trained on ~300,000 real-world e-commerce transactions
   - Benchmarks Random Forest, LightGBM, and XGBoost classifiers
   - Explainable AI (XAI) feature attribution identifying top risk drivers

3. **🔗 Unified Multi-Layer Merged Audit**
   - Combines website security intelligence (40%) and transaction risk probability (60%) into a unified risk rating.

4. **🖥️ Interactive Streamlit Web UI (`app.py`)**
   - Real-time risk gauges, interactive transaction simulator, model benchmarks, batch CSV scoring, and SQLite audit history explorer.

5. **⚡ REST API Microservice (`api.py`)**
   - Production FastAPI endpoints with interactive Swagger UI documentation at `/docs`.

6. **📜 Persistent Audit Logging (`database.py`)**
   - SQLite persistence tracking website scans, transaction risk assessments, and unified security audits.

---

## 🛠️ Quickstart

### 1. Installation
```bash
pip install -r requirements.txt
```

### 2. Run Master CLI Suite
```bash
python3 main.py
```

### 3. Launch Web Dashboard (Streamlit)
```bash
streamlit run app.py
```

### 4. Launch REST API Server (FastAPI)
```bash
uvicorn api:app --reload --port 8000
```
