"""
AI Scam & Fraud Detection Platform - Security Report Generator
Author: AI & Python Development Team
Description: Generates standalone, styled HTML Security Audit Reports (printable/saveable as PDF)
             summarizing URL security, DNS MX integrity, brand spoofing, AI transaction risk,
             and actionable remediation steps.
"""

import datetime
from typing import Dict, Any, Optional


def generate_html_security_report(
    domain: str,
    url_audit: Dict[str, Any],
    tx_audit: Optional[Dict[str, Any]] = None,
    unified_risk_score: Optional[float] = None,
    unified_status: Optional[str] = None
) -> str:
    """
    Generates a responsive, modern HTML audit report string.
    """
    now_str = datetime.datetime.now().strftime("%B %d, %Y - %H:%M:%S UTC")

    # Risk badge colors
    if unified_risk_score is None:
        unified_risk_score = url_audit.get("risk_score", 0.0)
        unified_status = url_audit.get("risk_level", "LOW RISK 🟢")

    if unified_risk_score <= 35:
        score_color = "#10b981"  # Emerald Green
        score_bg = "#ecfdf5"
        verdict_badge = "SAFE / LOW RISK"
    elif unified_risk_score <= 65:
        score_color = "#f59e0b"  # Amber Orange
        score_bg = "#fffbeb"
        verdict_badge = "CAUTION / SUSPICIOUS"
    else:
        score_color = "#ef4444"  # Crimson Red
        score_bg = "#fef2f2"
        verdict_badge = "HIGH FRAUD THREAT"

    # URL specifics
    has_https = url_audit.get("has_https", False)
    age_days = url_audit.get("age_in_days", None)
    has_mx = url_audit.get("has_mx", False)
    is_typo = url_audit.get("is_typosquatting", False)
    brand = url_audit.get("closest_brand", "")
    has_refund = url_audit.get("has_refund", False)
    breakdown = url_audit.get("breakdown", [])

    breakdown_html = "".join([f"<li style='margin-bottom: 6px;'>{item}</li>" for item in breakdown])

    # Transaction specifics HTML section
    tx_html = ""
    if tx_audit:
        tx_factors = tx_audit.get("factors", [])
        factors_rows = ""
        for f in tx_factors:
            sev_badge = (
                "<span style='background:#fee2e2; color:#b91c1c; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600;'>HIGH</span>"
                if f.get("severity") in ["HIGH", "CRITICAL"]
                else "<span style='background:#fef3c7; color:#b45309; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600;'>MED</span>"
            )
            factors_rows += f"""
            <tr>
                <td style='padding: 10px; border-bottom: 1px solid #e2e8f0;'>{sev_badge} <strong>{f.get('factor')}</strong></td>
                <td style='padding: 10px; border-bottom: 1px solid #e2e8f0; color: #64748b;'>{f.get('description')}</td>
                <td style='padding: 10px; border-bottom: 1px solid #e2e8f0; text-align: right; font-weight: bold; color: #ef4444;'>+{f.get('impact_pct')}%</td>
            </tr>
            """

        inputs = tx_audit.get("input_features", {})
        tx_html = f"""
        <div style="background: white; border-radius: 12px; padding: 24px; margin-top: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); border: 1px solid #e2e8f0;">
            <h3 style="margin-top: 0; color: #1e293b; font-size: 18px; border-bottom: 2px solid #f1f5f9; padding-bottom: 12px;">
                💳 Layer 2: AI Transaction Risk & Factor Attribution
            </h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 16px;">
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">Transaction Amount</div>
                    <div style="font-size: 18px; font-weight: bold; color: #0f172a;">${inputs.get('amount', 0):,.2f}</div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">User Typical Average</div>
                    <div style="font-size: 18px; font-weight: bold; color: #0f172a;">${inputs.get('avg_amount_user', 0):,.2f}</div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">Shipping Distance</div>
                    <div style="font-size: 18px; font-weight: bold; color: #0f172a;">{inputs.get('shipping_distance_km', 0):,.1f} km</div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">AI Fraud Probability</div>
                    <div style="font-size: 18px; font-weight: bold; color: #ef4444;">{tx_audit.get('fraud_probability', 0):.2f}%</div>
                </div>
            </div>
            <h4 style="color: #334155; margin-bottom: 8px; font-size: 14px;">Explainable AI (XAI) Attribution Breakdown:</h4>
            <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                <thead>
                    <tr style="background: #f1f5f9; text-align: left;">
                        <th style="padding: 10px; border-bottom: 2px solid #cbd5e1;">Risk Factor</th>
                        <th style="padding: 10px; border-bottom: 2px solid #cbd5e1;">Evidence</th>
                        <th style="padding: 10px; border-bottom: 2px solid #cbd5e1; text-align: right;">Risk Impact</th>
                    </tr>
                </thead>
                <tbody>
                    {factors_rows if factors_rows else "<tr><td colspan='3' style='padding:12px; text-align:center; color:#64748b;'>No abnormal risk flags triggered.</td></tr>"}
                </tbody>
            </table>
        </div>
        """

    html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>AI Security Audit Report - {domain}</title>
    <style>
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            background-color: #f8fafc;
            color: #334155;
            margin: 0;
            padding: 30px 20px;
        }}
        .container {{
            max-width: 900px;
            margin: 0 auto;
        }}
        .card {{
            background: white;
            border-radius: 12px;
            padding: 24px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            border: 1px solid #e2e8f0;
            margin-bottom: 24px;
        }}
        .header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            border-bottom: 2px solid #f1f5f9;
            padding-bottom: 16px;
            margin-bottom: 24px;
        }}
        .badge {{
            display: inline-block;
            padding: 6px 12px;
            border-radius: 9999px;
            font-size: 12px;
            font-weight: 700;
            letter-spacing: 0.05em;
            text-transform: uppercase;
        }}
        .pill-ok {{ background: #dcfce7; color: #15803d; }}
        .pill-warn {{ background: #fef3c7; color: #b45309; }}
        .pill-danger {{ background: #fee2e2; color: #b91c1c; }}
        @media print {{
            body {{ background: white; padding: 0; }}
            .card {{ box-shadow: none; border: 1px solid #cbd5e1; }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header -->
        <div class="card">
            <div class="header">
                <div>
                    <h1 style="margin: 0; font-size: 24px; color: #0f172a;">🛡️ Unified AI Security & Fraud Audit Report</h1>
                    <p style="margin: 4px 0 0; color: #64748b; font-size: 13px;">Generated on {now_str}</p>
                </div>
                <span class="badge" style="background: {score_bg}; color: {score_color}; font-size: 14px;">{verdict_badge}</span>
            </div>

            <!-- Top Score Summary -->
            <div style="display: flex; align-items: center; gap: 24px; background: {score_bg}; border: 1px solid {score_color}33; border-radius: 12px; padding: 20px;">
                <div style="font-size: 48px; font-weight: 900; color: {score_color}; line-height: 1;">
                    {unified_risk_score}<span style="font-size: 20px; font-weight: normal; color: #64748b;"> / 100</span>
                </div>
                <div>
                    <div style="font-size: 18px; font-weight: bold; color: #0f172a; margin-bottom: 4px;">{unified_status}</div>
                    <div style="font-size: 13px; color: #475569;">
                        Target Domain: <strong>{domain}</strong> | Evaluation Engine: XGBoost AI + WHOIS & DNS Threat Intel
                    </div>
                </div>
            </div>
        </div>

        <!-- Layer 1: Website Domain Intelligence -->
        <div class="card">
            <h3 style="margin-top: 0; color: #1e293b; font-size: 18px; border-bottom: 2px solid #f1f5f9; padding-bottom: 12px;">
                🌐 Layer 1: Website Threat & Domain Intelligence
            </h3>
            <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; margin-bottom: 20px;">
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">SSL / HTTPS</div>
                    <div style="font-size: 16px; font-weight: bold; color: {'#15803d' if has_https else '#b91c1c'};">
                        {"Active & Valid ✅" if has_https else "Missing / Insecure ❌"}
                    </div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">Domain Age</div>
                    <div style="font-size: 16px; font-weight: bold; color: #0f172a;">
                        {f"{age_days} Days" if age_days is not None else "Unknown / Hidden"}
                    </div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">Mail Server (MX)</div>
                    <div style="font-size: 16px; font-weight: bold; color: {'#15803d' if has_mx else '#b91c1c'};">
                        {"Verified ✅" if has_mx else "No MX Records ❌"}
                    </div>
                </div>
                <div style="background: #f8fafc; padding: 12px; border-radius: 8px;">
                    <div style="font-size: 12px; color: #64748b;">Brand Typosquatting</div>
                    <div style="font-size: 16px; font-weight: bold; color: {'#b91c1c' if is_typo else '#15803d'};">
                        {f"Spoofing '{brand}' 🚨" if is_typo else "Clean / Authentic ✅"}
                    </div>
                </div>
            </div>

            <h4 style="color: #334155; margin-bottom: 8px; font-size: 14px;">Domain Risk Rules Breakdown:</h4>
            <ul style="font-size: 13px; color: #475569; padding-left: 20px; line-height: 1.6;">
                {breakdown_html}
            </ul>
        </div>

        <!-- Layer 2 (Optional) -->
        {tx_html}

        <!-- Recommendations -->
        <div class="card" style="background: #f8fafc; border-left: 4px solid {score_color};">
            <h4 style="margin-top: 0; color: #0f172a; font-size: 16px;">🛡️ Security Recommendations & Guidance</h4>
            <ul style="font-size: 13px; color: #334155; line-height: 1.6; margin-bottom: 0; padding-left: 20px;">
                {'<li><strong>DO NOT ENTER PAYMENT CREDENTIALS:</strong> High probability of phishing or brand impersonation.</li>' if is_typo or unified_risk_score >= 65 else ''}
                {'<li><strong>ENFORCE 3D-SECURE (2FA):</strong> Require SMS OTP or biometric verification before settlement.</li>' if tx_audit and inputs.get('three_ds_flag') == 0 else ''}
                {'<li><strong>MANUAL REVIEW REQUIRED:</strong> Flag order for fraud analyst verification due to shipping address disparity.</li>' if tx_audit and inputs.get('shipping_distance_km', 0) > 400 else ''}
                <li>Verify merchant contact details and company registration prior to executing high-value orders.</li>
            </ul>
        </div>
    </div>
</body>
</html>"""
    return html_template


def save_report_to_file(html_content: str, filename: str = "security_audit_report.html") -> str:
    """Saves HTML string to local file."""
    with open(filename, "w", encoding="utf-8") as f:
        f.write(html_content)
    return filename
