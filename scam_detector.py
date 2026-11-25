import warnings
warnings.filterwarnings("ignore")

# Import required standard Python modules
import sys
import io
import datetime
import urllib.parse
from typing import Dict, Any, Tuple, Optional, List

# Import required third-party Python modules
import requests
from bs4 import BeautifulSoup
import whois
from dateutil import parser as date_parser

try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    from rapidfuzz import fuzz
    HAS_RAPIDFUZZ = True
except ImportError:
    HAS_RAPIDFUZZ = False

# Try disabling urllib3 warnings if present
try:
    import urllib3
    urllib3.disable_warnings()
except Exception:
    pass

import database

# Known reputable brand domains for typosquatting / spoofing checks
PROTECTED_BRANDS = [
    "shoppersstop.com",
    "amazon.com",
    "amazon.in",
    "flipkart.com",
    "myntra.com",
    "paypal.com",
    "apple.com",
    "nike.com",
    "walmart.com",
    "ebay.com"
]

SUSPICIOUS_KEYWORDS = [
    "discount", "deal", "offer", "sale", "free", "outlet", "clearance",
    "promo", "cheap", "bonus", "vip", "login", "secure", "verify"
]


def clean_url(user_input: str) -> str:
    """
    Cleans raw user input into a standardized domain name.
    Example: '  "https://www.example.com/path?id=123"  ' -> 'www.example.com'
    """
    if not user_input:
        return ""

    url = str(user_input).strip().strip("'\"")

    if url.startswith("https://"):
        url = url[8:]
    elif url.startswith("http://"):
        url = url[7:]
    elif url.startswith("//"):
        url = url[2:]

    domain = url.split("/")[0].split("?")[0].split(":")[0]
    return domain.lower()


def check_https_status(domain: str) -> bool:
    """
    Checks if the target website supports secure HTTPS (SSL certificate).
    """
    https_url = f"https://{domain}"
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }

    try:
        response = requests.get(https_url, headers=headers, timeout=8, verify=True)
        return response.status_code < 500
    except Exception:
        return False


def get_domain_age(domain: str) -> Tuple[Optional[datetime.datetime], Optional[int], Optional[float]]:
    """
    Queries WHOIS registration records to find creation date and calculate domain age in days and months.
    """
    try:
        whois_domain = domain[4:] if domain.startswith("www.") else domain

        old_stdout = sys.stdout
        old_stderr = sys.stderr
        sys.stdout = io.StringIO()
        sys.stderr = io.StringIO()

        try:
            domain_info = whois.whois(whois_domain)
        finally:
            sys.stdout = old_stdout
            sys.stderr = old_stderr

        if not domain_info:
            return None, None, None

        creation_date = getattr(domain_info, "creation_date", None)
        if isinstance(creation_date, list):
            creation_date = next((d for d in creation_date if d is not None), None)

        if not creation_date:
            return None, None, None

        if isinstance(creation_date, str):
            try:
                creation_date = date_parser.parse(creation_date)
            except Exception:
                return None, None, None

        if not isinstance(creation_date, (datetime.datetime, datetime.date)):
            return None, None, None

        if type(creation_date) is datetime.date:
            creation_date = datetime.datetime.combine(creation_date, datetime.time.min)

        if hasattr(creation_date, "tzinfo") and creation_date.tzinfo is not None:
            now = datetime.datetime.now(datetime.timezone.utc)
        else:
            now = datetime.datetime.now()

        age_in_days = (now - creation_date).days
        if age_in_days < 0:
            age_in_days = 0

        age_in_months = round(age_in_days / 30.0, 1)
        return creation_date, age_in_days, age_in_months

    except Exception:
        return None, None, None


def check_mx_records(domain: str) -> bool:
    """
    Checks if domain has active MX (Mail Exchange) DNS records.
    Legitimate e-commerce stores almost always configure mail servers.
    """
    if not HAS_DNS:
        return True

    try:
        clean_d = domain[4:] if domain.startswith("www.") else domain
        records = dns.resolver.resolve(clean_d, 'MX', lifetime=5)
        return len(records) > 0
    except Exception:
        return False


def check_typosquatting(domain: str) -> Tuple[bool, Optional[str], float]:
    """
    Uses RapidFuzz to compare domain against protected high-profile brands.
    Detects brand impersonation e.g., 'shoppers-stop-deals.com' or 'amaz0n-sale.in'.
    Returns: (is_typosquatting, closest_brand, similarity_ratio)
    """
    clean_d = domain[4:] if domain.startswith("www.") else domain
    domain_core = clean_d.split(".")[0]

    # Exact brand check - if it's the exact legitimate brand, it's not typosquatting
    for brand in PROTECTED_BRANDS:
        if clean_d == brand:
            return False, brand, 100.0

    best_match = None
    highest_score = 0.0

    for brand in PROTECTED_BRANDS:
        brand_core = brand.split(".")[0]

        # 1. Check if domain contains brand name combined with suspicious keywords
        if brand_core in clean_d and clean_d != brand:
            for kw in SUSPICIOUS_KEYWORDS:
                if kw in clean_d:
                    return True, brand, 95.0
            return True, brand, 90.0

        # 2. Check fuzzy ratio
        if HAS_RAPIDFUZZ:
            ratio = fuzz.ratio(domain_core, brand_core)
            if ratio > highest_score:
                highest_score = ratio
                best_match = brand

    # Threshold for fuzzy lookalikes (e.g. 78% to 94% similar)
    if highest_score >= 80.0 and highest_score < 100.0:
        return True, best_match, highest_score

    return False, best_match, highest_score


def check_homepage_content(domain: str) -> Dict[str, Any]:
    """
    Downloads homepage HTML and analyzes:
    - Refund Policy and Terms of Service presence
    - Fake urgency / countdown timer markers
    """
    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
    }

    response_text = ""
    fetched = False

    for scheme in ["https://", "http://"]:
        try:
            target_url = f"{scheme}{domain}"
            response = requests.get(target_url, headers=headers, timeout=8)
            if response.status_code == 200:
                response_text = response.text
                fetched = True
                break
        except Exception:
            continue

    if not fetched or not response_text:
        return {
            "fetched": False,
            "has_refund": False,
            "has_terms": False,
            "has_urgency_triggers": False,
            "urgency_details": []
        }

    try:
        soup = BeautifulSoup(response_text, "html.parser")
        all_text = soup.get_text().lower()

        has_refund = ("refund policy" in all_text) or ("refund" in all_text and "policy" in all_text)
        has_terms = ("terms of service" in all_text) or ("terms and conditions" in all_text) or ("terms & conditions" in all_text)

        # Deceptive urgency checks
        urgency_details = []
        if "countdown" in all_text or "timer" in all_text:
            urgency_details.append("Countdown timer / urgency script detected")
        if "hurry, only" in all_text or "almost sold out" in all_text or "deal expires in" in all_text:
            urgency_details.append("High-pressure scarcity text ('hurry', 'almost sold out')")

        has_urgency = len(urgency_details) > 0

        return {
            "fetched": True,
            "has_refund": has_refund,
            "has_terms": has_terms,
            "has_urgency_triggers": has_urgency,
            "urgency_details": urgency_details
        }
    except Exception:
        return {
            "fetched": False,
            "has_refund": False,
            "has_terms": False,
            "has_urgency_triggers": False,
            "urgency_details": []
        }


def calculate_risk_score(
    has_https: bool,
    age_in_days: Optional[int],
    has_refund_policy: bool,
    is_typosquatting: bool = False,
    has_mx: bool = True,
    has_urgency: bool = False,
    closest_brand: Optional[str] = None
) -> Tuple[float, str, List[str]]:
    """
    Enhanced multi-factor website risk scoring engine (0 - 100):
    - Typosquatting / Brand spoofing: +35 pts
    - Missing HTTPS / SSL: +25 pts
    - Domain age < 90 days (or unknown): +30 pts
    - Missing MX records: +15 pts
    - Missing Refund Policy: +15 pts
    - Artificial urgency triggers: +10 pts
    """
    risk_score = 0
    breakdown = []

    # 1. Brand Spoofing / Typosquatting
    if is_typosquatting:
        risk_score += 35
        brand_label = f"'{closest_brand}'" if closest_brand else "major brand"
        breakdown.append(f"+35 pts : 🚨 High brand spoofing / typosquatting match for {brand_label}")
    else:
        breakdown.append("+0 pts  : No brand impersonation detected")

    # 2. SSL / HTTPS Security
    if not has_https:
        risk_score += 25
        breakdown.append("+25 pts : Missing HTTPS / SSL Security Certificate")
    else:
        breakdown.append("+0 pts  : HTTPS / SSL status active & valid")

    # 3. Domain Age & Registration
    if age_in_days is None:
        risk_score += 30
        breakdown.append("+30 pts : Domain age unknown / WHOIS records masked")
    elif age_in_days < 90:
        risk_score += 30
        breakdown.append(f"+30 pts : Domain is brand new ({age_in_days} days old < 90-day threshold)")
    else:
        breakdown.append(f"+0 pts  : Domain is mature ({age_in_days} days old)")

    # 4. Mail Exchange (MX) Record
    if not has_mx:
        risk_score += 15
        breakdown.append("+15 pts : Missing MX mail server DNS records (common in pop-up scam stores)")
    else:
        breakdown.append("+0 pts  : Active MX records verified")

    # 5. Refund Policy
    if not has_refund_policy:
        risk_score += 15
        breakdown.append("+15 pts : 'Refund Policy' missing from homepage content")
    else:
        breakdown.append("+0 pts  : 'Refund Policy' verified in content")

    # 6. Deceptive urgency triggers
    if has_urgency:
        risk_score += 10
        breakdown.append("+10 pts : Deceptive urgency / fake countdown scripts detected")

    # Cap score at 100
    risk_score = min(100.0, float(risk_score))

    if risk_score <= 35:
        risk_level = "LOW RISK 🟢"
    elif risk_score <= 65:
        risk_level = "MEDIUM RISK 🟡"
    else:
        risk_level = "HIGH RISK 🔴"

    return risk_score, risk_level, breakdown


def audit_website(url: str, save_to_db: bool = True) -> Dict[str, Any]:
    """
    Master programmatic function to scan any website URL.
    Returns a complete audit dictionary and logs to database if requested.
    """
    domain = clean_url(url)
    has_https = check_https_status(domain)
    creation_date, age_in_days, age_in_months = get_domain_age(domain)
    has_mx = check_mx_records(domain)
    is_typosquatting, closest_brand, sim_score = check_typosquatting(domain)
    content_info = check_homepage_content(domain)

    risk_score, risk_level, breakdown = calculate_risk_score(
        has_https=has_https,
        age_in_days=age_in_days,
        has_refund_policy=content_info["has_refund"],
        is_typosquatting=is_typosquatting,
        has_mx=has_mx,
        has_urgency=content_info["has_urgency_triggers"],
        closest_brand=closest_brand
    )

    audit_result = {
        "domain": domain,
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "has_https": has_https,
        "creation_date": creation_date.strftime("%Y-%m-%d") if hasattr(creation_date, "strftime") else (str(creation_date) if creation_date else "Unknown"),
        "age_in_days": age_in_days,
        "age_in_months": age_in_months,
        "has_mx": has_mx,
        "is_typosquatting": is_typosquatting,
        "closest_brand": closest_brand,
        "brand_similarity": sim_score,
        "has_refund": content_info["has_refund"],
        "has_terms": content_info["has_terms"],
        "has_urgency_triggers": content_info["has_urgency_triggers"],
        "urgency_details": content_info["urgency_details"],
        "fetched": content_info["fetched"],
        "risk_score": risk_score,
        "risk_level": risk_level,
        "breakdown": breakdown
    }

    if save_to_db:
        try:
            database.log_url_audit(
                domain=domain,
                has_https=has_https,
                age_days=age_in_days,
                has_mx=has_mx,
                typosquatting_flag=is_typosquatting,
                closest_brand=closest_brand,
                risk_score=risk_score,
                risk_level=risk_level
            )
        except Exception as e:
            pass

    return audit_result


def display_dashboard(domain, has_https, creation_date, age_in_days, age_in_months, has_refund_policy, has_terms_of_service, fetched_content, risk_score, risk_level, breakdown, is_typosquatting=False, closest_brand=None, has_mx=True):
    """
    Console visual display for CLI.
    """
    print("\n" + "=" * 68)
    print("      SCAM & FRAUD DETECTION PLATFORM - ANALYSIS DASHBOARD      ")
    print("=" * 68)
    print(f" Target Domain        : {domain}")
    print(f" Analysis Timestamp   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("-" * 68)
    print(" 🔍 INTELLIGENCE & DATA COLLECTION SUMMARY:")
    
    https_str = "Active & Secure (HTTPS) ✅" if has_https else "Missing / Insecure (HTTP only) ❌"
    print(f"   • SSL Status        : {https_str}")

    if is_typosquatting:
        print(f"   • Brand Spoofing    : 🚨 Detected imitation of '{closest_brand}'!")
    else:
        print(f"   • Brand Spoofing    : Clean / No brand imitation ✅")

    mx_str = "Active MX records found ✅" if has_mx else "No MX records found ❌"
    print(f"   • Mail Server (MX)  : {mx_str}")

    if age_in_days is not None:
        created_str = creation_date.strftime('%Y-%m-%d') if hasattr(creation_date, 'strftime') else str(creation_date)
        print(f"   • Creation Date     : {created_str}")
        print(f"   • Domain Age        : {age_in_days} Days (~{age_in_months} Months)")
    else:
        print(f"   • Creation Date     : Unknown / WHOIS Private")
        print(f"   • Domain Age        : Unknown")

    if fetched_content:
        refund_str = "Found ✅" if has_refund_policy else "Missing ❌"
        terms_str = "Found ✅" if has_terms_of_service else "Missing ❌"
        print(f"   • Refund Policy     : {refund_str}")
        print(f"   • Terms of Service  : {terms_str}")
    else:
        print(f"   • Homepage Fetch    : Failed / Connection Error ❌")

    print("-" * 68)
    print(" ⚖️  RULE-BASED RISK SCORING BREAKDOWN:")
    for rule in breakdown:
        print(f"   • {rule}")

    print("-" * 68)
    print(f" 📊 FINAL RISK SCORE   : {risk_score} / 100")
    print(f" 🚨 RISK ASSESSMENT    : {risk_level}")
    print("=" * 68 + "\n")


def main(url=None):
    print("\n" + "=" * 65)
    print("    AI Scam & Fraud Detection Platform - URL & Phishing Scanner    ")
    print("=" * 65)

    if not url or not str(url).strip():
        url = input("Enter a website URL to evaluate (e.g., shoppersstop.com or http://fake-deal.net): ")

    if not url or not str(url).strip():
        print("Error: No URL provided. Returning to main menu.")
        return

    try:
        domain = clean_url(url)
        print(f"\n[+] Analyzing domain: '{domain}'...")
        res = audit_website(domain, save_to_db=True)

        display_dashboard(
            domain=res["domain"],
            has_https=res["has_https"],
            creation_date=res["creation_date"],
            age_in_days=res["age_in_days"],
            age_in_months=res["age_in_months"],
            has_refund_policy=res["has_refund"],
            has_terms_of_service=res["has_terms"],
            fetched_content=res["fetched"],
            risk_score=res["risk_score"],
            risk_level=res["risk_level"],
            breakdown=res["breakdown"],
            is_typosquatting=res["is_typosquatting"],
            closest_brand=res["closest_brand"],
            has_mx=res["has_mx"]
        )
    except Exception as e:
        print(f"\n[❌] Error analyzing website: {e}")
        print("[!] Returning to main menu...\n")


if __name__ == "__main__":
    main()
