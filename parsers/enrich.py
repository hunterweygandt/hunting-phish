from datetime import datetime, timezone
import time

import requests
import whois

from parsers.config import get_api_key

# VirusTotal config. The key now comes from config.ini via the config
# loader, not from an environment variable or (never) the source code.
VT_API_KEY = get_api_key("virustotal")
VT_BASE = "https://www.virustotal.com/api/v3"


# AbuseIPDB config. The key now comes from config.ini via the config
# loader, not from an environment variable or (never) the source code.
ABUSEIPDB_API_KEY = get_api_key("abuseipdb")
ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"


# URLScan.io - submits a URL to be visited and analyzed (behavioral, not
# just reputation). This one is ASYNC: you submit, then poll for the result.
URLSCAN_API_KEY = get_api_key("urlscan")
URLSCAN_BASE = "https://urlscan.io/api/v1"
# how long to wait for an async scan before giving up and just linking it
URLSCAN_POLL_ATTEMPTS = 6
URLSCAN_POLL_SECONDS = 3


# JUDGMENT KNOB for Domain age
NEW_DOMAIN_DAYS = 90


def whois_age_days(domain):
    if not domain:
        return None

    try:
        data = whois.whois(domain)
    except Exception:
        return None

    created = data.creation_date

    if isinstance(created, list):
        real_dates = [d for d in created if isinstance(d, datetime)]
        created = min(real_dates) if real_dates else None

    if not isinstance(created, datetime):
        return None

    now = datetime.now(timezone.utc)
    if created.tzinfo is None:
        created = created.replace(tzinfo=timezone.utc)

    return (now - created).days


def is_new_domain(age_days):
    return age_days is not None and age_days <= NEW_DOMAIN_DAYS

def virustotal_domain(domain):
    if not domain or not VT_API_KEY:
        return None

    try:
        resp = requests.get(
            f"{VT_BASE}/domains/{domain}",
            headers={"x-apikey": VT_API_KEY},
            timeout=15,
        )
    except requests.RequestException:
        return None

    # 200 = OK. 404 = VT never saw this domain. 401 = bad key.
    # 429 = rate limited (free tier is ~4 lookups/minute).
    if resp.status_code != 200:
        return None

    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError, TypeError):
        return None

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }

def virustotal_hash(sha256):
    if not sha256 or not VT_API_KEY:
        return None

    try:
        resp = requests.get(
            f"{VT_BASE}/files/{sha256}",
            headers={"x-apikey": VT_API_KEY},
            timeout=15,
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
    except (KeyError, ValueError, TypeError):
        return None

    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "harmless": stats.get("harmless", 0),
        "undetected": stats.get("undetected", 0),
    }


def vt_domain_link(domain):
    """Clickable VT report page for a domain."""
    return f"https://www.virustotal.com/gui/domain/{domain}"


def vt_file_link(sha256):
    """Clickable VT report page for a file hash."""
    return f"https://www.virustotal.com/gui/file/{sha256}"

def abuseipdb_check(ip):
    if not ip or not ABUSEIPDB_API_KEY:
        return None

    try:
        resp = requests.get(
            f"{ABUSEIPDB_BASE}/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        data = resp.json()["data"]
    except (KeyError, ValueError, TypeError):
        return None

    return {
        "abuse_score": data.get("abuseConfidenceScore", 0),
        "total_reports": data.get("totalReports", 0),
        "country": data.get("countryCode"),
        "isp": data.get("isp"),
    }


def abuseipdb_link(ip):
    """Clickable AbuseIPDB report page for an IP."""
    return f"https://www.abuseipdb.com/check/{ip}"

def urlscan_lookup(url):
    if not url or not URLSCAN_API_KEY:
        return None

    # --- step 1: submit the scan ---
    try:
        resp = requests.post(
            f"{URLSCAN_BASE}/scan/",
            headers={"API-Key": URLSCAN_API_KEY,
                     "Content-Type": "application/json"},
            json={"url": url, "visibility": "unlisted"},
            timeout=15,
        )
    except requests.RequestException:
        return None

    if resp.status_code != 200:
        return None

    try:
        submit = resp.json()
        uuid = submit["uuid"]
        result_link = submit.get("result")
    except (KeyError, ValueError, TypeError):
        return None

    # --- step 2: poll for the result ---
    api_url = f"{URLSCAN_BASE}/result/{uuid}/"
    verdict = None
    for _ in range(URLSCAN_POLL_ATTEMPTS):
        time.sleep(URLSCAN_POLL_SECONDS)  # give the scan time to run
        try:
            r = requests.get(api_url, timeout=15)
        except requests.RequestException:
            break
        if r.status_code == 200:
            try:
                overall = r.json().get("verdicts", {}).get("overall", {})
                verdict = {
                    "malicious": overall.get("malicious", False),
                    "score": overall.get("score", 0),
                }
            except (ValueError, TypeError):
                verdict = None
            break
        # 404 = still processing; loop and try again

    return {"result_link": result_link, "verdict": verdict}