import requests
import json
import os
from datetime import datetime, timedelta

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_FILE = "data/cisa_kev.json"

def fetch_kev(force_refresh=False) -> dict:
    """
    Fetch CISA Known Exploited Vulnerabilities catalog.
    Caches locally for 24 hours to avoid hammering the endpoint.
    """
    os.makedirs("data", exist_ok=True)

    # Check if cache exists and is fresh
    if not force_refresh and os.path.exists(CACHE_FILE):
        modified = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE))
        if datetime.now() - modified < timedelta(hours=24):
            with open(CACHE_FILE, "r") as f:
                return json.load(f)

    # Fetch fresh data
    try:
        response = requests.get(KEV_URL, timeout=15)
        response.raise_for_status()
        data = response.json()

        with open(CACHE_FILE, "w") as f:
            json.dump(data, f)

        return data

    except requests.exceptions.RequestException as e:
        # Return cached version if available, even if stale
        if os.path.exists(CACHE_FILE):
            with open(CACHE_FILE, "r") as f:
                return json.load(f)
        return {"error": str(e)}


def is_in_kev(cve_id: str) -> dict:
    """Check if a specific CVE is in the CISA KEV catalog."""
    data = fetch_kev()

    if "error" in data:
        return data

    for vuln in data.get("vulnerabilities", []):
        if vuln["cveID"].upper() == cve_id.upper():
            return {
                "in_kev": True,
                "vendor": vuln["vendorProject"],
                "product": vuln["product"],
                "vulnerability_name": vuln["vulnerabilityName"],
                "date_added": vuln["dateAdded"],
                "due_date": vuln["dueDate"],
                "required_action": vuln["requiredAction"]
            }

    return {"in_kev": False}


def get_recent_kev(days=7) -> list:
    """Get CVEs added to KEV in the last N days."""
    data = fetch_kev()

    if "error" in data:
        return []

    cutoff = datetime.now() - timedelta(days=days)
    recent = []

    for vuln in data.get("vulnerabilities", []):
        added = datetime.strptime(vuln["dateAdded"], "%Y-%m-%d")
        if added >= cutoff:
            recent.append({
                "cve_id": vuln["cveID"],
                "product": vuln["product"],
                "vendor": vuln["vendorProject"],
                "date_added": vuln["dateAdded"],
                "required_action": vuln["requiredAction"]
            })

    return sorted(recent, key=lambda x: x["date_added"], reverse=True)