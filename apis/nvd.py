import requests
import os
from dotenv import load_dotenv

load_dotenv()

NVD_API_KEY = os.getenv("NVD_API_KEY")
BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

def get_cve(cve_id: str) -> dict:
    """
    Fetch CVE details from NVD by CVE ID.
    Example: get_cve("CVE-2021-44228")
    """
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    params = {"cveId": cve_id.upper()}

    try:
        response = requests.get(BASE_URL, headers=headers, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if data["totalResults"] == 0:
            return {"error": f"No CVE found for {cve_id}"}

        cve = data["vulnerabilities"][0]["cve"]

        # Extract what we actually need
        result = {
            "id": cve["id"],
            "published": cve["published"],
            "description": cve["descriptions"][0]["value"],
            "severity": None,
            "cvss_score": None,
            "references": [r["url"] for r in cve.get("references", [])[:3]]
        }

        # Pull CVSS score if available
        metrics = cve.get("metrics", {})
        if "cvssMetricV31" in metrics:
            cvss = metrics["cvssMetricV31"][0]["cvssData"]
            result["severity"] = cvss["baseSeverity"]
            result["cvss_score"] = cvss["baseScore"]
        elif "cvssMetricV2" in metrics:
            cvss = metrics["cvssMetricV2"][0]["cvssData"]
            result["severity"] = metrics["cvssMetricV2"][0]["baseSeverity"]
            result["cvss_score"] = cvss["baseScore"]

        return result

    except requests.exceptions.RequestException as e:
        return {"error": str(e)}