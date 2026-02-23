import requests
import os
import hashlib
from dotenv import load_dotenv

load_dotenv()

VT_API_KEY = os.getenv("VT_API_KEY")
BASE_URL = "https://www.virustotal.com/api/v3"

HEADERS = {"x-apikey": VT_API_KEY}

def check_ip(ip: str) -> dict:
    try:
        response = requests.get(f"{BASE_URL}/ip_addresses/{ip}", headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "country": data.get("country"),
            "owner": data.get("as_owner"),
            "reputation": data.get("reputation")
        }
    except Exception as e:
        return {"error": str(e)}


def check_domain(domain: str) -> dict:
    try:
        response = requests.get(f"{BASE_URL}/domains/{domain}", headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        return {
            "domain": domain,
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "reputation": data.get("reputation"),
            "categories": data.get("categories", {})
        }
    except Exception as e:
        return {"error": str(e)}


def check_hash(file_hash: str) -> dict:
    try:
        response = requests.get(f"{BASE_URL}/files/{file_hash}", headers=HEADERS, timeout=10)
        response.raise_for_status()
        data = response.json()["data"]["attributes"]

        stats = data.get("last_analysis_stats", {})
        return {
            "hash": file_hash,
            "malicious_votes": stats.get("malicious", 0),
            "suspicious_votes": stats.get("suspicious", 0),
            "harmless_votes": stats.get("harmless", 0),
            "type": data.get("type_description"),
            "name": data.get("meaningful_name"),
            "size": data.get("size")
        }
    except Exception as e:
        return {"error": str(e)}