from mitreattack.stix20 import MitreAttackData
import os
import requests

MITRE_URL = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
MITRE_FILE = "data/enterprise-attack.json"

def download_mitre_data():
    """Download MITRE ATT&CK data if not already cached."""
    os.makedirs("data", exist_ok=True)
    if not os.path.exists(MITRE_FILE):
        print("Downloading MITRE ATT&CK data (one-time, ~50MB)...")
        response = requests.get(MITRE_URL, timeout=60)
        with open(MITRE_FILE, "wb") as f:
            f.write(response.content)
        print("Done.")

def get_mitre_data() -> MitreAttackData:
    download_mitre_data()
    return MitreAttackData(MITRE_FILE)


def get_technique(technique_id: str) -> dict:
    """Look up a technique by ID like T1059 or T1059.001"""
    mitre = get_mitre_data()
    techniques = mitre.get_techniques(remove_revoked_deprecated=True)

    for t in techniques:
        ext_refs = t.get("external_references", [])
        for ref in ext_refs:
            if ref.get("external_id", "").upper() == technique_id.upper():
                return {
                    "id": technique_id,
                    "name": t.get("name"),
                    "description": t.get("description", "")[:1000],
                    "platforms": t.get("x_mitre_platforms", []),
                    "detection": t.get("x_mitre_detection", "Not specified")[:500],
                    "url": ref.get("url")
                }

    return {"error": f"Technique {technique_id} not found"}


def get_threat_actor(group_name: str) -> dict:
    """Look up a threat actor group by name."""
    mitre = get_mitre_data()
    groups = mitre.get_groups(remove_revoked_deprecated=True)

    group_name_lower = group_name.lower()
    for group in groups:
        name = group.get("name", "").lower()
        aliases = [a.lower() for a in group.get("aliases", [])]

        if group_name_lower in name or group_name_lower in aliases:
            ext_refs = group.get("external_references", [])
            url = next((r.get("url") for r in ext_refs if "mitre" in r.get("url", "")), None)

            return {
                "name": group.get("name"),
                "aliases": group.get("aliases", []),
                "description": group.get("description", "")[:1000],
                "url": url
            }

    return {"error": f"Threat actor '{group_name}' not found"}