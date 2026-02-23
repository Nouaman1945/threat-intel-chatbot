import re
import os
import anthropic
from dotenv import load_dotenv

from apis.nvd import get_cve
from apis.cisa import is_in_kev, get_recent_kev
from apis.mitre import get_technique, get_threat_actor
from apis.virustotal import check_ip, check_domain, check_hash
from utils.prompts import (
    cve_prompt, threat_actor_prompt, technique_prompt,
    ioc_prompt, general_prompt
)

load_dotenv()
client = anthropic.Anthropic(api_key=os.getenv("ANTHROPIC_API_KEY"))

# Regex patterns for intent detection
CVE_PATTERN = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
TECHNIQUE_PATTERN = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)
IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
DOMAIN_PATTERN = re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b')
HASH_PATTERN = re.compile(r'\b[a-fA-F0-9]{32,64}\b')

KNOWN_ACTORS = [
    "apt28", "apt29", "apt41", "lazarus", "fin7", "carbanak",
    "cozy bear", "fancy bear", "sandworm", "scattered spider",
    "lockbit", "alphv", "blackcat", "volt typhoon", "salt typhoon"
]

KEV_KEYWORDS = ["kev", "known exploited", "actively exploited", "cisa kev", "recent vulnerabilities"]


def detect_intent(message: str) -> str:
    msg = message.lower()

    if CVE_PATTERN.search(message):
        return "cve_lookup"

    if TECHNIQUE_PATTERN.search(message):
        return "technique_lookup"

    if any(actor in msg for actor in KNOWN_ACTORS):
        return "threat_actor"

    if IP_PATTERN.search(message) and ("check" in msg or "lookup" in msg or "reputation" in msg or "malicious" in msg):
        return "ip_check"

    if HASH_PATTERN.search(message):
        return "hash_check"

    if any(kw in msg for kw in KEV_KEYWORDS):
        return "kev_recent"

    return "general"


def call_llm(prompt: str) -> str:
    response = client.messages.create(
        model="claude-haiku-4-5-20251001",
        max_tokens=800,
        messages=[{"role": "user", "content": prompt}]
    )
    return response.content[0].text


def process_message(message: str) -> str:
    intent = detect_intent(message)

    if intent == "cve_lookup":
        cve_id = CVE_PATTERN.search(message).group()
        cve_data = get_cve(cve_id)
        kev_data = is_in_kev(cve_id)
        prompt = cve_prompt(cve_data, kev_data, message)
        return call_llm(prompt)

    elif intent == "technique_lookup":
        tech_id = TECHNIQUE_PATTERN.search(message).group()
        technique_data = get_technique(tech_id)
        prompt = technique_prompt(technique_data, message)
        return call_llm(prompt)

    elif intent == "threat_actor":
        # Try to extract actor name from known list
        msg_lower = message.lower()
        actor_name = next((a for a in KNOWN_ACTORS if a in msg_lower), None)
        if actor_name:
            actor_data = get_threat_actor(actor_name)
            prompt = threat_actor_prompt(actor_data, message)
            return call_llm(prompt)
        return call_llm(general_prompt(message))

    elif intent == "ip_check":
        ip = IP_PATTERN.search(message).group()
        ioc_data = check_ip(ip)
        prompt = ioc_prompt(ioc_data, "IP Address", ip, message)
        return call_llm(prompt)

    elif intent == "hash_check":
        file_hash = HASH_PATTERN.search(message).group()
        ioc_data = check_hash(file_hash)
        prompt = ioc_prompt(ioc_data, "File Hash", file_hash, message)
        return call_llm(prompt)

    elif intent == "kev_recent":
        recent = get_recent_kev(days=7)
        if not recent:
            return "No new CVEs were added to the CISA KEV catalog in the last 7 days, or the feed could not be reached."
        summary = "\n".join([f"- {v['cve_id']} | {v['vendor']} {v['product']} | Added: {v['date_added']}" for v in recent])
        prompt = f"Summarize these recently added CISA KEV entries for a SOC analyst:\n\n{summary}\n\nUser question: {message}"
        return call_llm(prompt)

    else:
        return call_llm(general_prompt(message))