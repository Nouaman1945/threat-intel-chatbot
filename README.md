# 🛡️ Threat Intelligence Chatbot

A SOC analyst assistant that queries live threat intelligence sources in plain English using AI. Built as a junior SOC analyst portfolio project.

## Features
- **CVE Lookup** — Queries NVD for full vulnerability details including CVSS score and severity
- **Active Exploitation Check** — Cross-references CISA Known Exploited Vulnerabilities (KEV) catalog in real time
- **Threat Actor Profiling** — Pulls MITRE ATT&CK group data including TTPs, aliases, and targeted sectors
- **MITRE ATT&CK Techniques** — Plain-English breakdown of any technique ID with detection and mitigation guidance
- **IOC Reputation Checks** — Queries VirusTotal for IP, domain, and file hash reputation
- **AI-Powered Analyst Briefs** — LLM formats raw API data into structured, actionable security reports

## Tech Stack
- **Language:** Python 3.10+
- **UI:** Streamlit
- **AI:** Anthropic Claude API (claude-haiku-4-5)
- **Data Sources:** NVD · MITRE ATT&CK · CISA KEV · VirusTotal

## How It Works
```
User Query → Intent Detection → API Call → LLM Formatting → Analyst Brief
```

1. User asks a question in plain English
2. Regex-based intent detection identifies the query type (CVE, technique, threat actor, IOC)
3. The relevant API is called and raw data is retrieved
4. Data is passed to Claude with a structured prompt
5. Claude returns a formatted, actionable analyst brief

## Setup

1. Clone the repo
```bash
git clone https://github.com/Nouaman1945/threat-intel-chatbot.git
cd threat-intel-chatbot
```

2. Create and activate a virtual environment
```bash
python -m venv venv
venv\Scripts\activate        # Windows
source venv/bin/activate     # Mac/Linux
```

3. Install dependencies
```bash
pip install -r requirements.txt
```

4. Create a `.env` file with your API keys
```
ANTHROPIC_API_KEY=your_key_here
VT_API_KEY=your_virustotal_key_here
NVD_API_KEY=your_nvd_key_here
```

5. Run the app
```bash
streamlit run app.py
```

## Example Queries
- `Tell me about CVE-2026-22769`
- `Is CVE-2021-44228 being actively exploited?`
- `What do we know about APT29?`
- `Explain technique T1059.001`
- `What CVEs were added to CISA KEV recently?`

## Screenshots

### CVE Analysis with Active Exploitation Status
![CVE Lookup](screenshots/cve_dell_recoverpoint.png)

### Active Exploitation Check
![Active Exploitation](screenshots/cve_active_exploitation.png)

### Threat Actor Profiling
![Threat Actor](screenshots/apt29_profile.png)

### MITRE ATT&CK Technique Breakdown
![MITRE Technique](screenshots/t1059_powershell.png)

### Recent CISA KEV Additions
![KEV Feed](screenshots/kev_recent.png)

## Known Limitations
- Intent detection is regex-based, so rephrased versions of the same question may return similar responses
- No conversation memory between queries — each message is processed independently
- Threat actor detection is limited to a predefined list of known groups
- Free API tiers may cause rate limiting under heavy use

## Future Improvements
- Upgrade to RAG (Retrieval-Augmented Generation) for more accurate, grounded responses
- Add conversation memory so analysts can ask follow-up questions
- Expand threat actor coverage beyond the predefined list
- Add a daily threat briefing feature that summarizes the latest KEV additions automatically
- Build an IOC bulk upload feature for triage of multiple indicators at once

## Author
Built by Nouaman — Junior SOC Analyst portfolio project.
