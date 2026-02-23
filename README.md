# 🛡️ Threat Intelligence Chatbot

A SOC analyst assistant that queries threat intelligence 
sources in plain English using AI.

## Features
- CVE lookup via NVD with CVSS scoring
- CISA KEV cross-reference for active exploitation status
- MITRE ATT&CK technique and threat actor profiling
- IOC reputation checks via VirusTotal
- AI-powered plain-English analyst briefs

## Tech Stack
- Python, Streamlit, Anthropic Claude API
- Data sources: NVD, MITRE ATT&CK, CISA KEV, VirusTotal

## Setup
1. Clone the repo
2. Create a virtual environment and install dependencies
   pip install -r requirements.txt
3. Create a .env file with your API keys
   ANTHROPIC_API_KEY=your_key
   VT_API_KEY=your_key
4. Run the app
   streamlit run app.py

## Example Queries
- "Tell me about CVE-2021-44228"
- "What TTPs does APT29 use?"
- "Explain technique T1059.001"
- "What CVEs were added to CISA KEV recently?"
