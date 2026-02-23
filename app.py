import streamlit as st
from chatbot import process_message

# Page config
st.set_page_config(
    page_title="Threat Intel Chatbot",
    page_icon="🛡️",
    layout="centered"
)

st.title("🛡️ Threat Intelligence Chatbot")
st.caption("Query CVEs, MITRE ATT&CK techniques, threat actors, and IOCs in plain English.")

# Sidebar with example queries
with st.sidebar:
    st.header("Example Queries")
    examples = [
        "Tell me about CVE-2021-44228",
        "What TTPs does APT29 use?",
        "Explain technique T1059.001",
        "Check IP 185.220.101.45",
        "What CVEs were added to CISA KEV recently?",
        "Is CVE-2023-23397 being actively exploited?",
    ]
    for example in examples:
        if st.button(example, use_container_width=True):
            st.session_state.pending_input = example

    st.divider()
    st.caption("Data sources: NVD · MITRE ATT&CK · CISA KEV · VirusTotal")

# Initialize chat history
if "messages" not in st.session_state:
    st.session_state.messages = []

# Display chat history
for msg in st.session_state.messages:
    with st.chat_message(msg["role"]):
        st.markdown(msg["content"])

# Handle example button clicks
if "pending_input" in st.session_state:
    user_input = st.session_state.pop("pending_input")
else:
    user_input = st.chat_input("Ask about a CVE, threat actor, technique, or IOC...")

# Process input
if user_input:
    # Show user message
    st.session_state.messages.append({"role": "user", "content": user_input})
    with st.chat_message("user"):
        st.markdown(user_input)

    # Generate and show response
    with st.chat_message("assistant"):
        with st.spinner("Querying threat intelligence sources..."):
            response = process_message(user_input)
        st.markdown(response)

    st.session_state.messages.append({"role": "assistant", "content": response})