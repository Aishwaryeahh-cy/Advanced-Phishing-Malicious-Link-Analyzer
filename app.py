import streamlit as st
import pandas as pd
from analyzer import URLAnalyzer, FileAnalyzer
import utils

# Page Setup
st.set_page_config(page_title="Threat Analyzer", page_icon="🛡️", layout="wide")

# Custom CSS for styling
st.markdown("""
<style>
    .main {
        background-color: #f8f9fa;
    }
    .stMetric {
        background-color: white;
        padding: 15px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .result-card {
        padding: 20px;
        border-radius: 10px;
        color: white;
        margin-bottom: 20px;
    }
</style>
""", unsafe_allow_html=True)

# Session State Initialization
if 'history' not in st.session_state:
    st.session_state.history = []

# Header
st.title("🛡️ Advanced Phishing & Malicious Link Analyzer")
st.markdown("Scan suspicious links and filenames before you click. Stay safe!")

# Layout Columns
col1, col2 = st.columns([2, 1])

with col1:
    st.subheader("🔍 Local Scan")
    scan_type = st.radio("Choose scan type:", ["URL / Link", "File Name"], horizontal=True)
    
    user_input = st.text_input(
        f"Enter {scan_type} below:", 
        placeholder="e.g., http://login-verify-account.tk or invoice.pdf.exe"
    )
    
    if st.button("Run Security Scan", type="primary"):
        if user_input:
            with st.spinner("Analyzing threat vectors..."):
                if scan_type == "URL / Link":
                    result = URLAnalyzer().analyze(user_input)
                else:
                    result = FileAnalyzer().analyze(user_input)
                
                # Add to history
                result['input'] = user_input
                st.session_state.history.insert(0, result)
                
                # Display Results
                st.divider()
                
                m1, m2 = st.columns(2)
                config = utils.RISK_CONFIG[result['level']]
                
                m1.metric("Threat Level", f"{config['emoji']} {result['level']}")
                m2.metric("Security Score", f"{result['score']}/100", delta="-Risk" if result['score'] > 0 else "Safe")
                
                if result['level'] == "HIGH":
                    st.error("### 🔴 CRITICAL THREAT DETECTED")
                elif result['level'] == "MEDIUM":
                    st.warning("### 🟡 POTENTIAL THREAT DETECTED")
                else:
                    st.success("### 🟢 LOW RISK DETECTED")
                
                with st.expander("📝 Detailed Risk Factors (Why this score?)", expanded=True):
                    if not result['factors']:
                        st.write("No major phishing or malware indicators found.")
                    else:
                        for factor in result['factors']:
                            st.write(f"- {factor['msg']} (Impact: +{factor['impact']})")
        else:
            st.warning("Please enter something to scan.")

with col2:
    st.subheader("📜 Scan History")
    if not st.session_state.history:
        st.info("No scans performed yet.")
    else:
        history_df = pd.DataFrame([
            {
                "Target": h['input'],
                "Type": h['type'],
                "Level": h['level'],
                "Score": h['score']
            } for h in st.session_state.history
        ])
        st.dataframe(history_df, hide_index=True, use_container_width=True)
        if st.button("Clear History"):
            st.session_state.history = []
            st.rerun()

# Footer / Education
st.divider()
st.markdown("### 🛠️ How it works")
c1, c2, c3 = st.columns(3)
with c1:
    st.info("**URL Analysis**  \nScans for IP addresses, suspicious TLDs, shorteners, and keyword spoofing used in phishing.")
with c2:
    st.info("**File Check**  \nDetects dangerous extensions and double-extension masking (e.g. .pdf.exe).")
with c3:
    st.info("**Heuristic Scoring**  \nCombines multiple risk factors into a unified security score from 0 to 100.")
