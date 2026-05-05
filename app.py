import os
import json
import streamlit as st
from dotenv import load_dotenv
from scanners.triage_engine import TriageEngine

load_dotenv()

@st.cache_resource
def get_triage_engine():
    return TriageEngine()

triage_engine = get_triage_engine()

# --- STATEFUL WORKFLOW CONTROLLER ---
# This acts as the "notepad" so the app remembers what step you are on!
if "workflow_step" not in st.session_state:
    st.session_state.workflow_step = "IDLE"
if "scan_result" not in st.session_state:
    st.session_state.scan_result = None

# --- UI SETUP ---
st.set_page_config(page_title="Guardian OS", page_icon="🛡️", layout="wide")

st.sidebar.title("Guardian OS")
st.sidebar.markdown("*Operations-First AI Governance*")
st.sidebar.divider()

page = st.sidebar.radio("Navigation", ["Dashboard Overview", "Process Injection (Teams)"])

# --- PAGE: PROCESS INJECTION (THE REAL WORKFLOW) ---
if page == "Process Injection (Teams)":
    st.title("💬 Real-World Process Injection")
    st.markdown("Watch the actual workflow state change as human interactions trigger database commands.")
    
    alert_text = st.text_input("Enter Data to Scan", "Database log containing Medicare Number: 4123 45678 1")
    
    # STEP 1: TRIGGER SCAN
    if st.session_state.workflow_step == "IDLE":
        if st.button("🚀 Trigger Operations Scan", width='stretch'):
            with st.spinner("Phi-4 is processing..."):
                # Run the actual day 2 script
                st.session_state.scan_result = triage_engine.triage_record({"notes": alert_text}, ["Medicare"])
                
                # UPDATE THE STATE
                st.session_state.workflow_step = "WAITING_FOR_HUMAN"
                st.rerun() # Forces Streamlit to remember the new step!

    # STEP 2: HUMAN-IN-THE-LOOP GATE
    elif st.session_state.workflow_step == "WAITING_FOR_HUMAN":
        st.warning("🚨 ACTION REQUIRED: AI detected high-risk PII and is waiting for your command.")
        
        # Render the Teams Card
        with st.container(border=True):
            st.markdown(f"""
            **🛡️ Guardian AI Bot** &nbsp;&nbsp;&nbsp;&nbsp;&nbsp; *Just Now*
            
            **Record Flagged:** `{alert_text}`
            
            **AI Assessment:** {st.session_state.scan_result.get('explanation')}
            
            ---
            **Click an option below to authorize action:**
            """)
            
            col1, col2 = st.columns(2)
            with col1:
                if st.button("🔒 Quarantine Record", width='stretch'):
                    st.session_state.workflow_step = "QUARANTINED"
                    st.rerun()
            with col2:
                if st.button("📝 Ignore (False Positive)", width='stretch'):
                    st.session_state.workflow_step = "IGNORED"
                    st.rerun()

    # STEP 3: WORKFLOW COMPLETION
    elif st.session_state.workflow_step == "QUARANTINED":
        st.success("🏁 Workflow Completed: The database record has been isolated in the secure vault.")
        if st.button("Start New Scan"):
            st.session_state.workflow_step = "IDLE"
            st.rerun()
            
    elif st.session_state.workflow_step == "IGNORED":
        st.info("🏁 Workflow Completed: Flag suppressed. No data was moved.")
        if st.button("Start New Scan"):
            st.session_state.workflow_step = "IDLE"
            st.rerun()

# --- OTHER PAGES ---
else:
    st.title("📊 Dashboard")
    st.markdown("Switch to the 'Process Injection' tab to see the live workflow!")
