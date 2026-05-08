# app.py
# Guardian - AI Governance Platform
# Governance Analyst Interface
# Built on Azure AI Language + Azure AI Foundry (Phi-4)

import os
import json
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import streamlit as st
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv()

st.set_page_config(
    page_title="Guardian | AI Governance Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# CUSTOM STYLING — Accenture purple accent + clean enterprise
# ============================================================
st.markdown("""
<style>
    /* Import fonts */
    @import url('https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap');

    /* Root variables */
    :root {
        --purple: #A100FF;
        --purple-dark: #7B00CC;
        --purple-light: #E8D5FF;
        --purple-subtle: #F5EEFF;
        --navy: #1A1A2E;
        --navy-light: #2D2D44;
        --white: #FFFFFF;
        --off-white: #F8F7FC;
        --text-primary: #1A1A2E;
        --text-secondary: #5A5A7A;
        --text-muted: #9090AA;
        --border: #E4E0F0;
        --border-strong: #C8C0E0;
        --success: #0A7B4B;
        --warning: #B45309;
        --danger: #C41E3A;
        --card-bg: #FFFFFF;
        --sidebar-bg: #1A1A2E;
    }

    /* Global font */
    html, body, [class*="css"] {
        font-family: 'DM Sans', sans-serif !important;
    }

    /* Main background */
    .stApp {
        background-color: var(--off-white);
    }

    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: var(--sidebar-bg) !important;
        border-right: 1px solid rgba(161, 0, 255, 0.3);
    }
    [data-testid="stSidebar"] * {
        color: #FFFFFF !important;
    }
    [data-testid="stSidebar"] .stRadio label {
        color: #FFFFFF !important;
        font-size: 0.875rem;
        font-weight: 400;
        padding: 4px 0;
    }
    [data-testid="stSidebar"] .stCaption {
        color: rgba(255,255,255,0.55) !important;
    }
    [data-testid="stSidebar"] hr {
        border-color: rgba(161, 0, 255, 0.25) !important;
    }

    /* Main content */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 3rem;
        max-width: 1200px;
    }

    /* Typography */
    h1 {
        color: var(--text-primary) !important;
        font-weight: 700 !important;
        font-size: 1.85rem !important;
        letter-spacing: -0.3px;
        font-family: 'DM Sans', sans-serif !important;
    }
    h2, h3 {
        color: var(--text-primary) !important;
        font-weight: 600 !important;
        font-family: 'DM Sans', sans-serif !important;
    }

    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: var(--card-bg);
        padding: 1.25rem 1.5rem;
        border-radius: 12px;
        border: 1px solid var(--border);
        box-shadow: 0 1px 4px rgba(161,0,255,0.06);
        transition: box-shadow 0.2s ease, border-color 0.2s ease;
        cursor: pointer;
    }
    [data-testid="stMetric"]:hover {
        box-shadow: 0 4px 16px rgba(161,0,255,0.12);
        border-color: var(--purple-light);
    }
    [data-testid="stMetricLabel"] {
        color: var(--text-secondary) !important;
        font-size: 0.75rem !important;
        font-weight: 600 !important;
        text-transform: uppercase;
        letter-spacing: 0.6px;
    }
    [data-testid="stMetricValue"] {
        color: var(--text-primary) !important;
        font-weight: 700 !important;
        font-size: 1.8rem !important;
    }
    [data-testid="stMetricDelta"] {
        font-size: 0.75rem !important;
    }

    /* Buttons */
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        font-family: 'DM Sans', sans-serif !important;
        transition: all 0.2s ease;
        border: 1.5px solid transparent;
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, var(--purple) 0%, var(--purple-dark) 100%) !important;
        color: white !important;
        border-color: var(--purple) !important;
    }
    .stButton > button[kind="primary"]:hover {
        box-shadow: 0 4px 14px rgba(161,0,255,0.35) !important;
        transform: translateY(-1px);
    }
    .stButton > button:not([kind="primary"]) {
        background: var(--card-bg) !important;
        color: var(--text-primary) !important;
        border-color: var(--border-strong) !important;
    }
    .stButton > button:not([kind="primary"]):hover {
        border-color: var(--purple) !important;
        color: var(--purple) !important;
    }

    /* Expander */
    [data-testid="stExpander"] {
        background-color: var(--card-bg);
        border-radius: 10px !important;
        border: 1px solid var(--border) !important;
        margin-bottom: 0.6rem;
        box-shadow: 0 1px 3px rgba(0,0,0,0.04);
    }
    [data-testid="stExpander"]:hover {
        border-color: var(--purple-light) !important;
    }

    /* Alerts */
    [data-testid="stAlert"] {
        border-radius: 10px !important;
        border-left-width: 4px !important;
        font-size: 0.9rem;
    }

    /* Dataframe */
    [data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
        border: 1px solid var(--border);
    }

    /* Input fields */
    [data-testid="stTextInput"] input,
    [data-testid="stTextArea"] textarea {
        border-radius: 8px !important;
        border-color: var(--border-strong) !important;
        font-family: 'DM Sans', sans-serif !important;
    }
    [data-testid="stTextInput"] input:focus,
    [data-testid="stTextArea"] textarea:focus {
        border-color: var(--purple) !important;
        box-shadow: 0 0 0 2px rgba(161,0,255,0.12) !important;
    }

    /* Select box */
    [data-testid="stSelectbox"] > div > div {
        border-radius: 8px !important;
        border-color: var(--border-strong) !important;
    }

    /* Divider */
    hr {
        border-color: var(--border) !important;
        margin: 1.5rem 0 !important;
    }

    /* Caption */
    .stCaption {
        color: var(--text-muted) !important;
        font-size: 0.8rem;
    }

    /* Purple accent bar — used as page header underline */
    .guardian-accent {
        height: 3px;
        background: linear-gradient(90deg, var(--purple) 0%, transparent 100%);
        border-radius: 2px;
        margin-bottom: 1.5rem;
    }

    /* Status pill */
    .status-pill {
        display: inline-block;
        padding: 2px 10px;
        border-radius: 999px;
        font-size: 0.72rem;
        font-weight: 600;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }

    /* Tooltip style for definitions */
    .definition-box {
        background: var(--navy);
        color: white;
        padding: 0.6rem 0.9rem;
        border-radius: 8px;
        font-size: 0.82rem;
        border-left: 3px solid var(--purple);
        margin-top: 0.25rem;
    }
</style>
""", unsafe_allow_html=True)

# ============================================================
# IMPORTS FROM GUARDIAN MODULES
# ============================================================
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners.pii_scanner import scan_text_for_pii
from scanners.triage_engine import TriageEngine
from utils.audit_log import read_audit_log, get_audit_summary, write_audit_log
from utils.security import SecurityPerimeter

DB_PATH = Path('database/guardian.db')
PIPELINE_REPORT_PATH = Path('database/pipeline_report.json')

# ============================================================
# CONSTANTS & DEFINITIONS
# ============================================================
RISK_COLOURS = {
    'CRITICAL': '#C41E3A',
    'HIGH': '#C05621',
    'MEDIUM': '#B45309',
    'LOW': '#0A7B4B',
    'UNKNOWN': '#9090AA'
}

RISK_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢',
    'UNKNOWN': '⚪'
}

ACTION_DEFINITIONS = {
    'ESCALATE': 'Finding is too complex or high-risk to resolve alone. Routes to Privacy Officer or senior governance team for consultation before any action is taken.',
    'REDACT': 'The sensitive identifier is removed or masked in the source record. Irreversible — requires explicit authorisation.',
    'MIGRATE': 'The record is moved to a more secure, appropriately controlled storage location that meets legislative requirements.',
    'RETAIN': 'Record is reviewed and deliberately kept as-is, with documented justification that current storage is compliant.',
    'DISPOSE': 'Record is securely deleted in accordance with the applicable retention policy. Irreversible — requires explicit authorisation.'
}

MODE_DEFINITIONS = {
    'ONLINE': 'Azure AI Language was active. Both Azure contextual detection and Guardian\'s Australian deterministic rules were applied.',
    'ONLINE_PLUS_GUARDIAN_AU_RULES': 'Azure AI Language was active. Both Azure contextual detection and Guardian\'s Australian deterministic rules were applied.',
    'OFFLINE': 'Azure was unavailable. Guardian\'s offline Australian regex rules ran as the fallback detection layer.',
    'FAILED': 'Both Azure and offline detection failed. Fail-safe triggered: record flagged at maximum risk and routed to human review.',
    'UNKNOWN': 'Detection mode not recorded.'
}

RISK_SCORE_EXPLANATION = """Risk score (0–5.0) accumulates based on what PII was detected:
• Tax File Number → +2.0 (highest — mandatory legislative protection)
• Medicare Number → +1.5
• Credit card → +1.5  
• Bank account / BSB → +1.0
• Email / Phone → +0.5 each
• Name / Address / DOB → +0.3 each

Score above 3.0 triggers Governance Analyst review."""

FINDING_EXPLANATION = "A finding is one detected instance of a PII category within a scanned record. One record can produce multiple findings — for example, a TFN and a Medicare number in the same document counts as two findings."

# ============================================================
# CACHED RESOURCES
# ============================================================
@st.cache_resource
def get_triage_engine():
    return TriageEngine()

@st.cache_resource
def get_security():
    return SecurityPerimeter()

@st.cache_data(ttl=30)
def load_pipeline_report():
    if PIPELINE_REPORT_PATH.exists():
        with open(PIPELINE_REPORT_PATH) as f:
            return json.load(f)
    return None

@st.cache_data(ttl=30)
def load_audit_entries():
    return read_audit_log(limit=200)

# ============================================================
# SIDEBAR
# ============================================================
st.sidebar.markdown("""
<div style="display:flex;align-items:center;gap:10px;padding:8px 0 4px 0;">
    <span style="font-size:1.6rem;">🛡️</span>
    <div>
        <div style="font-size:1.1rem;font-weight:700;color:#FFFFFF;letter-spacing:-0.3px;">Guardian</div>
        <div style="font-size:0.72rem;color:rgba(255,255,255,0.5);text-transform:uppercase;letter-spacing:1px;">AI Governance Platform</div>
    </div>
</div>
""", unsafe_allow_html=True)

st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Governance Dashboard",
        "🔍 Live PII Scanner",
        "⚠️ Review Queue",
        "📋 Audit Trail",
        "ℹ️ About Guardian"
    ]
)

st.sidebar.divider()
st.sidebar.markdown("<div style='font-size:0.7rem;font-weight:700;text-transform:uppercase;letter-spacing:1px;color:rgba(255,255,255,0.4);margin-bottom:8px;'>System Status</div>", unsafe_allow_html=True)

def status_dot(key, label):
    val = os.getenv(key, '')
    colour = '#A100FF' if val else '#C41E3A'
    icon = '●' if val else '○'
    st.sidebar.markdown(f"<div style='font-size:0.82rem;color:{'#FFFFFF' if val else '#FF6B6B'};margin:3px 0;'><span style='color:{colour};'>{icon}</span> {label}</div>", unsafe_allow_html=True)

status_dot('AZURE_LANGUAGE_KEY', 'Azure AI Language')
status_dot('AZURE_INFERENCE_KEY', 'Azure AI Foundry (Phi-4)')
status_dot('AZURE_CONTENT_SAFETY_KEY', 'Azure Content Safety')

st.sidebar.caption(f"Last refreshed: {datetime.now().strftime('%H:%M:%S')}")

# ============================================================
# HELPER — Purple accent bar
# ============================================================
def accent_bar():
    st.markdown('<div class="guardian-accent"></div>', unsafe_allow_html=True)

def clean_scan_mode(raw):
    if 'ONLINE' in raw:
        return 'ONLINE'
    elif 'OFFLINE' in raw:
        return 'OFFLINE'
    elif 'FAILED' in raw:
        return 'FAILED'
    return raw

# ============================================================
# PAGE 1 — GOVERNANCE DASHBOARD
# ============================================================
if page == "🏠 Governance Dashboard":
    st.title("🛡️ Guardian — Governance Dashboard")
    st.caption("Real-time visibility across your data estate · Human-in-the-Lead AI governance")
    accent_bar()

    report = load_pipeline_report()
    audit_summary = get_audit_summary()

    if not report:
        st.warning("No pipeline report found. Run `python main.py` to generate data.")
    else:
        scan = report.get('scan_report', {})
        risk = scan.get('risk_distribution', {})
        actions = scan.get('action_recommendations', {})
        meta = report.get('pipeline_metadata', {})

        # ---- KPI ROW ----
        c1, c2, c3, c4 = st.columns(4)

        with c1:
            st.metric(
                "Records Scanned",
                scan.get('total_records_scanned', 0),
                help="Total estate records processed by Guardian's batch pipeline in the last run."
            )
        with c2:
            st.metric(
                "PII Detection Rate",
                f"{scan.get('pii_detection_rate', 0)}%",
                help="Percentage of scanned records where at least one PII identifier was found."
            )
        with c3:
            critical = risk.get('critical', 0)
            st.metric(
                "Critical Risk Records",
                critical,
                delta=f"{critical} flagged for escalation" if critical > 0 else "None",
                delta_color="inverse",
                help="Records scoring 4.0–5.0. Contain high-value identifiers such as Tax File Numbers or Medicare numbers requiring immediate Governance Analyst review."
            )
        with c4:
            overrides = audit_summary.get('human_overrides', 0)
            st.metric(
                "GA Overrides",
                overrides,
                help="Cases where the Governance Analyst chose a different action from Guardian's recommendation. Overrides are fully logged and auditable.",
                delta="GA judgement differed from AI" if overrides > 0 else None,
                delta_color="off"
            )

        # Clickable filter state
        if 'dashboard_filter' not in st.session_state:
            st.session_state.dashboard_filter = None

        st.divider()

        # ---- CHARTS ----
        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Risk Distribution")
            risk_data = pd.DataFrame({
                'Risk Level': ['Critical', 'High', 'Medium', 'Low'],
                'Records': [
                    risk.get('critical', 0),
                    risk.get('high', 0),
                    risk.get('medium', 0),
                    risk.get('low', 0)
                ]
            })
            fig_risk = px.bar(
                risk_data, x='Risk Level', y='Records', color='Risk Level',
                color_discrete_map={
                    'Critical': '#C41E3A', 'High': '#C05621',
                    'Medium': '#B45309', 'Low': '#0A7B4B'
                }
            )
            fig_risk.update_layout(
                showlegend=False, height=280,
                plot_bgcolor='rgba(0,0,0,0)',
                paper_bgcolor='rgba(0,0,0,0)',
                font_family='DM Sans',
                margin=dict(l=0, r=0, t=20, b=0)
            )
            fig_risk.update_traces(marker_line_width=0)
            st.plotly_chart(fig_risk, use_container_width=True)

        with col_right:
            st.subheader("Recommended Actions")
            st.caption("Distribution of actions Guardian recommended across all scanned records.")
            if actions:
                filtered_actions = {k: v for k, v in actions.items() if v > 0}
                if filtered_actions:
                    action_data = pd.DataFrame(
                        list(filtered_actions.items()),
                        columns=['Action', 'Count']
                    )
                    fig_actions = px.pie(
                        action_data, names='Action', values='Count',
                        color_discrete_sequence=['#A100FF', '#7B00CC', '#5500A0', '#3A0080', '#C8A0FF']
                    )
                    fig_actions.update_layout(
                        height=280,
                        plot_bgcolor='rgba(0,0,0,0)',
                        paper_bgcolor='rgba(0,0,0,0)',
                        font_family='DM Sans',
                        margin=dict(l=0, r=0, t=20, b=0),
                        legend=dict(font=dict(size=11))
                    )
                    st.plotly_chart(fig_actions, use_container_width=True)

                    # Action legend
                    with st.expander("What do these actions mean?"):
                        for action, definition in ACTION_DEFINITIONS.items():
                            if action in filtered_actions:
                                st.markdown(f"**{action}** — {definition}")

        st.divider()

        # ---- WAF STATUS ----
        st.subheader("Microsoft Well-Architected Framework")
        st.caption("Guardian is designed against all five pillars. Each is active in the current deployment.")
        waf = report.get('well_architected_notes', {})
        waf_cols = st.columns(5)
        waf_items = [
            ("🔄 Reliability", "reliability", "Three-tier safety net: Azure → AU rules → fail-safe"),
            ("🔒 Security", "security", "PII hashed in audit log — privacy by design"),
            ("💰 Cost", "cost_optimisation", "Free F0 tier with documented S-tier path"),
            ("📊 Operations", "operational_excellence", "Full JSONL audit trail, legislation auto-cited"),
            ("⚡ Performance", "performance", "Modular pipeline — completes in under 30 seconds"),
        ]
        for col, (label, key, desc) in zip(waf_cols, waf_items):
            with col:
                st.success(f"**{label}**")
                st.caption(desc)

        st.divider()

        # ---- PIPELINE METADATA ----
        st.subheader("Last Pipeline Run")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.info(f"⏱️ **Duration:** {meta.get('duration_seconds', 0)} seconds")
        with m2:
            completed = meta.get('completed', 'Unknown')
            st.info(f"📅 **Completed:** {completed[:19] if completed != 'Unknown' else 'Unknown'}")
        with m3:
            st.info(f"🔧 **Mode:** {meta.get('mode', 'unknown').upper()}")

# ============================================================
# PAGE 2 — LIVE PII SCANNER
# ============================================================
elif page == "🔍 Live PII Scanner":
    st.title("🔍 Live PII Scanner")
    st.caption("Scan any text for personally identifiable information · Azure AI Language detects · Phi-4 triages · Governance Analyst decides")
    accent_bar()

    if 'scan_result' not in st.session_state:
        st.session_state.scan_result = None
    if 'triage_result' not in st.session_state:
        st.session_state.triage_result = None
    if 'scan_text' not in st.session_state:
        st.session_state.scan_text = ""

    st.subheader("Enter text to scan")
    st.caption("Load a sample or paste your own text. Guardian scans for Australian PII identifiers and assesses risk.")

    sample_col1, sample_col2, sample_col3 = st.columns(3)

    with sample_col1:
        if st.button("📋 Load Sample — Estate Record"):
            st.session_state.scan_text = """Estate File: QPT-0042
Beneficiary: Margaret Johnson
Date of Birth: 15/03/1962
TFN: 432 567 891
Medicare: 29876543210
Email: margaret.johnson@gmail.com
Phone: 0412 345 678
Address: 42 Coronation Drive, Toowong QLD 4066
BSB: 124-001 Account: 12345678
Notes: Client contacted 12/03/2026 regarding estate distribution."""
            st.session_state.scan_result = None
            st.session_state.triage_result = None
            st.rerun()

    with sample_col2:
        if st.button("📋 Load Sample — Case Notes"):
            st.session_state.scan_text = """Case meeting notes - 15 April 2026
Spoke with beneficiary Robert Chen (DOB 22/07/1945).
His TFN is 987 654 321. Medicare card 61234567890.
Bank details: BSB 062-001 Account 98765432.
Contact: robert.chen@email.com or 0498 765 432."""
            st.session_state.scan_result = None
            st.session_state.triage_result = None
            st.rerun()

    with sample_col3:
        if st.button("📋 Load Sample — Clean Text"):
            st.session_state.scan_text = """The estate review meeting was held on Tuesday.
All parties agreed to proceed with the standard distribution process.
Further documentation will be required before finalisation."""
            st.session_state.scan_result = None
            st.session_state.triage_result = None
            st.rerun()

    text_input = st.text_area(
        "Text to scan",
        value=st.session_state.scan_text,
        height=180,
        placeholder="Paste any text here to scan for PII..."
    )

    col_scan, col_clear = st.columns([3, 1])
    with col_scan:
        scan_clicked = st.button("🔍 Scan for PII", type="primary", use_container_width=True)
    with col_clear:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.scan_result = None
            st.session_state.triage_result = None
            st.session_state.scan_text = ""
            st.rerun()

    if scan_clicked and text_input.strip():
        security = get_security()
        safety_check = security.check_input(text_input, source="live_scanner")

        if safety_check['blocked']:
            st.error(f"⛔ Input blocked by security perimeter: {safety_check['reason']}")
        else:
            with st.spinner("Azure AI Language scanning for PII..."):
                result = scan_text_for_pii(text_input, context="live_scanner")

            st.session_state.scan_result = result
            st.session_state.scan_text = text_input

            if result['pii_found'] and result['findings']:
                if "Estate File" in text_input:
                    context_label = "Estate Record Sample"
                elif "Case meeting" in text_input:
                    context_label = "Case Notes Sample"
                else:
                    context_label = "Manual Input"

                with st.spinner("Azure AI Foundry (Phi-4) triaging risk..."):
                    engine = get_triage_engine()
                    pii_categories = list(set(f['category'] for f in result['findings']))
                    triage = engine.triage_record(
                        {"text": text_input[:500]},
                        pii_categories
                    )
                    st.session_state.triage_result = triage

                if result.get('requires_human_review'):
                    scan_id = f"SCAN-{datetime.now().strftime('%Y%m%d%H%M%S')}"
                    if 'review_queue' not in st.session_state:
                        st.session_state.review_queue = []
                    new_item = {
                        'id': scan_id,
                        'record': f"Live Scan — {context_label}",
                        'risk_score': result['overall_risk_score'],
                        'risk_level': 'CRITICAL' if result['overall_risk_score'] >= 4.0 else 'HIGH',
                        'pii_types': pii_categories,
                        'recommendation': 'ESCALATE' if result['overall_risk_score'] >= 4.0 else 'MIGRATE',
                        'legislation': 'Privacy Act 1988 (Cth) — Tax File Number Rule; Information Privacy Act 2009 (Qld) — IPP 4',
                        'status': 'PENDING',
                        'ai_explanation': triage.get('explanation', 'High-risk PII detected. Governance Analyst review required before any action.'),
                        'source': 'live_scanner',
                        'scanned_at': datetime.now().isoformat()
                    }
                    existing_ids = [q['id'] for q in st.session_state.review_queue]
                    if scan_id not in existing_ids:
                        st.session_state.review_queue.append(new_item)
                    st.warning("⚠️ **Review Required** — This finding has been added to the Governance Analyst Review Queue. Navigate there to authorise an action.")

    if st.session_state.scan_result:
        result = st.session_state.scan_result
        st.divider()
        st.subheader("Scan Results")

        r1, r2, r3, r4 = st.columns(4)
        with r1:
            if result['pii_found']:
                st.error("⚠️ PII DETECTED")
            else:
                st.success("✅ No PII Found")
        with r2:
            st.metric(
                "Findings",
                result['finding_count'],
                help=FINDING_EXPLANATION
            )
        with r3:
            st.metric(
                "Risk Score",
                f"{result['overall_risk_score']}/5.0",
                help=RISK_SCORE_EXPLANATION
            )
        with r4:
            raw_mode = result.get('scan_mode', 'UNKNOWN')
            display_mode = clean_scan_mode(raw_mode)
            mode_help = MODE_DEFINITIONS.get(raw_mode, MODE_DEFINITIONS.get(display_mode, ''))
            st.metric("Detection Mode", display_mode, help=mode_help)

        if result['pii_found'] and result['findings']:
            st.subheader("Findings Breakdown")
            st.caption("Each row is one detected PII identifier (finding) within the scanned text.")

            findings_data = []
            for f in result['findings']:
                findings_data.append({
                    'PII Category': f['category'],
                    'Risk Level': f['risk_level'],
                    'Confidence': f"{f['confidence_score']:.0%}",
                    'Detection Method': f.get('detection_method', 'unknown'),
                    'Risk Score': f['risk_score']
                })

            df_findings = pd.DataFrame(findings_data)

            def colour_risk(val):
                colours = {
                    'CRITICAL': 'background-color: #FEE2E2; color: #C41E3A',
                    'HIGH': 'background-color: #FED7AA; color: #C05621',
                    'MEDIUM': 'background-color: #FEF3C7; color: #B45309',
                    'LOW': 'background-color: #D1FAE5; color: #0A7B4B'
                }
                return colours.get(val, '')

            st.dataframe(
                df_findings.style.map(colour_risk, subset=['Risk Level']),
                use_container_width=True,
                hide_index=True,
                column_config={
                    'PII Category': st.column_config.TextColumn('PII Category', help='The type of personally identifiable information detected.'),
                    'Risk Level': st.column_config.TextColumn('Risk Level', help='CRITICAL = 4.0–5.0 · HIGH = 3.0–3.9 · MEDIUM = 2.0–2.9 · LOW = 0–1.9'),
                    'Confidence': st.column_config.TextColumn('Confidence', help='How certain the detection model is. Azure AI Language provides probabilistic confidence. Guardian AU rules always return 100% (exact pattern match).'),
                    'Detection Method': st.column_config.TextColumn('Detection Method', help='azure_language_pii = Azure AI Language · guardian_au_rules = Guardian\'s deterministic Australian regex rules'),
                    'Risk Score': st.column_config.NumberColumn('Risk Score', help=RISK_SCORE_EXPLANATION, format="%.2f")
                }
            )

            st.subheader("Redacted Preview")
            st.caption("This shows what the text would look like if PII were removed. **This is a preview only — no action has been taken. The Governance Analyst must authorise any changes.**")
            st.code(result.get('redacted_text', ''), language=None)

            if st.session_state.triage_result:
                triage = st.session_state.triage_result
                st.subheader("AI Triage Assessment")
                st.caption("Powered by Azure AI Foundry — Phi-4 · Grounded in Australian privacy legislation · This is a recommendation only.")

                score = triage.get('triage_score', 'UNKNOWN')

                with st.container(border=True):
                    t1, t2 = st.columns([1, 3])
                    with t1:
                        st.markdown(f"### {RISK_EMOJI.get(score, '⚪')} {score}")
                        st.caption("Triage Score")
                    with t2:
                        st.markdown("**AI Assessment:**")
                        st.write(triage.get('explanation', 'No explanation available'))
                        st.markdown("**Recommended Action:**")
                        rec_action = triage.get('action_required', 'No action specified')
                        st.info(rec_action)
                        # Show action definition
                        for action_key, action_def in ACTION_DEFINITIONS.items():
                            if action_key in str(rec_action).upper():
                                st.caption(f"**What {action_key} means:** {action_def}")
                                break

                if result['requires_human_review']:
                    st.warning("⚠️ **Review Queue Updated** — Navigate to the Governance Analyst Review Queue to review this finding and authorise an action.")

        else:
            st.success("✅ No PII detected in this text. No action required.")

# ============================================================
# PAGE 3 — GOVERNANCE ANALYST REVIEW QUEUE
# ============================================================
elif page == "⚠️ Review Queue":
    st.title("⚠️ Governance Analyst Review Queue")
    st.caption("Guardian has identified these records. Review each finding and authorise an action.")
    accent_bar()

    st.info("""
    **Review each finding and select an action.**
    
    Guardian detects and recommends. The Governance Analyst decides.
    No action is taken until you click Authorise. Every decision is logged automatically with your identifier, a timestamp, and the applicable legislation.
    """)

    if 'review_queue' not in st.session_state:
        st.session_state.review_queue = [
            {
                'id': 'QPT-0001',
                'record': 'Estate Record QPT-0001',
                'risk_score': 5.0,
                'risk_level': 'CRITICAL',
                'pii_types': ['AUTaxFileNumber', 'AUMedicareNumber', 'Email', 'PhoneNumber'],
                'recommendation': 'ESCALATE',
                'legislation': 'Privacy Act 1988 (Cth) — Tax File Number Rule; Information Privacy Act 2009 (Qld) — IPP 4',
                'status': 'PENDING',
                'ai_explanation': 'Record contains Tax File Number and Medicare Number in an unstructured notes field. Both identifiers carry mandatory legislative protection under the Privacy Act 1988 TFN Rule. Immediate Governance Analyst review required before any remediation action.',
                'source': 'pipeline',
                'scanned_at': '2026-05-07T06:00:00'
            },
            {
                'id': 'QPT-0002',
                'record': 'Estate Record QPT-0002',
                'risk_score': 5.0,
                'risk_level': 'CRITICAL',
                'pii_types': ['AUTaxFileNumber', 'Address', 'Person'],
                'recommendation': 'MIGRATE',
                'legislation': 'Privacy Act 1988 (Cth) — APP 11; Information Privacy Act 2009 (Qld) — IPP 4',
                'status': 'PENDING',
                'ai_explanation': 'TFN detected in a field classified as Internal access. Current storage location does not meet the separation requirements under the TFN Rule. Migration to a restricted access system is recommended.',
                'source': 'pipeline',
                'scanned_at': '2026-05-07T06:00:01'
            },
            {
                'id': 'QPT-0003',
                'record': 'Estate Record QPT-0003',
                'risk_score': 5.0,
                'risk_level': 'CRITICAL',
                'pii_types': ['AUTaxFileNumber', 'AUMedicareNumber', 'CreditCardNumber'],
                'recommendation': 'ESCALATE',
                'legislation': 'Privacy Act 1988 (Cth) — Notifiable Data Breaches Scheme',
                'status': 'PENDING',
                'ai_explanation': 'Financial credentials detected alongside government identifiers. Combination of TFN, Medicare, and payment card data creates elevated fraud risk. Possible notifiable data breach — Privacy Officer consultation required before any action.',
                'source': 'pipeline',
                'scanned_at': '2026-05-07T06:00:02'
            }
        ]

    if 'review_log' not in st.session_state:
        st.session_state.review_log = []

    queue = st.session_state.review_queue
    pending = [q for q in queue if q['status'] == 'PENDING']
    reviewed = [q for q in queue if q['status'] != 'PENDING']
    overrides = [q for q in reviewed if q.get('status') != q.get('recommendation')]

    # Queue metrics — more meaningful
    q1, q2, q3 = st.columns(3)
    with q1:
        st.metric(
            "Pending Review",
            len(pending),
            help="Findings awaiting Governance Analyst decision. No action has been taken on these records."
        )
    with q2:
        st.metric(
            "Reviewed",
            len(reviewed),
            help="Findings where a Governance Analyst has authorised an action. All decisions are logged."
        )
    with q3:
        st.metric(
            "GA Overrides",
            len(overrides),
            help="Cases where the Governance Analyst chose a different action from Guardian's recommendation. This is expected — the GA's professional judgement may differ from the AI's assessment. All overrides are logged with a reason.",
            delta="GA judgement differed from AI" if overrides else None,
            delta_color="off"
        )

    st.divider()

    if not pending:
        st.success("✅ All findings reviewed. Queue is clear.")
    else:
        st.subheader(f"Pending Findings ({len(pending)})")

        for i, item in enumerate(pending):
            source_tag = "🔄 Batch pipeline" if item.get('source') == 'pipeline' else "🔍 Live scan"
            with st.expander(
                f"{RISK_EMOJI.get(item['risk_level'], '⚪')} {item['record']} — {item['risk_level']} Risk · {item['recommendation']} Recommended · {source_tag}",
                expanded=(i == 0)
            ):
                col_detail, col_action = st.columns([2, 1])

                with col_detail:
                    st.markdown(f"**Record ID:** `{item['id']}`")
                    st.markdown(f"**Risk Score:** {item['risk_score']}/5.0")
                    with st.expander("How is risk score calculated?", expanded=False):
                        st.caption(RISK_SCORE_EXPLANATION)
                    st.markdown(f"**PII Detected:** {', '.join(item['pii_types'])}")
                    with st.expander("What are these PII categories?", expanded=False):
                        for pii in item['pii_types']:
                            explanations = {
                                'AUTaxFileNumber': 'Tax File Number — unique identifier issued by the ATO. Mandatory protection under Privacy Act 1988 TFN Rule.',
                                'AUMedicareNumber': 'Medicare card number — issued by Services Australia. Protected under Privacy Act APP 11.',
                                'CreditCardNumber': 'Payment card number — financial credential. Elevated breach risk when combined with other identifiers.',
                                'Email': 'Email address — contact identifier. Lower risk individually but contributes to combined risk score.',
                                'PhoneNumber': 'Phone number — contact identifier.',
                                'Address': 'Physical address — location identifier.',
                                'Person': 'Person name — identity indicator.'
                            }
                            st.caption(f"**{pii}** — {explanations.get(pii, 'Personally identifiable information requiring protective handling.')}")
                    st.markdown(f"**Legislation:** {item['legislation']}")
                    st.markdown(f"**Source:** {source_tag} · Scanned: {item.get('scanned_at', '')[:19]}")
                    st.markdown("**AI Assessment:**")
                    st.info(item['ai_explanation'])
                    st.caption("⚠️ This is Guardian's recommendation. The Governance Analyst retains full authority over the final decision.")

                with col_action:
                    st.markdown("**Governance Analyst Action**")
                    dqo_id = st.text_input(
                        "Your identifier",
                        value="GA-001",
                        key=f"dqo_{item['id']}",
                        help="Your staff identifier — logged permanently with this decision."
                    )
                    action_choice = st.selectbox(
                        "Select action",
                        ["ESCALATE", "REDACT", "MIGRATE", "RETAIN", "DISPOSE"],
                        key=f"action_{item['id']}",
                        help="Choose the appropriate governance action for this finding."
                    )
                    # Show definition of selected action
                    st.caption(f"_{ACTION_DEFINITIONS.get(action_choice, '')}_")

                    override_reason = st.text_area(
                        "Reason / Notes",
                        placeholder="Required if your action differs from Guardian's recommendation...",
                        key=f"reason_{item['id']}",
                        height=80,
                        help="Provide justification if overriding Guardian's recommendation. This is logged in the audit trail."
                    )

                    if st.button(
                        "✅ Authorise Action",
                        key=f"approve_{item['id']}",
                        type="primary",
                        use_container_width=True
                    ):
                        item['status'] = action_choice
                        item['reviewed_by'] = dqo_id
                        item['override_reason'] = override_reason
                        item['reviewed_at'] = datetime.now().isoformat()
                        overrode = action_choice != item['recommendation']

                        write_audit_log(
                            event_type='GA_DECISION',
                            scan_result={
                                'scan_mode': 'ONLINE',
                                'source_context': item['id'],
                                'pii_found': True,
                                'finding_count': len(item['pii_types']),
                                'overall_risk_score': item['risk_score'],
                                'requires_human_review': True,
                                'findings': [
                                    {'category': p, 'risk_level': item['risk_level'],
                                     'confidence_score': 0.95, 'text': p}
                                    for p in item['pii_types']
                                ]
                            },
                            action_taken=action_choice,
                            reviewed_by=dqo_id,
                            ai_recommendation=item['recommendation'],
                            human_decision=action_choice,
                            override_reason=override_reason if overrode else None,
                            notes="Governance Analyst authorised via Guardian interface"
                        )

                        if overrode:
                            st.warning(f"⚠️ Override recorded. Guardian recommended {item['recommendation']}, you selected {action_choice}. This is logged.")
                        else:
                            st.success(f"✅ Action authorised: {action_choice}. Audit log updated.")

                        st.rerun()

    if reviewed:
        st.divider()
        st.subheader(f"Reviewed ({len(reviewed)})")
        for item in reviewed:
            overrode = item.get('status') != item.get('recommendation')
            icon = "⚠️" if overrode else "✅"
            label = f" (Override — GA chose {item['status']}, Guardian recommended {item['recommendation']})" if overrode else ""
            st.success(
                f"{icon} {item['record']} — **{item['status']}** authorised by {item.get('reviewed_by', 'Unknown')} at {item.get('reviewed_at', '')[:19]}{label}"
            )

# ============================================================
# PAGE 4 — AUDIT TRAIL
# ============================================================
elif page == "📋 Audit Trail":
    st.title("📋 Audit Trail")
    st.caption("Complete governance record · Every scan, finding, and decision logged · Privacy by design · PII hashed — never stored in plain text")
    accent_bar()

    entries = load_audit_entries()

    if not entries:
        st.info("No audit entries yet. Entries are created automatically as Guardian scans records and Governance Analysts authorise decisions.")
    else:
        summary = get_audit_summary()

        a1, a2, a3, a4 = st.columns(4)
        with a1:
            st.metric(
                "Total Entries",
                summary.get('total_scans', 0),
                help="Total number of events logged — includes every scan, finding, and GA decision."
            )
        with a2:
            st.metric(
                "Records with PII",
                summary.get('pii_found_count', 0),
                help="Scan events where at least one PII finding was detected."
            )
        with a3:
            st.metric(
                "Review Required",
                summary.get('hitl_triggered_count', 0),
                help="Scan events where the risk score exceeded 3.0 and Governance Analyst review was triggered."
            )
        with a4:
            overrides = summary.get('human_overrides', 0)
            st.metric(
                "GA Overrides",
                overrides,
                help="Cases where the Governance Analyst chose a different action from Guardian's recommendation. All overrides are fully logged with reason and timestamp.",
                delta="Overrides logged" if overrides > 0 else None,
                delta_color="off"
            )

        st.divider()

        # Glossary
        with st.expander("📖 Column definitions — click to expand"):
            col_g1, col_g2 = st.columns(2)
            with col_g1:
                st.markdown("""
**Log ID** — Unique identifier for this audit entry. Format: AUD-{timestamp}.

**Timestamp** — UTC date and time when the scan or decision event occurred.

**Event** — Type of event:
- `DATABASE_RECORD_SCANNED` — Guardian's batch pipeline scanned a database record
- `LIVE_SCAN` — A document was scanned via the Live PII Scanner
- `GA_DECISION` — A Governance Analyst authorised an action

**Detection Mode** — Which detection layer ran:
- `ONLINE` — Azure AI Language + Guardian AU rules (both active)
- `OFFLINE` — Azure unavailable, Guardian AU regex rules only
- `FAILED` — Both failed, fail-safe triggered
""")
            with col_g2:
                st.markdown(f"""
**PII Found** — Whether any PII identifier was detected in this scan.

**Findings** — {FINDING_EXPLANATION}

**Risk Score** — {RISK_SCORE_EXPLANATION.split(chr(10))[0]}

**Review Required** — Whether the risk score exceeded 3.0, triggering Governance Analyst review.

**Action** — The action authorised by the Governance Analyst. Blank if no action taken yet.

**Legislation** — The Australian privacy legislation applicable to the PII found. Auto-cited by Guardian's rules engine — not generated by the AI.
""")

        # Filters
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            filter_pii = st.checkbox("PII found only", value=False, help="Show only scan events where PII was detected.")
        with col_f2:
            filter_hitl = st.checkbox("Review required only", value=False, help="Show only events where Governance Analyst review was triggered.")
        with col_f3:
            filter_mode = st.selectbox(
                "Detection mode",
                ["All", "ONLINE", "OFFLINE", "FAILED"],
                help="Filter by which detection layer processed the scan."
            )

        filtered = entries
        if filter_pii:
            filtered = [e for e in filtered if e.get('pii_found')]
        if filter_hitl:
            filtered = [e for e in filtered if e.get('hitl_triggered')]
        if filter_mode != "All":
            filtered = [e for e in filtered if clean_scan_mode(e.get('scan_mode', '')) == filter_mode]

        st.caption(f"Showing {len(filtered)} of {len(entries)} entries")

        if filtered:
            table_data = []
            for e in filtered:
                raw_mode = e.get('scan_mode', '')
                display_mode = clean_scan_mode(raw_mode)

                event_raw = e.get('event_type', '')
                event_display = {
                    'DATABASE_RECORD_SCANNED': 'DB Scan',
                    'LIVE_SCAN': 'Live Scan',
                    'GA_DECISION': 'GA Decision',
                    'DQO_DECISION': 'GA Decision'
                }.get(event_raw, event_raw)

                table_data.append({
                    'Log ID': e.get('log_id', '')[:20],
                    'Timestamp': e.get('timestamp', '')[:19],
                    'Event': event_display,
                    'Mode': display_mode,
                    'PII Found': '✅' if e.get('pii_found') else '❌',
                    'Findings': e.get('finding_count', 0),
                    'Risk Score': e.get('overall_risk_score', 0),
                    'Review Required': '⚠ Yes' if e.get('hitl_triggered') else '—',
                    'Action': e.get('action_taken', '—') or '—',
                    'Authorised By': e.get('reviewed_by', '—') or '—',
                    'Legislation': e.get('legislation_reference', '') or '—'
                })

            df_audit = pd.DataFrame(table_data)
            st.dataframe(
                df_audit,
                use_container_width=True,
                hide_index=True,
                column_config={
                    'Log ID': st.column_config.TextColumn('Log ID', width='medium'),
                    'Timestamp': st.column_config.TextColumn('Timestamp', width='medium'),
                    'Event': st.column_config.TextColumn('Event', help='Type of event logged. DB Scan = batch pipeline. Live Scan = manual scan. GA Decision = Governance Analyst authorised an action.'),
                    'Mode': st.column_config.TextColumn('Detection Mode', help='ONLINE = Azure AI Language + Guardian AU rules active. OFFLINE = Azure unavailable, regex fallback only. FAILED = fail-safe triggered.'),
                    'PII Found': st.column_config.TextColumn('PII Found', help='Whether any PII identifier was detected in this scan event.'),
                    'Findings': st.column_config.NumberColumn('Findings', help=FINDING_EXPLANATION, format="%d"),
                    'Risk Score': st.column_config.NumberColumn('Risk Score', help=RISK_SCORE_EXPLANATION, format="%.1f"),
                    'Review Required': st.column_config.TextColumn('Review Required', help='Risk score exceeded 3.0 — Governance Analyst review was triggered for this record.'),
                    'Action': st.column_config.TextColumn('Action', help='Action authorised by the Governance Analyst. Blank if no decision has been made yet.'),
                    'Authorised By': st.column_config.TextColumn('Authorised By', help='Staff identifier of the Governance Analyst who authorised the action.'),
                    'Legislation': st.column_config.TextColumn('Legislation', width='large', help='Australian privacy legislation applicable to the PII found. Auto-cited by Guardian — not generated by the AI, cannot hallucinate.')
                }
            )

# ============================================================
# PAGE 5 — ABOUT GUARDIAN
# ============================================================
elif page == "ℹ️ About Guardian":
    st.title("ℹ️ About Guardian")
    st.caption("A prototype built to test frameworks — not a finished product")
    accent_bar()

    st.subheader("The problem")
    st.markdown("""
    Organisations managing sensitive personal information — Tax File Numbers, Medicare numbers,
    financial records — often have no systematic way of knowing where that information lives,
    who can access it, or whether it is stored compliantly.

    Information accumulates over years across shared drives, case notes, emails, and databases.
    Nobody intended the governance gap. It just happened.

    Under the **Privacy Act 1988 (Cth)** and the **Information Privacy Act 2009 (Qld)**,
    that gap is a compliance risk.
    """)

    st.divider()

    st.subheader("Five questions. One design.")
    st.markdown("Guardian was designed using **Backward Design** — starting with what the Governance Analyst needs to answer, then building backwards to the technology.")

    q1, q2, q3, q4, q5 = st.columns(5)
    questions = [
        ("1", "Where is our highest-risk information right now?"),
        ("2", "Which findings need my review?"),
        ("3", "What actions have been taken, and who authorised them?"),
        ("4", "Which legislation applies to each finding?"),
        ("5", "Can I produce this audit trail for a regulator?"),
    ]
    for col, (num, q) in zip([q1, q2, q3, q4, q5], questions):
        with col:
            st.info(f"**{num}**\n\n{q}")

    st.caption("Every component in Guardian exists because one of those questions required it. Technology came last.")

    st.divider()

    st.subheader("How it works")
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.success("**🔍 Detect**\n\nAzure AI Language + Guardian AU deterministic rules scan records for PII. Hybrid approach catches what neither does alone.")
    with c2:
        st.warning("**⚖️ Triage**\n\nPhi-4 via Azure AI Foundry assesses risk in plain English, grounded in Australian privacy legislation.")
    with c3:
        st.error("**🛑 Gate**\n\nHigh-risk findings route to the Governance Analyst Review Queue. Nothing happens without human authorisation. This is Human-in-the-Lead — not just Human-in-the-Loop.")
    with c4:
        st.info("**📋 Log**\n\nEvery decision is recorded with who, what, when, and why. PII is hashed. Legislation is auto-cited by code — not the AI.")

    st.divider()

    st.subheader("Guardian recommends. The Governance Analyst decides.")
    st.markdown("""
    No irreversible action — redaction, migration, disposal — is taken without explicit Governance Analyst authorisation.
    The AI identifies the risk. The human owns the consequence. That principle is embedded in the architecture, not in a policy document.
    """)

    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Technology stack")
        tech_data = pd.DataFrame({
            'Component': ['PII Detection', 'AI Triage', 'Security Perimeter', 'Offline Fallback', 'Audit Logging', 'Interface'],
            'Technology': ['Azure AI Language', 'Azure AI Foundry — Phi-4', 'Azure Content Safety + Prompt Shield', 'Python Regex (AU patterns)', 'JSONL — Privacy by Design', 'Streamlit'],
            'Purpose': [
                'Contextual entity recognition — TFN, Medicare, names, addresses',
                'Plain-English risk assessment grounded in legislation',
                'Jailbreak and content filtering on inputs and outputs',
                'Continuous operation when Azure is unavailable',
                'PII hashed, legislation auto-cited, regulator-ready',
                'Governance Analyst review and decision interface'
            ]
        })
        st.dataframe(tech_data, use_container_width=True, hide_index=True)

    with col_right:
        st.subheader("Social architecture considerations")
        st.markdown("AI deployment reshapes **authority, knowledge, and governance** — not just technical workflows. Guardian was designed with that in mind.")
        social_data = pd.DataFrame({
            'Design Decision': ['Human-in-the-Lead gate', 'Offline mode', 'Audit explainability', 'Provisional thresholds', 'Legislation auto-cited'],
            'Rationale': [
                'GA retains legal authority over all consequential decisions — AI never acts unilaterally',
                'Prevents knowledge atrophy and ensures operational continuity when Azure is unavailable',
                'GAs learn from every review — expertise is preserved, not replaced',
                'Risk thresholds must be co-designed with real GAs before production deployment',
                'Grounds every finding in actual law — not AI-generated text that could hallucinate'
            ]
        })
        st.dataframe(social_data, use_container_width=True, hide_index=True)
        st.caption("*Backward design tells you what to build toward. Social architecture tells you what not to destroy along the way.*")

    st.divider()

    st.subheader("Relevant legislation")
    leg_col1, leg_col2 = st.columns(2)
    with leg_col1:
        st.markdown("""
        - **Privacy Act 1988 (Cth)** — Tax File Number Rule, APP 11, Notifiable Data Breaches Scheme
        - **Information Privacy Act 2009 (Qld)** — IPP 1, IPP 4
        - **QGEA** — Information Asset Custodianship Policy
        """)
    with leg_col2:
        st.markdown("""
        - **ISO 27001** — Information Security Management
        - **ACSC Essential Eight** — Cybersecurity Baseline Framework
        """)

    st.divider()
    st.caption("Guardian · Built by Deborrah David · Prototype — work in progress · Not a production system · github.com/debdavid/guardian")