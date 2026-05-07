# app.py
# Guardian - AI Governance Platform
# Human-in-the-Lead DQO Interface
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
# CUSTOM STYLING — Microsoft-inspired design
# ============================================================
st.markdown("""
<style>
    /* Main background */
    .stApp {
        background-color: #F5F5F0;
    }
    
    /* Sidebar */
    [data-testid="stSidebar"] {
        background-color: #1A1A2E;
    }
    [data-testid="stSidebar"] * {
        color: #FFFFFF !important;
    }
    [data-testid="stSidebar"] .stRadio label {
        color: #FFFFFF !important;
        font-size: 0.9rem;
    }
    [data-testid="stSidebar"] .stCaption {
        color: #A0AEC0 !important;
    }
    [data-testid="stSidebar"] hr {
        border-color: #2D3748 !important;
    }
    
    /* Main content area */
    .main .block-container {
        padding-top: 2rem;
        padding-bottom: 2rem;
        background-color: #F5F5F0;
    }
    
    /* Headers */
    h1 {
        color: #1A1A2E !important;
        font-weight: 700 !important;
        letter-spacing: -0.5px;
    }
    h2, h3 {
        color: #1A1A2E !important;
        font-weight: 600 !important;
    }
    
    /* Metric cards */
    [data-testid="stMetric"] {
        background-color: #FFFFFF;
        padding: 1rem 1.5rem;
        border-radius: 12px;
        border: 1px solid #E2E8F0;
        box-shadow: 0 1px 3px rgba(0,0,0,0.05);
    }
    [data-testid="stMetricLabel"] {
        color: #64748B !important;
        font-size: 0.8rem !important;
        font-weight: 500 !important;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    [data-testid="stMetricValue"] {
        color: #1A1A2E !important;
        font-weight: 700 !important;
    }
    
    /* Info/Success/Warning/Error boxes */
    [data-testid="stAlert"] {
        border-radius: 10px !important;
        border: none !important;
    }
    
    /* Buttons */
    .stButton > button {
        border-radius: 8px !important;
        font-weight: 600 !important;
        transition: all 0.2s ease;
    }
    .stButton > button[kind="primary"] {
        background-color: #1A1A2E !important;
        color: white !important;
        border: none !important;
    }
    .stButton > button[kind="primary"]:hover {
        background-color: #2D3748 !important;
        box-shadow: 0 4px 12px rgba(26,26,46,0.3) !important;
    }
    
    /* Expander */
    [data-testid="stExpander"] {
        background-color: #FFFFFF;
        border-radius: 10px !important;
        border: 1px solid #E2E8F0 !important;
        margin-bottom: 0.5rem;
    }
    
    /* Dataframe */
    [data-testid="stDataFrame"] {
        border-radius: 10px;
        overflow: hidden;
    }
    
    /* Input fields */
    [data-testid="stTextInput"] input,
    [data-testid="stTextArea"] textarea,
    [data-testid="stSelectbox"] {
        border-radius: 8px !important;
        border-color: #E2E8F0 !important;
    }
    
    /* Divider */
    hr {
        border-color: #E2E8F0 !important;
        margin: 1.5rem 0 !important;
    }
    
    /* Caption text */
    .stCaption {
        color: #64748B !important;
    }
    
    /* Success metric delta */
    [data-testid="stMetricDelta"] {
        font-size: 0.75rem !important;
    }
    
    /* Container borders */
    [data-testid="stVerticalBlock"] > div > div[data-testid="stVerticalBlock"] {
        background-color: #FFFFFF;
        border-radius: 12px;
        padding: 1rem;
    }
</style>
""", unsafe_allow_html=True)

import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners.pii_scanner import scan_text_for_pii
from scanners.triage_engine import TriageEngine
from utils.audit_log import read_audit_log, get_audit_summary, write_audit_log
from utils.security import SecurityPerimeter

DB_PATH = Path('database/guardian.db')
PIPELINE_REPORT_PATH = Path('database/pipeline_report.json')

RISK_COLOURS = {
    'CRITICAL': '#DC2626',
    'HIGH': '#EA580C',
    'MEDIUM': '#D97706',
    'LOW': '#16A34A',
    'UNKNOWN': '#6B7280'
}

RISK_EMOJI = {
    'CRITICAL': '🔴',
    'HIGH': '🟠',
    'MEDIUM': '🟡',
    'LOW': '🟢',
    'UNKNOWN': '⚪'
}

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
st.sidebar.image("https://img.icons8.com/color/96/shield.png", width=60)
st.sidebar.title("Guardian")
st.sidebar.caption("AI Governance Platform")
st.sidebar.caption("Human-in-the-Lead · Responsible AI")
st.sidebar.divider()

page = st.sidebar.radio(
    "Navigation",
    [
        "🏠 Governance Dashboard",
        "🔍 Live PII Scanner",
        "⚠️ DQO Review Queue",
        "📋 Audit Trail",
        "ℹ️ About Guardian"
    ]
)

st.sidebar.divider()
st.sidebar.markdown("**System Status**")

if os.getenv('AZURE_LANGUAGE_KEY', ''):
    st.sidebar.success("🟢 Azure AI Language")
else:
    st.sidebar.warning("🔴 Azure AI Language")

if os.getenv('AZURE_INFERENCE_KEY', ''):
    st.sidebar.success("🟢 Azure AI Foundry (Phi-4)")
else:
    st.sidebar.warning("🔴 Azure AI Foundry")

if os.getenv('AZURE_CONTENT_SAFETY_KEY', ''):
    st.sidebar.success("🟢 Azure Content Safety")
else:
    st.sidebar.warning("🔴 Azure Content Safety")

st.sidebar.caption(f"Last updated: {datetime.now().strftime('%H:%M:%S')}")

# ============================================================
# PAGE 1 - GOVERNANCE DASHBOARD
# ============================================================
if page == "🏠 Governance Dashboard":
    st.title("🛡️ Guardian Governance Dashboard")
    st.caption("Real-time visibility across your data estate · Human-in-the-Lead AI governance")
    st.divider()

    report = load_pipeline_report()
    audit_summary = get_audit_summary()

    if not report:
        st.warning("No pipeline report found. Run `python main.py` first to generate data.")
    else:
        scan = report.get('scan_report', {})
        risk = scan.get('risk_distribution', {})
        actions = scan.get('action_recommendations', {})

        col1, col2, col3, col4, col5 = st.columns(5)
        with col1:
            st.metric("Records Scanned", scan.get('total_records_scanned', 0))
        with col2:
            st.metric("PII Detection Rate", f"{scan.get('pii_detection_rate', 0)}%")
        with col3:
            st.metric("Critical Risk", risk.get('critical', 0),
                delta=f"{risk.get('critical', 0)} require escalation",
                delta_color="inverse")
        with col4:
            st.metric("HITL Reviews", scan.get('records_requiring_hitl', 0))
        with col5:
            st.metric("Audit Entries", audit_summary.get('total_scans', 0))

        st.divider()

        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("PII Types Detected")
            all_entries = read_audit_log(limit=10000)
            category_counts = {}
            for e in all_entries:
                for f in e.get('findings_summary', []):
                    cat = f.get('category', 'Unknown')
                    category_counts[cat] = category_counts.get(cat, 0) + 1

            if category_counts:
                pii_df = pd.DataFrame(
                    sorted(category_counts.items(), key=lambda x: x[1], reverse=True),
                    columns=['PII Type', 'Count']
                )
                fig_pii = px.bar(
                    pii_df, x='Count', y='PII Type',
                    orientation='h',
                    color='Count',
                    color_continuous_scale=['#FEF3C7', '#EA580C', '#DC2626'],
                    title="What sensitive data is exposed"
                )
                fig_pii.update_layout(
                    showlegend=False, height=300,
                    coloraxis_showscale=False,
                    yaxis={'categoryorder': 'total ascending'}
                )
                st.plotly_chart(fig_pii, use_container_width=True)
            else:
                st.info("No findings data yet.")

        with col_right:
            st.subheader("AI vs Human Decisions")
            actions_taken = audit_summary.get('actions_taken', {})
            total_dqo = sum(actions_taken.values())
            overrides = audit_summary.get('human_overrides', 0)
            agreements = total_dqo - overrides

            if total_dqo > 0:
                decision_df = pd.DataFrame({
                    'Outcome': ['Agreed with AI', 'Overrode AI'],
                    'Count': [agreements, overrides]
                })
                fig_decisions = px.bar(
                    decision_df, x='Outcome', y='Count',
                    color='Outcome',
                    color_discrete_map={
                        'Agreed with AI': '#16A34A',
                        'Overrode AI': '#DC2626'
                    },
                    title="Human-in-the-Lead: DQO decision pattern"
                )
                fig_decisions.update_layout(showlegend=False, height=300)
                st.plotly_chart(fig_decisions, use_container_width=True)
            else:
                st.info("No DQO decisions recorded yet. Authorise actions in the Review Queue to populate this chart.")

        st.divider()

        st.subheader("Microsoft Well-Architected Framework Status")
        waf = report.get('well_architected_notes', {})
        waf_cols = st.columns(5)
        waf_items = [
            ("Reliability", "reliability", "🔄"),
            ("Security", "security", "🔒"),
            ("Cost", "cost_optimisation", "💰"),
            ("Operations", "operational_excellence", "📊"),
            ("Performance", "performance", "⚡")
        ]
        for col, (label, key, emoji) in zip(waf_cols, waf_items):
            with col:
                st.success(f"{emoji} **{label}**")
                st.caption(waf.get(key, 'Active'))

        st.divider()

        meta = report.get('pipeline_metadata', {})
        st.subheader("Last Pipeline Run")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.info(f"⏱️ Duration: {meta.get('duration_seconds', 0)} seconds")
        with m2:
            st.info(f"📅 Completed: {meta.get('completed', 'Unknown')[:19]}")
        with m3:
            st.info(f"🔧 Mode: {meta.get('mode', 'unknown').upper()}")
            
# ============================================================
# PAGE 2 - LIVE PII SCANNER
# ============================================================
elif page == "🔍 Live PII Scanner":
    st.title("🔍 Live PII Scanner")
    st.caption("Scan any text for PII · Azure AI Language detects · Phi-4 triages · DQO decides")
    st.divider()

    if 'scan_result' not in st.session_state:
        st.session_state.scan_result = None
    if 'triage_result' not in st.session_state:
        st.session_state.triage_result = None
    if 'scan_text' not in st.session_state:
        st.session_state.scan_text = ""

    st.subheader("Enter text to scan")

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
        height=200,
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
                # Determine context label
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

                # Auto-populate DQO Review Queue if HITL triggered
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
                        'ai_explanation': triage.get('explanation', 'High-risk PII detected. DQO review required before any action.'),
                        'source': 'live_scanner',
                        'scanned_at': datetime.now().isoformat()
                    }

                    existing_ids = [q['id'] for q in st.session_state.review_queue]
                    if scan_id not in existing_ids:
                        st.session_state.review_queue.append(new_item)

                    st.warning("⚠️ **HITL Gate Triggered** — This finding has been added to the DQO Review Queue.")

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
            st.metric("Findings", result['finding_count'])
        with r3:
            st.metric("Risk Score", f"{result['overall_risk_score']}/5.0")
        with r4:
            scan_mode = result.get('scan_mode', 'UNKNOWN')
            if 'ONLINE' in scan_mode:
                st.success(f"🌐 ONLINE")
            else:
                st.warning(f"📴 {scan_mode}")

        if result['pii_found'] and result['findings']:
            st.subheader("Findings Breakdown")
            findings_data = []
            for f in result['findings']:
                findings_data.append({
                    'Category': f['category'],
                    'Risk Level': f['risk_level'],
                    'Confidence': f"{f['confidence_score']:.0%}",
                    'Detection Method': f.get('detection_method', 'unknown'),
                    'Risk Score': f['risk_score']
                })

            df_findings = pd.DataFrame(findings_data)

            def colour_risk(val):
                colours = {
                    'CRITICAL': 'background-color: #FEE2E2; color: #DC2626',
                    'HIGH': 'background-color: #FED7AA; color: #EA580C',
                    'MEDIUM': 'background-color: #FEF3C7; color: #D97706',
                    'LOW': 'background-color: #DCFCE7; color: #16A34A'
                }
                return colours.get(val, '')

            st.dataframe(
                df_findings.style.map(colour_risk, subset=['Risk Level']),
                use_container_width=True,
                hide_index=True
            )

            st.subheader("Redacted Preview")
            st.caption("This is a preview only. No action has been taken. The DQO must authorise any changes.")
            st.code(result.get('redacted_text', ''), language=None)

            if st.session_state.triage_result:
                triage = st.session_state.triage_result
                st.subheader("AI Triage Assessment")
                st.caption("Powered by Azure AI Foundry — Phi-4 · Grounded in Australian privacy legislation")

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
                        st.info(triage.get('action_required', 'No action specified'))

                if result['requires_human_review']:
                    st.warning("⚠️ **This record has been added to the DQO Review Queue.** Navigate there to authorise an action.")

        else:
            st.success("✅ No PII detected in this text. No action required.")

# ============================================================
# PAGE 3 - DQO REVIEW QUEUE
# ============================================================
elif page == "⚠️ DQO Review Queue":
    st.title("⚠️ DQO Review Queue")
    st.caption("Guardian has identified these records. Review each finding and authorise an action.")
    st.divider()

    st.info("""
    **Review each finding below and select an action.**
    
    Guardian has identified records requiring your attention.
    Your decision will be logged automatically with your identifier and timestamp.
    No action is taken until you click Authorise.
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
                'ai_explanation': 'Record contains Tax File Number and Medicare Number in unstructured notes field. Both identifiers carry mandatory legislative protection under the Privacy Act 1988 TFN Rule. Immediate DQO review required before any remediation action.',
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
                'ai_explanation': 'TFN detected in a field classified as Internal access. Current storage location does not meet the separation requirements under the TFN Rule. Migration to a restricted access system recommended.',
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

    q1, q2, q3 = st.columns(3)
    with q1:
        st.metric("Pending Review", len(pending))
    with q2:
        st.metric("Reviewed Today", len(reviewed))
    with q3:
        st.metric("Total in Queue", len(queue))

    st.divider()

    if not pending:
        st.success("✅ All findings reviewed. Queue is clear.")
    else:
        st.subheader(f"Pending Findings ({len(pending)})")

        for i, item in enumerate(pending):
            source_tag = "🔄 Pipeline" if item.get('source') == 'pipeline' else "🔍 Live Scan"
            with st.expander(
                f"{RISK_EMOJI.get(item['risk_level'], '⚪')} {item['record']} — {item['risk_level']} Risk · {item['recommendation']} Recommended · {source_tag}",
                expanded=(i == 0)
            ):
                col_detail, col_action = st.columns([2, 1])

                with col_detail:
                    st.markdown(f"**Record ID:** `{item['id']}`")
                    st.markdown(f"**Risk Score:** {item['risk_score']}/5.0")
                    st.markdown(f"**PII Detected:** {', '.join(item['pii_types'])}")
                    st.markdown(f"**Legislation:** {item['legislation']}")
                    st.markdown(f"**Source:** {source_tag} · Scanned: {item.get('scanned_at', '')[:19]}")
                    st.markdown("**AI Assessment:**")
                    st.info(item['ai_explanation'])

                with col_action:
                    st.markdown("**DQO Action Required**")
                    dqo_id = st.text_input(
                        "DQO Identifier",
                        value="DQO-001",
                        key=f"dqo_{item['id']}"
                    )
                    action_choice = st.selectbox(
                        "Select Action",
                        ["ESCALATE", "REDACT", "MIGRATE", "RETAIN", "DISPOSE"],
                        key=f"action_{item['id']}"
                    )
                    override_reason = st.text_area(
                        "Reason / Notes",
                        placeholder="Required if overriding AI recommendation...",
                        key=f"reason_{item['id']}",
                        height=80
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
                            event_type='DQO_DECISION',
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
                            notes="DQO authorised via Guardian interface"
                        )

                        if overrode:
                            st.warning(f"⚠️ Override recorded. AI recommended {item['recommendation']}, DQO selected {action_choice}.")
                        else:
                            st.success(f"✅ Action authorised: {action_choice}. Audit log updated.")

                        st.rerun()

    if reviewed:
        st.divider()
        st.subheader(f"Reviewed ({len(reviewed)})")
        for item in reviewed:
            overrode = item.get('status') != item.get('recommendation')
            emoji = "⚠️" if overrode else "✅"
            st.success(
                f"{emoji} {item['record']} — {item['status']} by {item.get('reviewed_by', 'Unknown')} at {item.get('reviewed_at', '')[:19]}"
            )

# ============================================================
# PAGE 4 - AUDIT TRAIL
# ============================================================
elif page == "📋 Audit Trail":
    st.title("📋 Audit Trail")
    st.caption("Complete governance record · Every scan, decision, and action logged · Privacy by design")
    st.divider()

    entries = load_audit_entries()

    if not entries:
        st.info("No audit entries to display yet. Entries are created as Guardian scans documents and processes findings.")
    else:
        summary = get_audit_summary()

        # ── Summary metrics ──────────────────────────────────────────
        a1, a2, a3, a4 = st.columns(4)
        with a1:
            st.metric("Total Entries", summary.get('total_scans', 0))
        with a2:
            st.metric("PII Found", summary.get('pii_found_count', 0))
        with a3:
            st.metric("HITL Triggered", summary.get('hitl_triggered_count', 0))
        with a4:
            st.metric("Human Overrides", summary.get('human_overrides', 0))

        st.divider()

        # ── Filters ───────────────────────────────────────────────────
        col_f1, col_f2, col_f3 = st.columns(3)
        with col_f1:
            filter_pii = st.checkbox("PII found only", value=False)
        with col_f2:
            filter_hitl = st.checkbox("HITL triggered only", value=False)
        with col_f3:
            filter_mode = st.selectbox("Scan mode", ["All", "ONLINE", "OFFLINE", "FAILED"])

        filtered = entries
        if filter_pii:
            filtered = [e for e in filtered if e.get('pii_found')]
        if filter_hitl:
            filtered = [e for e in filtered if e.get('hitl_triggered')]
        if filter_mode != "All":
            filtered = [e for e in filtered if e.get('scan_mode') == filter_mode]

        st.caption(f"Showing {len(filtered)} of {len(entries)} entries")

        if not filtered:
            st.info("No entries match the current filters.")
        else:
            # ── Label maps ────────────────────────────────────────────
            ACTION_EMOJI = {
                'ESCALATE': '🔴 ESCALATE',
                'REDACT':   '✏️ REDACT',
                'MIGRATE':  '📦 MIGRATE',
                'RETAIN':   '📁 RETAIN',
                'DISPOSE':  '🗑️ DISPOSE',
            }
            EVENT_LABEL = {
                'DATABASE_RECORD_SCANNED': '🔍 DB Scan',
                'DQO_DECISION':            '⚖️ DQO Decision',
                'LIVE_SCAN':               '🌐 Live Scan',
            }

            # ── Build table rows ──────────────────────────────────────
            table_data = []

            for e in filtered:
                # Scan mode
                raw_mode = e.get('scan_mode', '')
                if 'ONLINE'  in raw_mode: display_mode = '🌐 ONLINE'
                elif 'OFFLINE' in raw_mode: display_mode = '📴 OFFLINE'
                elif 'FAILED'  in raw_mode: display_mode = '❌ FAILED'
                else: display_mode = raw_mode or '—'

                # Risk score
                risk_score = e.get('overall_risk_score', 0)

                # Action with emoji
                raw_action = e.get('action_taken') or '—'
                action_display = ACTION_EMOJI.get(raw_action, raw_action)

                # Event label
                raw_event = e.get('event_type', '')
                event_display = EVENT_LABEL.get(raw_event, raw_event)

                # Legislation — truncated for column display
                leg = (e.get('legislation_reference') or '').replace(' - ', ' — ').replace(';', ' ·')
                leg_display = leg or '—'
                log_id_short = (e.get('log_id') or '')[:16]

                table_data.append({
                    'Log ID':      log_id_short,
                    'Timestamp':   (e.get('timestamp') or '')[:19],
                    'Event':       event_display,
                    'Mode':        display_mode,
                    'PII Found':   '✅' if e.get('pii_found') else '❌',
                    'Findings':    e.get('finding_count', 0),
                    'Risk Score':  risk_score,
                    'HITL':        '⚠️' if e.get('hitl_triggered') else '—',
                    'Action':      action_display,
                    'Reviewed By': e.get('reviewed_by') or '—',
                    'Legislation': leg_display,
                })

            df_audit = pd.DataFrame(table_data)

            # ── Column order ──────────────────────────────────────────
            display_cols = [
                'Log ID', 'Timestamp', 'Event', 'Mode',
                'PII Found', 'Findings', 'Risk Score',
                'HITL', 'Action', 'Reviewed By',
                'Legislation'
            ]

            # ── Stylers ───────────────────────────────────────────────
            def style_risk(val):
                try:
                    v = float(val)
                except (ValueError, TypeError):
                    return ''
                if v >= 4.5:   return 'background-color:#FEE2E2; color:#DC2626; font-weight:700'
                elif v >= 3.5: return 'background-color:#FED7AA; color:#EA580C; font-weight:600'
                elif v >= 2.0: return 'background-color:#FEF3C7; color:#D97706'
                else:          return 'background-color:#DCFCE7; color:#16A34A'

            def style_action(val):
                if 'ESCALATE' in str(val): return 'color:#DC2626; font-weight:700'
                if 'MIGRATE'  in str(val): return 'color:#D97706; font-weight:600'
                if 'REDACT'   in str(val): return 'color:#7C3AED; font-weight:600'
                if 'DISPOSE'  in str(val): return 'color:#6B7280'
                if 'RETAIN'   in str(val): return 'color:#16A34A'
                return ''

            styled_df = (
                df_audit[display_cols]
                .style
                .map(style_risk,   subset=['Risk Score'])
                .map(style_action, subset=['Action'])
                .set_properties(**{'text-align': 'left'})
                .set_table_styles([
                    {'selector': 'th', 'props': [
                        ('background-color', '#1A1A2E'),
                        ('color', 'white'),
                        ('font-weight', '600'),
                        ('font-size', '0.8rem'),
                        ('text-transform', 'uppercase'),
                        ('letter-spacing', '0.5px'),
                        ('padding', '10px 12px'),
                    ]},
                    {'selector': 'td', 'props': [
                        ('padding', '9px 12px'),
                        ('border-bottom', '1px solid #F1F5F9'),
                        ('font-size', '0.875rem'),
                    ]},
                    {'selector': 'tr:hover td', 'props': [
                        ('background-color', '#F8FAFC'),
                    ]},
                ])
            )

            st.dataframe(
                styled_df,
                use_container_width=True,
                hide_index=True,
                height=min(400, 56 + len(df_audit) * 48),
                column_config={
                    "Legislation": st.column_config.TextColumn(
                        "Legislation",
                        width="large",
                    )
                }
            )

            st.divider()
            st.caption("💡 Right-click the table and choose **Download as CSV** to export for regulator review.")
# ============================================================
# PAGE 5 - ABOUT GUARDIAN
# ============================================================
elif page == "ℹ️ About Guardian":
    st.title("ℹ️ About Guardian")
    st.caption("A prototype built to test frameworks — not a finished product")
    st.divider()

    # ---- THE PROBLEM ----
    st.subheader("The problem")
    st.markdown("""
    Organisations managing sensitive personal information — Tax File Numbers, Medicare numbers,
    financial records — often have no systematic way of knowing where that information lives,
    who can access it, or whether it is stored compliantly.

    The information accumulates over years. It spreads across shared drives, case notes, emails,
    and databases. Nobody intended the governance gap. It just happened.

    Under the **Privacy Act 1988 (Cth)** and the **Information Privacy Act 2009 (Qld)**,
    that gap is a compliance risk. A serious one.
    """)

    st.divider()

    # ---- THE FIVE QUESTIONS ----
    st.subheader("Five questions. One design.")
    st.markdown("""
    Guardian was not designed by starting with technology.
    It was designed by asking what a Data Quality Officer needs to answer — on demand:
    """)

    q1, q2, q3, q4, q5 = st.columns(5)
    with q1:
        st.info("**1**\n\nWhere is our highest-risk information right now?")
    with q2:
        st.info("**2**\n\nWhich findings need my review?")
    with q3:
        st.info("**3**\n\nWhat actions have been taken, and who authorised them?")
    with q4:
        st.info("**4**\n\nWhich legislation applies to each finding?")
    with q5:
        st.info("**5**\n\nCan I produce this audit trail for a regulator?")

    st.caption("Every component in Guardian exists because one of those questions required it. This is backward design — applied to AI solution architecture.")

    st.divider()

    # ---- HOW IT WORKS ----
    st.subheader("How it works")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.success("**🔍 Detect**\n\nAzure AI Language scans records for PII — names, TFNs, Medicare numbers, addresses, bank details.")
    with c2:
        st.warning("**⚖️ Triage**\n\nPhi-4 assesses the risk in plain English, citing relevant Australian legislation.")
    with c3:
        st.error("**🛑 Gate**\n\nHigh-risk findings route to the DQO Review Queue. Nothing happens without human authorisation.")
    with c4:
        st.info("**📋 Log**\n\nEvery decision is recorded — who, what, when, why — with PII hashed for privacy by design.")

    st.divider()

    # ---- GUARDIAN RECOMMENDS ----
    st.subheader("Guardian recommends. Humans decide.")
    st.markdown("""
    No irreversible action — redaction, migration, disposal — is taken without explicit DQO authorisation.
    The AI identifies the risk. The human owns the consequence.

    This is not a policy document. It is embedded in the architecture.
    """)

    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("Technology stack")
        tech_data = pd.DataFrame({
            'Component': ['PII Detection', 'AI Triage', 'Security', 'Offline Fallback', 'Audit Logging', 'Interface'],
            'Technology': ['Azure AI Language', 'Azure AI Foundry — Phi-4', 'Azure Content Safety + Prompt Shield', 'Python Regex (AU patterns)', 'JSONL — Privacy by Design', 'Streamlit'],
            'Purpose': ['TFN, Medicare, names, addresses', 'Plain English risk assessment', 'Jailbreak + content filtering', 'Continuous operation', 'PII hashed, legislation cited', 'DQO governance interface']
        })
        st.dataframe(tech_data, use_container_width=True, hide_index=True)

    with col_right:
        st.subheader("Social architecture")
        st.markdown("""
        AI deployment reshapes authority, knowledge, and governance — not just workflows.
        Guardian was designed with that in mind.
        """)
        social_data = pd.DataFrame({
            'Design Decision': ['HITL gate', 'Offline mode', 'Audit explainability', 'Provisional thresholds'],
            'Rationale': [
                'Preserves DQO authority over consequential decisions',
                'Prevents knowledge atrophy when Azure is unavailable',
                'DQOs learn from every review — expertise is preserved',
                'Co-design with DQOs required before production'
            ]
        })
        st.dataframe(social_data, use_container_width=True, hide_index=True)
        st.caption("*Backward design tells you what to build toward. Social architecture tells you what not to destroy along the way.*")

    st.divider()
    st.caption("Guardian · Built by Deborrah David · github.com/debdavid/guardian · Prototype — not a production system")