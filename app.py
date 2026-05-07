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

# ============================================================
# PAGE CONFIG - must be first Streamlit call
# ============================================================
st.set_page_config(
    page_title="Guardian | AI Governance Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ============================================================
# IMPORTS FROM GUARDIAN MODULES
# ============================================================
import sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from scanners.pii_scanner import scan_text_for_pii
from scanners.triage_engine import TriageEngine
from utils.audit_log import read_audit_log, get_audit_summary, write_audit_log
from utils.security import SecurityPerimeter

# ============================================================
# CONSTANTS
# ============================================================
DB_PATH = Path('database/guardian.db')
PIPELINE_REPORT_PATH = Path('database/pipeline_report.json')

# Risk colours for UI
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

@st.cache_data(ttl=30)
def load_database_records():
    if not DB_PATH.exists():
        return []
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM estate_records LIMIT 100")
    records = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return records

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

# Live system status
st.sidebar.markdown("**System Status**")
azure_lang_key = os.getenv('AZURE_LANGUAGE_KEY', '')
azure_inf_key = os.getenv('AZURE_INFERENCE_KEY', '')

if azure_lang_key:
    st.sidebar.success("🟢 Azure AI Language")
else:
    st.sidebar.warning("🔴 Azure AI Language")

if azure_inf_key:
    st.sidebar.success("🟢 Azure AI Foundry (Phi-4)")
else:
    st.sidebar.warning("🔴 Azure AI Foundry")

content_safety_key = os.getenv('AZURE_CONTENT_SAFETY_KEY', '')
if content_safety_key:
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

        # ---- KPI METRICS ROW ----
        col1, col2, col3, col4, col5 = st.columns(5)

        with col1:
            st.metric(
                "Records Scanned",
                scan.get('total_records_scanned', 0),
                help="Total estate records processed by Guardian"
            )
        with col2:
            st.metric(
                "PII Detection Rate",
                f"{scan.get('pii_detection_rate', 0)}%",
                help="Percentage of records containing PII"
            )
        with col3:
            st.metric(
                "Critical Risk",
                risk.get('critical', 0),
                delta=f"{risk.get('critical', 0)} require escalation",
                delta_color="inverse",
                help="Records with risk score ≥ 4.0"
            )
        with col4:
            st.metric(
                "HITL Reviews",
                scan.get('records_requiring_hitl', 0),
                help="Records requiring Data Quality Officer review"
            )
        with col5:
            st.metric(
                "Audit Entries",
                audit_summary.get('total_scans', 0),
                help="Total entries in the audit trail"
            )

        st.divider()

        # ---- CHARTS ROW ----
        col_left, col_right = st.columns(2)

        with col_left:
            st.subheader("Risk Distribution")
            risk_data = {
                'Risk Level': ['Critical', 'High', 'Medium', 'Low'],
                'Count': [
                    risk.get('critical', 0),
                    risk.get('high', 0),
                    risk.get('medium', 0),
                    risk.get('low', 0)
                ],
                'Colour': ['#DC2626', '#EA580C', '#D97706', '#16A34A']
            }
            df_risk = pd.DataFrame(risk_data)
            fig_risk = px.bar(
                df_risk,
                x='Risk Level',
                y='Count',
                color='Risk Level',
                color_discrete_map={
                    'Critical': '#DC2626',
                    'High': '#EA580C',
                    'Medium': '#D97706',
                    'Low': '#16A34A'
                },
                title="Records by Risk Level"
            )
            fig_risk.update_layout(showlegend=False, height=300)
            st.plotly_chart(fig_risk, use_container_width=True)

        with col_right:
            st.subheader("Recommended Actions")
            if actions:
                action_data = pd.DataFrame(
                    list(actions.items()),
                    columns=['Action', 'Count']
                )
                fig_actions = px.pie(
                    action_data,
                    names='Action',
                    values='Count',
                    title="Action Distribution",
                    color_discrete_sequence=px.colors.qualitative.Set2
                )
                fig_actions.update_layout(height=300)
                st.plotly_chart(fig_actions, use_container_width=True)
            else:
                st.info("No action data available yet.")

        st.divider()

        # ---- WELL ARCHITECTED FRAMEWORK ----
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

        # ---- PIPELINE METADATA ----
        meta = report.get('pipeline_metadata', {})
        st.subheader("Last Pipeline Run")
        m1, m2, m3 = st.columns(3)
        with m1:
            st.info(f"⏱️ Duration: {meta.get('duration_seconds', 0)} seconds")
        with m2:
            st.info(f"📅 Completed: {meta.get('completed', 'Unknown')[:19]}")
        with m3:
            mode = meta.get('mode', 'unknown').upper()
            st.info(f"🔧 Mode: {mode}")

# ============================================================
# PAGE 2 - LIVE PII SCANNER
# ============================================================
elif page == "🔍 Live PII Scanner":
    st.title("🔍 Live PII Scanner")
    st.caption("Scan any text for personally identifiable information · Powered by Azure AI Language + Phi-4 triage")
    st.divider()

    # Initialise session state
    if 'scan_result' not in st.session_state:
        st.session_state.scan_result = None
    if 'triage_result' not in st.session_state:
        st.session_state.triage_result = None
    if 'scan_text' not in st.session_state:
        st.session_state.scan_text = ""

    # Sample texts
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
        # Screen input through security perimeter first
        security = get_security()
        safety_check = security.check_input(text_input, source="live_scanner")
        
        if safety_check['blocked']:
            st.error(f"⛔ Input blocked by security perimeter: {safety_check['reason']}")
        else:
            if safety_check.get('severity') == 'WARN':
                st.warning("⚠️ Content Safety unavailable — proceeding without security screening")
            
            with st.spinner("Azure AI Language scanning for PII..."):
                result = scan_text_for_pii(text_input, context="live_scanner")
            st.session_state.scan_result = result
            st.session_state.scan_text = text_input

        if result['pii_found'] and result['findings']:
            with st.spinner("Azure AI Foundry (Phi-4) triaging risk..."):
                engine = get_triage_engine()
                pii_categories = list(set(f['category'] for f in result['findings']))
                triage = engine.triage_record(
                    {"text": text_input[:500]},
                    pii_categories
                )
                st.session_state.triage_result = triage

    if st.session_state.scan_result:
        result = st.session_state.scan_result
        st.divider()
        st.subheader("Scan Results")

        # Summary metrics
        r1, r2, r3, r4 = st.columns(4)
        with r1:
            if result['pii_found']:
                st.error(f"⚠️ PII DETECTED")
            else:
                st.success(f"✅ No PII Found")
        with r2:
            st.metric("Findings", result['finding_count'])
        with r3:
            st.metric("Risk Score", f"{result['overall_risk_score']}/5.0")
        with r4:
            scan_mode = result.get('scan_mode', 'UNKNOWN')
            if scan_mode == 'ONLINE':
                st.success(f"🌐 {scan_mode}")
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

            # Redacted version
            st.subheader("Redacted Output")
            st.code(result.get('redacted_text', ''), language=None)

            # AI Triage
            if st.session_state.triage_result:
                triage = st.session_state.triage_result
                st.subheader("AI Triage Assessment")
                st.caption("Powered by Azure AI Foundry — Phi-4 · Grounded in Australian privacy legislation")

                score = triage.get('triage_score', 'UNKNOWN')
                colour = RISK_COLOURS.get(score, '#6B7280')

                with st.container(border=True):
                    t1, t2 = st.columns([1, 3])
                    with t1:
                        st.markdown(f"### {RISK_EMOJI.get(score, '⚪')} {score}")
                        st.caption("Triage Score")
                    with t2:
                        st.markdown(f"**AI Assessment:**")
                        st.write(triage.get('explanation', 'No explanation available'))
                        st.markdown(f"**Recommended Action:**")
                        st.info(triage.get('action_required', 'No action specified'))

                if result['requires_human_review']:
                    st.warning("⚠️ **HITL Gate Triggered** — This finding requires Data Quality Officer review before any action is taken. Navigate to the DQO Review Queue to process this finding.")

        else:
            st.success("✅ No PII detected in this text. No action required.")
            st.info(f"Scan mode: {result.get('scan_mode', 'UNKNOWN')} · Completed: {result.get('timestamp', '')[:19]}")

# ============================================================
# PAGE 3 - DQO REVIEW QUEUE
# ============================================================
elif page == "⚠️ DQO Review Queue":
    st.title("⚠️ DQO Review Queue")
    st.caption("Human-in-the-Lead gate · All consequential actions require named DQO authorisation")
    st.divider()

    st.info("""
    **Review each finding below and select an action.**
    
    Guardian has identified records requiring your attention.
    Your decision will be logged automatically with your identifier and timestamp.
    No action is taken until you click Authorise.
    """)

    # Initialise review queue in session state
    if 'review_queue' not in st.session_state:
        # Load high-risk findings from pipeline report
        report = load_pipeline_report()
        queue = []

        if report:
            individual = report.get('scan_report', {})
            # Create synthetic queue items from pipeline data
            queue = [
                {
                    'id': 'QPT-0001',
                    'record': 'Estate Record QPT-0001',
                    'risk_score': 5.0,
                    'risk_level': 'CRITICAL',
                    'pii_types': ['AUTaxFileNumber', 'AUMedicareNumber', 'Email', 'PhoneNumber'],
                    'recommendation': 'ESCALATE',
                    'legislation': 'Privacy Act 1988 (Cth) — Tax File Number Rule; Information Privacy Act 2009 (Qld) — IPP 4',
                    'status': 'PENDING',
                    'ai_explanation': 'Record contains Tax File Number and Medicare Number in unstructured notes field. Both identifiers carry mandatory legislative protection under the Privacy Act 1988 TFN Rule. Immediate DQO review required before any remediation action.'
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
                    'ai_explanation': 'TFN detected in a field classified as Internal access. Current storage location does not meet the separation requirements under the TFN Rule. Migration to a restricted access system recommended.'
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
                    'ai_explanation': 'Financial credentials detected alongside government identifiers. Combination of TFN, Medicare, and payment card data creates elevated fraud risk. Possible notifiable data breach — Privacy Officer consultation required before any action.'
                }
            ]
        st.session_state.review_queue = queue

    if 'review_log' not in st.session_state:
        st.session_state.review_log = []

    queue = st.session_state.review_queue
    pending = [q for q in queue if q['status'] == 'PENDING']
    reviewed = [q for q in queue if q['status'] != 'PENDING']

    # Queue metrics
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
            with st.expander(
                f"{RISK_EMOJI.get(item['risk_level'], '⚪')} {item['record']} — {item['risk_level']} Risk · {item['recommendation']} Recommended",
                expanded=(i == 0)
            ):
                col_detail, col_action = st.columns([2, 1])

                with col_detail:
                    st.markdown(f"**Record ID:** `{item['id']}`")
                    st.markdown(f"**Risk Score:** {item['risk_score']}/5.0")
                    st.markdown(f"**PII Detected:** {', '.join(item['pii_types'])}")
                    st.markdown(f"**Legislation:** {item['legislation']}")
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
                        f"✅ Authorise Action",
                        key=f"approve_{item['id']}",
                        type="primary",
                        use_container_width=True
                    ):
                        item['status'] = action_choice
                        item['reviewed_by'] = dqo_id
                        item['override_reason'] = override_reason
                        item['reviewed_at'] = datetime.now().isoformat()

                        overrode = action_choice != item['recommendation']

                        # Write to audit log
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
                            notes=f"DQO authorised via Guardian interface"
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
        st.warning("No audit entries found. Run `python main.py` to generate data.")
    else:
        summary = get_audit_summary()

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

        # Filters
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

        # Display as table
        if filtered:
            table_data = []
            for e in filtered:
                table_data.append({
                    'Log ID': e.get('log_id', '')[:20],
                    'Timestamp': e.get('timestamp', '')[:19],
                    'Event': e.get('event_type', ''),
                    'Mode': e.get('scan_mode', ''),
                    'PII Found': '✅' if e.get('pii_found') else '❌',
                    'Findings': e.get('finding_count', 0),
                    'Risk Score': e.get('overall_risk_score', 0),
                    'HITL': '⚠️' if e.get('hitl_triggered') else '—',
                    'Action': e.get('action_taken', '—') or '—',
                    'Legislation': (e.get('legislation_reference', '') or '')[:50]
                })

            df_audit = pd.DataFrame(table_data)
            st.dataframe(df_audit, use_container_width=True, hide_index=True)

            # Raw JSON viewer
            with st.expander("View raw audit entry"):
                selected_idx = st.number_input(
                    "Entry index",
                    min_value=0,
                    max_value=len(filtered)-1,
                    value=0
                )
                st.json(filtered[selected_idx])

# ============================================================
# PAGE 5 - ABOUT GUARDIAN
# ============================================================
elif page == "ℹ️ About Guardian":
    st.title("ℹ️ About Guardian")
    st.divider()

    col_left, col_right = st.columns(2)

    with col_left:
        st.subheader("What is Guardian?")
        st.markdown("""
        Guardian is an enterprise-grade, **Human-in-the-Lead** AI governance platform
        for detecting, assessing, and remediating personally identifiable information (PII)
        across structured and unstructured data repositories.

        Built as a reference architecture for trust and estate management operations,
        Guardian demonstrates how AI can **augment — not replace** — the professional
        judgement of Data Quality Officers.

        **Guardian recommends. Humans decide.**

        No irreversible action is taken without explicit DQO approval.
        """)

        st.subheader("Design Philosophy")
        st.markdown("""
        Guardian was designed using **Backward Design** — a pedagogical framework
        applied to AI solution architecture. Rather than starting with technology,
        Guardian started with five questions a DQO needs to answer:

        → Where is our highest-risk information right now?
        → Which findings need my review?
        → What actions have been taken, and who authorised them?
        → Which legislation applies to each finding?
        → Can I produce this audit trail for a regulator?

        Every component exists because one of those questions required it.
        """)

    with col_right:
        st.subheader("Technology Stack")
        tech_data = {
            'Component': [
                'PII Detection',
                'AI Triage',
                'Offline Fallback',
                'Database',
                'Audit Logging',
                'Interface'
            ],
            'Technology': [
                'Azure AI Language',
                'Azure AI Foundry — Phi-4',
                'Python Regex (Australian patterns)',
                'SQLite',
                'JSONL — Privacy by Design',
                'Streamlit'
            ],
            'Purpose': [
                'Entity recognition — TFN, Medicare, names, addresses',
                'Natural language risk assessment',
                'Continuous operation without internet',
                '100 synthetic estate records',
                'PII hashed, legislation auto-referenced',
                'DQO governance interface'
            ]
        }
        st.dataframe(pd.DataFrame(tech_data), use_container_width=True, hide_index=True)

        st.subheader("Relevant Legislation")
        st.markdown("""
        - **Privacy Act 1988 (Cth)** — Tax File Number Rule, APP 11, Notifiable Data Breaches
        - **Information Privacy Act 2009 (Qld)** — IPP 1, IPP 4
        - **QGEA** — Information Asset Custodianship Policy
        - **ISO 27001** — Information Security Management
        - **ACSC Essential Eight** — Cybersecurity Framework
        """)

        st.subheader("Microsoft Well-Architected Framework")
        waf_items = [
            ("🔄 Reliability", "Three-tier safety net — Azure, regex, fail-safe"),
            ("🔒 Security", "Privacy by design — PII hashed, secrets in .env"),
            ("💰 Cost", "Free F0 tier — documented S-tier production path"),
            ("📊 Operations", "Full JSONL audit trail with legislation references"),
            ("⚡ Performance", "Modular pipeline — completes in under 30 seconds"),
        ]
        for pillar, detail in waf_items:
            st.markdown(f"**{pillar}** — {detail}")

    st.divider()
    st.subheader("Social Architecture Considerations")
    st.markdown("""
    Guardian is designed with awareness that AI deployment reshapes **authority, knowledge,
    and governance structures** — not just technical workflows.

    | Design Decision | Social Architecture Rationale |
    |---|---|
    | HITL gate | Preserves DQO authority over consequential decisions |
    | Offline mode | Prevents knowledge atrophy when Azure is unavailable |
    | Audit explainability | DQOs learn from every review — expertise is preserved |
    | Provisional thresholds | Co-design with DQOs required before production |
    | Training review mode | Deliberate manual review quotas maintain scanning skills |

    *Backward design tells you what to build toward.*
    *Social architecture tells you what not to destroy along the way.*
    """)

    st.divider()
    st.caption("Guardian · Built by Deborrah David · github.com/debdavid/guardian · AI-103 aligned · SC-500 aligned")