# Guardian — Data Governance & PII Remediation Platform

> An enterprise-grade, Human-in-the-Lead AI pipeline for detecting,
> assessing, and remediating personally identifiable information (PII)
> across structured and unstructured data repositories.

Built as a reference architecture for government trust and estate
management operations. Demonstrates how AI can augment — not replace —
the professional judgement of Data Quality Officers.

---

## What Guardian does

Guardian automates the discovery and risk assessment of PII across
database records and documents. It combines Azure AI Language with
offline regex fallback to ensure continuous operation regardless of
Azure availability.

For every finding, Guardian:
- Assigns a risk score based on Australian privacy legislation
- Recommends a remediation action (redact, migrate, dispose, retain, escalate)
- Routes high-risk findings to a human reviewer (DQO) for authorisation
- Writes a full audit trail with legislation references

**Guardian recommends. Humans decide.**
No irreversible action is taken without explicit DQO approval.
This is the Human-in-the-Lead principle embedded in the architecture.

---

## Architecture principles

| Principle | Implementation |
|---|---|
| Human-in-the-Lead | DQO authorises all consequential actions |
| Privacy by design | PII hashed in audit log — never stored in plain text |
| Graceful degradation | Three-tier safety net — Azure, regex, fail-safe |
| Auditability | JSONL audit log with legislation auto-referenced |
| Data sovereignty | Australia East region — data never leaves Australia |
| Cost governance | Free F0 tier for development — S tier path documented |

---

## Technology stack

- **Azure AI Language** — PII entity recognition (online mode)
- **Python regex** — offline fallback scanner
- **SQLite** — local database for synthetic estate records
- **Faker** — Australian locale synthetic data generation
- **Python** — orchestration, audit logging, pipeline management

---

## Relevant legislation

- Privacy Act 1988 (Cth) — Tax File Number Rule, APP 11
- Information Privacy Act 2009 (Qld) — IPP 1, IPP 4
- Notifiable Data Breaches scheme — mandatory breach notification
- QGEA Information Asset Custodianship policy

---

## Project structure
guardian/
├── data/
│   └── generate_data.py      # Synthetic estate record generation
├── database/
│   ├── guardian.db           # SQLite database (gitignored)
│   └── audit_log.jsonl       # Audit trail (gitignored)
├── scanners/
│   ├── pii_scanner.py        # PII detection — online and offline
│   └── sql_scanner.py        # Database scanning pipeline
├── utils/
│   └── audit_log.py          # Audit logging and reporting
└── main.py                   # Pipeline orchestrator

---

## Day 1 results

- 100 synthetic estate beneficiary records generated
- 100% PII detection rate across all records
- Azure AI Language detecting: names, addresses, TFNs,
  Medicare numbers, emails, phone numbers, bank accounts
- Offline regex detecting: TFNs, Medicare, email,
  phone, credit card, dates, IP addresses
- Full audit trail with legislation references
- Pipeline completes in ~20 seconds for 5 records

---

## Microsoft Well-Architected Framework

| Pillar | Status |
|---|---|
| Reliability | Three-tier safety net active |
| Security | Secrets in .env, PII hashed in logs, Australia East |
| Cost optimisation | Free F0 tier, offline fallback for zero-cost scanning |
| Operational excellence | Full JSONL audit trail, pipeline report |
| Performance efficiency | 20 second pipeline, batch commit pattern |

---

## Social architecture considerations

Guardian is designed with awareness that AI deployment reshapes
authority, knowledge, and governance structures — not just technical
workflows.

Key design decisions informed by this:
- HITL gate preserves DQO authority on consequential decisions
- Offline mode prevents capability atrophy when Azure is unavailable
- Audit explainability ensures DQOs learn from every review
- Thresholds are provisional — must be co-designed with DQOs
  before production deployment

A full Social Architecture Impact Assessment is planned for Day 7.

---

## Days ahead

| Day | Component |
|---|---|
| Day 1 | Data foundation + PII detection pipeline |
| Day 2 | Azure OpenAI + intelligent triage engine |
| Day 3 | Azure AI Search + RAG policy compliance engine |
| Day 4 | Security perimeter — Prompt Shield, Content Safety |
| Day 5 | LangGraph multi-agent workflow + HITL gate |
| Day 6 | Streamlit application — DQO interface and dashboard |
| Day 7 | Portfolio, Social Architecture report, exam prep |

---

*Built by Deborrah David — AI & Data Consultant (Solution Architecture)*
*Azure AI Engineer Associate (in progress) · Master of Applied Data Science, Monash University*