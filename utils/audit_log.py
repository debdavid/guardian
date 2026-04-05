# audit_log.py
# Purpose: Record every Guardian scan, decision, and action to a structured JSON audit log.
#
# Why a separate audit log module?
# Audit logging is a cross-cutting concern - every part of
# Guardian needs it. Centralising it here means one change
# updates logging everywhere. This is the DRY principle.
#
# Why JSON format?
# JSON is human-readable, machine-parseable, and universally
# supported. An audito, a developer, or another system can
# all read the same file without special tools.
#
# Relevant policy:
# QGEA Information Asset Custodianship:
# https://www.qgcio.qld.gov.au/products/qgea-documents
#
# Australian Privacy Act 1988 - accountability principle:
# https://www.legislation.gov.au/Details/C2021C00139

import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path

# Audit log file location
# Path() creates a cross-platform file path
# Works on Mac, Windows, and Linux without changing the code
AUDIT_LOG_PATH = Path('database/audit_log.jsonl')

# JASONL = JSON Lines format
# Each line is a complete, valid JSON object
# Why JSONL instead of a single JSON array?
# You can append one line at a time without reading the whole file
# A single JSON array requires reading and rewriting everything
# At scale with thousands of entries, JSONL is significantly faster 

def write_audit_log(
    event_type: str,
    scan_result: dict,
    action_taken: str = None,
    reviewed_by: str = None,
    ai_recommendation: str = None,
    human_decision: str = None,
    override_reason: str = None,
    notes: str = None    
) -> dict:
    """
    Writes one entry to the audit log.

    Called after every scan, every HITL decision,
    and every remediation action.

    Why so many optional parameters?
    Not every event has all fields. A scan event
    has no human_decision yet. A HITL decision event
    has no scan_result details. Optional parameters
    with None defaults handle this cleanly without
    requiring separate functions for each event type.
    """

    # Build the audit entry
    entry = {
        # Unique identifier for this log entry
        # timestamp + event_type makes it unique and sortable
        'log_id': "AUD-" + datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S%f'),

        # When this event occurred - always UTC for consistency
        # Why UTC and not local time?
        # A government trust operates across timezones.
        # UTC is unambiguous. Local time creates confusion
        # during daylight saving changes.
        'timestamp': datetime.now(timezone.utc).isoformat(),

        # What type of event this is
        # Examples: PII_DETECTED, HITL_TRIGGERED,
        # DQO_APPROVED, DQO_REJECTED, ACTION_EXECUTED
        'event_type': event_type,
    
        # Which scan mode was running - ONLINE or OFFLINE
        'scan_mode': scan_result.get('scan_mode', 'UNKNOWN'),
    
        # Where the scanned content came from
        'source_context': scan_result.get('source_context', 'UNKNOWN'),
    
        # Was PII found?
        'pii_found': scan_result.get('pii_found', False),
        
        # Overall risk score
        'overall_risk_score': scan_result.get('overall_risk_score', 0.0),
    
        # Did this trigger the HITL gate?
        'hitl_triggered': scan_result.get('requires_human_review', False),
    
        # Summary of findings - category and risk level only
        # Why not store the actual PTT text?
        # The audit log itself could become a PII exposure.
        # We log THAT a TFN was found, not WHAT the TFN was.
        # This is privacy by design - protecting PII even
        # in the governance records about PII.
        'findings_summary': [
            {
                'category': f['category'],
                'risk_level': f['risk_level'],
                'confidence': f['confidence_score'],
                # Hash the actual text - proves it was found
                # without storing the sensitive value itself
                'text_hash': hashlib.sha256(
                    f['text'].encode()
                ).hexdigest()[:16]
            }
            for f in scan_result.get('findings',[])
        ],
        
        # Human review fields - populated when DQO acts
        'reviewed_by': reviewed_by,
        'ai_recommendation': ai_recommendation,
        'human_decision': human_decision,

        # Did the DQO override Guardian's recommendation?
        'human_overrode_ai': (
            human_decision != ai_recommendation
            if human_decision and ai_recommendation
            else None
        ),
    
        # Why did the DQO override? Required if overriding.
        'override_reason': override_reason,
    
        # What action was taken
        # REDACT / MIGRATE / DISPOSE / RETAIN / ESCALATE
        'action_taken': action_taken,
    
       # Any additional context
       'notes': notes,
    
       # Which legislation applies to this finding
       # Automatically assigned based on what was found
       'legislation_reference': get_legislation_reference(
           scan_result.get('findings', [])
       )
    }

    
    # Write to audit log file
    # 'a' mode = append - adds to end without overwiting
    # Why append and not write?
    # Write would erase the entire log every time.
    # Append adds one line, preserving all previous entries.
    AUDIT_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)

    with open(AUDIT_LOG_PATH, 'a') as f:
        # json.dumps converts dict to JSON string
        # ensure_ascii=False allows Australian characters
        f.write(json.dumps(entry, ensure_ascii=False) + '\n')

    return entry

def get_legislation_reference(findings: list) -> str:
    """
    Returns the most relevant legislation reference
    based on what PII was found.

    Why automate this?
    A DQO shouldn't need to remember which law applies
    to which PII type. Guardian surfaces it automatically
    so every audit entry is legally grounded from the start.
    """

    # Check for the highest-risk categories first
    # Order matters - we return the most serious legislation
    categories = [f['category'] for f in findings]

    if 'AUTaxFileNumber' in categories:
        return(
            "Privacy Act 1988 (Cth) - Tax File Number Rule; "
            "Information Privacy Act 2009 (Qld) - IPP 4"
        )
    
    if 'AUMedicareNumber' in categories:
        return (
            "Privacy Act 1988 (Cth) - APP 11; "
            "Information PRivacy Act 2009 (Qld) - IPP 4"
        )
    
    if any(c in categories for c in [
        'CreditCardNumber',
        'AUBankAccountNumber'
    ]):
        return (
            "Privacy Act 1988 (Cth) - APP 11; "
            "Notifiable Data Breaches Scheme"
        )
    
    if any(c in categories for c in [
        'Person', 'Address', 'PhoneNumber', 'Email'
    ]):
        return "Information Privacy Act 2009 (Qld) - IPP 1, IPP 4"
    
    # Default if nothing specific matched
    return "Information Privacy Act 2009 (Qld) - IPP 4"

def read_audit_log(limit: int = 100) -> list:
    """
    Reads the most recent entries from the audit log.
    Used by the Streamlit dashboard to display activity.
    
    Why limit parameter?
    At scale the log could have thousands of entries.
    Loading all of them into memory for a dashboard
    is wasteful. We only need the most recent ones.
    Default of 100 is enough for a dashboard view.
    
    Parameters:
        limit: int - maximum number of entries to return
    
    Returns:
        list of audit log entries as dictionaries,
        most recent first
    """
    
    # Return empty list if log doesn't exist yet
    # Why not crash? Because on first run the log file
    # hasn't been created yet. Returning empty list
    # lets the dashboard show "no entries yet" gracefully
    if not AUDIT_LOG_PATH.exists():
        return []
    
    entries = []
    
    # Read the file line by line
    # Why line by line and not all at once?
    # JSONL format - each line is one complete record
    # Reading line by line means we never load the
    # entire file into memory - efficient at scale
    with open(AUDIT_LOG_PATH, 'r') as f:
        for line in f:
            line = line.strip()  # remove whitespace and \n
            
            # Skip empty lines - defensive programming
            # An empty line would crash json.loads()
            if not line:
                continue
            
            try:
                # Convert JSON string back to dictionary
                # json.loads is the reverse of json.dumps
                entry = json.loads(line)
                entries.append(entry)
            except json.JSONDecodeError:
                # Skip malformed lines without crashing
                # Why? A corrupted line shouldn't stop
                # the dashboard from showing valid entries
                continue
    
    # Return most recent entries first, limited to limit
    # [-limit:] takes the last N items from the list
    # [::-1] reverses the list so newest is first
    return entries[-limit:][::-1]


def get_audit_summary() -> dict:
    """
    Returns summary statistics for the dashboard.
    Total scans, breaches found, HITL triggers, etc.
    
    Why a separate summary function?
    The dashboard needs counts, not raw entries.
    Calculating summary stats from raw entries here
    keeps the Streamlit code clean and simple.
    """
    
    entries = read_audit_log(limit=10000)  # get everything
    
    if not entries:
        return {
            'total_scans': 0,
            'pii_found_count': 0,
            'hitl_triggered_count': 0,
            'critical_findings': 0,
            'human_overrides': 0,
            'actions_taken': {}
        }
    
    # Count each metric using list comprehensions
    # [x for x in list if condition] filters a list
    total_scans = len(entries)
    
    pii_found = len([
        e for e in entries
        if e.get('pii_found')  # True entries only
    ])
    
    hitl_triggered = len([
        e for e in entries
        if e.get('hitl_triggered')
    ])
    
    critical_findings = len([
        e for e in entries
        if any(
            f.get('risk_level') == 'CRITICAL'
            for f in e.get('findings_summary', [])
        )
    ])
    
    human_overrides = len([
        e for e in entries
        if e.get('human_overrode_ai')
    ])
    
    # Count actions taken using a dictionary
    # This builds {'REDACT': 5, 'RETAIN': 12, ...}
    actions = {}
    for entry in entries:
        action = entry.get('action_taken')
        if action:  # skip None values
            # .get() with default 0 handles first occurrence
            actions[action] = actions.get(action, 0) + 1
    
    return {
        'total_scans': total_scans,
        'pii_found_count': pii_found,
        'hitl_triggered_count': hitl_triggered,
        'critical_findings': critical_findings,
        'human_overrides': human_overrides,
        'actions_taken': actions
    }


if __name__ == "__main__":
    # Quick test - write a sample entry and read it back
    print("Testing Guardian audit log...")
    
    # Simulate a scan result
    test_scan = {
        'scan_mode': 'OFFLINE',
        'source_context': 'test',
        'pii_found': True,
        'finding_count': 2,
        'overall_risk_score': 4.0,
        'requires_human_review': True,
        'findings': [
            {
                'category': 'AUTaxFileNumber',
                'risk_level': 'CRITICAL',
                'confidence_score': 0.95,
                'text': '432 567 891'
            }
        ]
    }
    
    # Write test entry
    entry = write_audit_log(
        event_type='PII_DETECTED',
        scan_result=test_scan,
        ai_recommendation='REDACT',
        notes='Test entry'
    )
    
    print(f"Entry written: {entry['log_id']}")
    print(f"Legislation: {entry['legislation_reference']}")
    
    # Read it back
    entries = read_audit_log(limit=5)
    print(f"Entries in log: {len(entries)}")
    
    # Summary
    summary = get_audit_summary()
    print(f"Summary: {summary}")
    

