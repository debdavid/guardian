# sql_scanner.py
# Purpose: Scan every record in the SQLite database
# for PII and log findings to the audit trail.
#
# Why scan structured database records?
# PII doesn't only live in documents. It lives in
# databases, spreadsheets, and structured systems.
# A complete governance solution scans both.
#
# This file connects three Guardian components:
#   1. SQLite database (generate_data.py created it)
#   2. PII scanner (pii_scanner.py detects PII)
#   3. Audit log (audit_log.py records findings)
#
# Microsoft Learn - data governance:
# https://learn.microsoft.com/en-us/azure/purview/
#
# Queensland Government data quality framework:
# https://www.qgcio.qld.gov.au/products/qgea-documents

import sqlite3
import json
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


from datetime import datetime
from pathlib import Path

# Import our own Guardian modules
# Why relative imports using 'from'?
# These files are in the same project.
# We import specific functions we need rather than
# the whole module - keeps memory usage efficient.
from scanners.pii_scanner import scan_text_for_pii
from utils.audit_log import write_audit_log, read_audit_log

# Database location
DB_PATH = Path('database/guardian.db')

# Fields that contain PII and should be scanned
# Why not scan every field?
# Fields like 'record_id', 'estate_id', 'estate_status'
# are system identifiers with no PII risk.
# Scanning only PII-relevant fields reduces cost
# and processing time - an architect decision.
PII_FIELDS = [
    'first_name',
    'middle_name', 
    'last_name',
    'date_of_birth',
    'email',
    'phone_number',
    'address',
    'suburb',
    'tfn',
    'medicare_number',
    'bank_bsb',
    'bank_account',
    'notes'
]

def scan_record(record: dict) -> dict:
    """
    Scans one estate record for PII across all PII fields.
    
    Why scan field by field instead of the whole record?
    Scanning field by field tells us exactly WHICH field
    contains PII. Scanning the whole record as one blob
    would find PII but not tell us where it lives.
    Knowing WHERE the PII is determines the remediation
    action - you can't redact a specific field if you
    don't know which one it's in.
    
    Parameters:
        record: dict - one row from the database
        
    Returns:
        dict - scan results for this record including
        all field-level findings and overall risk score
    """
    
    record_id = record.get('estate_id', 'UNKNOWN')
    field_findings = []
    total_risk = 0.0
    
    # Scan each PII field individually
    for field_name in PII_FIELDS:
        field_value = record.get(field_name)
        
        # Skip empty fields - nothing to scan
        # Why check for None AND empty string?
        # Database can return either for missing values
        if not field_value or str(field_value).strip() == '':
            continue
        
        # Convert to string - some fields may be numbers
        # str() converts integers and floats to scannable text
        text_to_scan = str(field_value)
        
        # Scan this specific field
        # context tells the scanner where this text came from
        context = f"database_field:{record_id}:{field_name}"
        result = scan_text_for_pii(text_to_scan, context=context)
        
        # Only record fields where PII was actually found
        if result['pii_found']:
            field_finding = {
                'field_name': field_name,
                'field_value_redacted': result['redacted_text'],
                'findings': result['findings'],
                'field_risk_score': result['overall_risk_score'],
                'scan_mode': result['scan_mode']
            }
            field_findings.append(field_finding)
            total_risk += result['overall_risk_score']
    
    # Cap total risk at 5.0
    overall_risk = min(total_risk, 5.0)
    
    # Build the complete record scan result
    record_result = {
        'estate_id': record_id,
        'record_id': record.get('record_id'),
        'full_name': f"{record.get('first_name', '')} {record.get('last_name', '')}".strip(),
        'data_classification': record.get('data_classification'),
        'remediation_status': record.get('remediation_status'),
        'fields_scanned': len(PII_FIELDS),
        'fields_with_pii': len(field_findings),
        'field_findings': field_findings,
        'overall_risk_score': round(overall_risk, 2),
        'requires_human_review': overall_risk > 3.0,
        'scan_timestamp': datetime.now().isoformat(),
        
        # Recommended action based on risk score
        # This is Guardian's recommendation - not a decision
        # A DQO must approve before any action is taken
        'recommended_action': get_recommended_action(
            overall_risk,
            record.get('data_classification', 'Internal')
        )
    }
    
    # Write to audit log
    # Convert record_result to scan_result format
    # that write_audit_log expects
    audit_scan_result = {
        'scan_mode': field_findings[0]['scan_mode'] if field_findings else 'ONLINE',
        'source_context': f"database_record:{record_id}",
        'pii_found': len(field_findings) > 0,
        'finding_count': sum(len(f['findings']) for f in field_findings),
        'overall_risk_score': overall_risk,
        'requires_human_review': overall_risk > 3.0,
        'findings': [
            finding
            for field in field_findings
            for finding in field['findings']
        ]
    }
    
    write_audit_log(
        event_type='DATABASE_RECORD_SCANNED',
        scan_result=audit_scan_result,
        ai_recommendation=record_result['recommended_action']
    )
    
    return record_result


def get_recommended_action(
    risk_score: float,
    data_classification: str
) -> str:
    """
    Recommends a remediation action based on risk score
    and data classification.
    
    Why combine both factors?
    A TFN in a Restricted document is expected and correct.
    The same TFN in a Public document is a critical breach.
    Risk score alone doesn't capture context - classification
    does. Both together give a more accurate recommendation.
    
    This recommendation is NEVER automatically executed.
    A named DQO must approve every action.
    That is the Human-in-the-Lead principle in code.
    """
    
    # Critical risk - always escalate regardless of classification
    if risk_score >= 4.0:
        return 'ESCALATE'
    
    # High risk - action depends on classification
    if risk_score >= 2.0:
        if data_classification in ['Public', 'Internal']:
            # PII in a public or internal document is wrong
            return 'MIGRATE'
        else:
            # PII in confidential/restricted may be legitimate
            return 'RETAIN'
    
    # Medium risk - review and retain unless misclassified
    if risk_score >= 1.0:
        if data_classification == 'Public':
            return 'REDACT'
        return 'RETAIN'
    
    # Low risk - retain
    return 'RETAIN'

def scan_all_records(limit: int = None) -> dict:
    """
    Scans all estate records in the database.
    
    Parameters:
        limit: int - optional, scan only first N records
                     useful for testing without scanning all 100
                     None means scan everything
    
    Returns:
        dict - complete scan report with summary statistics
    
    Why return a report rather than just print results?
    The report dict can be used by multiple consumers:
    - main.py prints it to terminal
    - Streamlit displays it as a dashboard
    - The audit log stores it as a record
    One function, multiple uses. DRY principle.
    """
    
    # Check database exists before trying to open it
    if not DB_PATH.exists():
        print("ERROR: Database not found.")
        print("Run: python data/generate_data.py first")
        return {}
    
    # Connect to database
    conn = sqlite3.connect(DB_PATH)
    
    # Why row_factory?
    # By default SQLite returns rows as tuples: (1, 'John', ...)
    # Row factory makes rows behave like dictionaries: {'id': 1, 'name': 'John'}
    # Dictionary access by name is cleaner and less error-prone
    # than tuple access by position
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    
    # Build the SQL query
    # Why build it dynamically?
    # The LIMIT clause is optional - we only add it if limit is set
    # This avoids running two separate queries for limited vs full scan
    query = "SELECT * FROM estate_records"
    if limit:
        query += f" LIMIT {limit}"  # add limit if specified
    
    cursor.execute(query)
    records = cursor.fetchall()  # get all matching rows
    conn.close()                 # always close after fetching
    
    print(f"\nStarting Guardian database scan...")
    print(f"Records to scan: {len(records)}")
    print("="*50)
    
    # Tracking variables for the summary report
    scan_results = []
    total_pii_found = 0
    total_hitl_required = 0
    action_counts = {
        'ESCALATE': 0,
        'MIGRATE': 0,
        'REDACT': 0,
        'RETAIN': 0
    }
    risk_distribution = {
        'critical': 0,   # score >= 4.0
        'high': 0,       # score >= 2.0
        'medium': 0,     # score >= 1.0
        'low': 0         # score < 1.0
    }
    
    # Scan each record
    for i, record in enumerate(records, start=1):
        # Convert Row object to regular dict
        # dict(record) works because Row supports dict conversion
        record_dict = dict(record)
        
        # Progress indicator - shows every 10 records
        # Why show progress?
        # Scanning 100 records takes time. Without feedback
        # the user thinks the program has frozen.
        if i % 10 == 0 or i == 1:
            print(f"Scanning record {i}/{len(records)}...")
        
        # Scan this record
        result = scan_record(record_dict)
        scan_results.append(result)
        
        # Update summary counters
        if result['fields_with_pii'] > 0:
            total_pii_found += 1
        
        if result['requires_human_review']:
            total_hitl_required += 1
        
        # Count recommended actions
        action = result['recommended_action']
        if action in action_counts:
            action_counts[action] += 1
        
        # Categorise risk level
        score = result['overall_risk_score']
        if score >= 4.0:
            risk_distribution['critical'] += 1
        elif score >= 2.0:
            risk_distribution['high'] += 1
        elif score >= 1.0:
            risk_distribution['medium'] += 1
        else:
            risk_distribution['low'] += 1
    
    # Build the complete report
    report = {
        'scan_timestamp': datetime.now().isoformat(),
        'total_records_scanned': len(records),
        'records_with_pii': total_pii_found,
        'records_requiring_hitl': total_hitl_required,
        'pii_detection_rate': round(
            total_pii_found / len(records) * 100, 1
        ) if records else 0,
        'hitl_rate': round(
            total_hitl_required / len(records) * 100, 1
        ) if records else 0,
        'action_recommendations': action_counts,
        'risk_distribution': risk_distribution,
        'individual_results': scan_results
    }
    
    # Print summary to terminal
    print("\n" + "="*50)
    print("GUARDIAN DATABASE SCAN COMPLETE")
    print("="*50)
    print(f"Records scanned:        {report['total_records_scanned']}")
    print(f"Records with PII:       {report['records_with_pii']}")
    print(f"PII detection rate:     {report['pii_detection_rate']}%")
    print(f"Requiring HITL review:  {report['records_requiring_hitl']}")
    print(f"\nRisk distribution:")
    print(f"  Critical: {risk_distribution['critical']}")
    print(f"  High:     {risk_distribution['high']}")
    print(f"  Medium:   {risk_distribution['medium']}")
    print(f"  Low:      {risk_distribution['low']}")
    print(f"\nRecommended actions:")
    for action, count in action_counts.items():
        print(f"  {action}: {count}")
    print("="*50)
    
    return report


if __name__ == "__main__":
    # Test by scanning first 5 records only
    # Why only 5 for testing?
    # Each scan calls Azure AI Language - costs transactions.
    # Testing with 5 keeps cost near zero while proving
    # the system works before scanning all 100.
    print("Guardian SQL Scanner - Test Run")
    print("Scanning first 5 records only for testing...")
    
    report = scan_all_records(limit=5)
    
    if report:
        print(f"\nTest complete.")
        print(f"Scan saved to audit log.")
        print(f"Full scan: python scanners/sql_scanner.py")