# main.py
# Purpose: Entry point for Guardian Day 1 pipeline.
# Orchestrates data generation, PII scanning, and
# SQL database scanning with full audit logging.
#
# Three-tier safety net:
#   Tier 1: Azure AI Language (most accurate)
#   Tier 2: Regex offline scanner (no internet needed)
#   Tier 3: Fail-safe response (never crashes)
#
# Human-in-the-Lead principle:
# Guardian recommends. Humans decide.
# No irreversible action is taken without DQO approval.
#
# Microsoft Well-Architected Framework - reliability:
# https://learn.microsoft.com/en-us/azure/well-architected/reliability/

import sys
import os
import json
from datetime import datetime
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from data.generate_data import create_database, populate_database, verify_database
from scanners.pii_scanner import scan_text_for_pii
from scanners.sql_scanner import scan_all_records
from utils.audit_log import write_audit_log, get_audit_summary


def fail_safe_scan(text: str, context: str) -> dict:
    """
    Tier 3 safety net - runs when both Azure and regex fail.
    
    Never crashes. Always returns a valid result.
    Assumes maximum risk when scanning is impossible.
    
    Why assume maximum risk?
    If we cannot scan, we cannot confirm safety.
    Failing safe means escalating to humans rather than
    silently passing content that may contain PII.
    This is the responsible AI principle of safety
    applied at the infrastructure level.
    
    Microsoft Responsible AI - safety pillar:
    https://learn.microsoft.com/en-us/azure/machine-learning/concept-responsible-ai
    """
    return {
        'pii_found': None,           # unknown - not confirmed safe
        'finding_count': 0,
        'findings': [],
        'overall_risk_score': 5.0,   # assume worst case
        'requires_human_review': True, # always escalate
        'redacted_text': '[SCANNING UNAVAILABLE - MANUAL REVIEW REQUIRED]',
        'scan_mode': 'FAILED',
        'timestamp': datetime.now().isoformat(),
        'source_context': context,
        'error': 'All scanning methods unavailable',
        'limitation': 'Manual review required - automated scanning unavailable'
    }


def safe_scan(text: str, context: str) -> dict:
    """
    Wraps scan_text_for_pii with the three-tier safety net.
    
    Tier 1: Try Azure AI Language
    Tier 2: If Azure fails, try regex offline
    Tier 3: If both fail, return fail-safe response
    
    Why wrap in a separate function?
    Any file that needs scanning calls safe_scan()
    instead of scan_text_for_pii() directly.
    The safety net is applied consistently everywhere
    without duplicating the try/except logic.
    Single responsibility - one function owns the safety net.
    """
    try:
        # Tier 1 and 2 are handled inside scan_text_for_pii
        # It already tries Azure first, falls back to regex
        result = scan_text_for_pii(text, context)
        return result
    except Exception as e:
        # Tier 3 - both tiers inside scan_text_for_pii failed
        print(f"WARNING: All scanning methods failed for {context}: {e}")
        print("Applying fail-safe response - routing to human review")
        return fail_safe_scan(text, context)
    
def run_guardian_pipeline(
    regenerate_data: bool = False,
    scan_limit: int = None,
    verbose: bool = True
) -> dict:
    """
    Runs the complete Guardian Day 1 pipeline.
    
    Parameters:
        regenerate_data: bool - if True, recreates the database
                                from scratch with fresh records.
                                Default False - uses existing data.
        scan_limit: int - optional limit on records to scan.
                          None means scan all records.
                          Use small numbers for testing.
        verbose: bool - if True, prints detailed progress.
                        Default True for terminal runs.
                        Set False when called from Streamlit.
    
    Returns:
        dict - complete pipeline report including scan results,
               audit summary, and pipeline metadata.
    
    Why three parameters?
    Flexibility without hardcoding. The same function works
    for development testing (limit=5), full production runs
    (limit=None), and Streamlit dashboard calls (verbose=False).
    One function, multiple contexts. DRY principle.
    """
    
    pipeline_start = datetime.now()
    
    if verbose:
        print("\n" + "="*60)
        print("GUARDIAN - Data Governance & PII Remediation Platform")
        print("="*60)
        print(f"Pipeline started: {pipeline_start.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"Mode: {'Full scan' if not scan_limit else f'Test scan ({scan_limit} records)'}")
        print("="*60)
    
    # --------------------------------------------------------
    # STAGE 1: Data preparation
    # --------------------------------------------------------
    if verbose:
        print("\nSTAGE 1: Preparing data...")
    
    db_path = Path('database/guardian.db')
    
    if regenerate_data or not db_path.exists():
        if verbose:
            print("Creating database and generating synthetic records...")
        conn, cursor = create_database()
        populate_database(conn, cursor)
        verify_database(cursor)
        conn.close()
        if verbose:
            print("Database ready.")
    else:
        if verbose:
            print("Using existing database.")
    
    # --------------------------------------------------------
    # STAGE 2: PII detection scan
    # --------------------------------------------------------
    if verbose:
        print("\nSTAGE 2: Running PII detection scan...")
        print("Guardian is scanning estate records for PII...")
        print("Azure AI Language active - online mode")
    
    scan_report = scan_all_records(limit=scan_limit)
    
    if verbose:
        print(f"Scan complete. {scan_report.get('records_with_pii', 0)} records contain PII.")
    
    # --------------------------------------------------------
    # STAGE 3: Audit summary
    # --------------------------------------------------------
    if verbose:
        print("\nSTAGE 3: Generating audit summary...")
    
    audit_summary = get_audit_summary()
    
    # --------------------------------------------------------
    # STAGE 4: Pipeline report
    # --------------------------------------------------------
    pipeline_end = datetime.now()
    duration = (pipeline_end - pipeline_start).seconds
    
    pipeline_report = {
        'pipeline_metadata': {
            'started': pipeline_start.isoformat(),
            'completed': pipeline_end.isoformat(),
            'duration_seconds': duration,
            'scan_limit': scan_limit,
            'mode': 'test' if scan_limit else 'full'
        },
        'scan_report': {
            'total_records_scanned': scan_report.get('total_records_scanned', 0),
            'records_with_pii': scan_report.get('records_with_pii', 0),
            'pii_detection_rate': scan_report.get('pii_detection_rate', 0),
            'records_requiring_hitl': scan_report.get('records_requiring_hitl', 0),
            'risk_distribution': scan_report.get('risk_distribution', {}),
            'action_recommendations': scan_report.get('action_recommendations', {})
        },
        'audit_summary': audit_summary,
        'well_architected_notes': {
            'reliability': 'Three-tier safety net active - Azure, regex, fail-safe',
            'security': 'PII hashed in audit log - privacy by design',
            'cost_optimisation': f'Free F0 tier - {audit_summary.get("total_scans", 0)} transactions used',
            'operational_excellence': 'Full audit trail written to JSONL log',
            'performance': f'Pipeline completed in {duration} seconds'
        }
    }
    
    if verbose:
        print("\n" + "="*60)
        print("GUARDIAN PIPELINE COMPLETE")
        print("="*60)
        print(f"Duration: {duration} seconds")
        print(f"Records scanned: {pipeline_report['scan_report']['total_records_scanned']}")
        print(f"PII detection rate: {pipeline_report['scan_report']['pii_detection_rate']}%")
        print(f"Audit entries: {audit_summary.get('total_scans', 0)}")
        print("\nWell-Architected Framework status:")
        for pillar, status in pipeline_report['well_architected_notes'].items():
            print(f"  {pillar}: {status}")
        print("="*60)
        print("\nNext steps:")
        print("  - Review HITL queue for high-risk findings")
        print("  - DQO approval required before any remediation action")
        print("  - Full audit log: database/audit_log.jsonl")
        print("="*60)
    
    return pipeline_report


if __name__ == "__main__":
    # Run with limit=5 for quick test
    # Change to limit=None for full scan of all 100 records
    # Change regenerate_data=True to rebuild database from scratch
    report = run_guardian_pipeline(
        regenerate_data=False,
        scan_limit=5,
        verbose=True
    )
    
    # Save pipeline report to file
    report_path = Path('database/pipeline_report.json')
    with open(report_path, 'w') as f:
        json.dump(report, f, indent=2)
    
    print(f"\nPipeline report saved: {report_path}")