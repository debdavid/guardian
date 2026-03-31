# pii_scanner.py
# Purpose: Scan text for PII and return structured results
# with risk scores, redacted text, and audit entries.
#
# Two modes:
#   Online: Uses Azure AI Language - accurate, enterprise-grade
#   Offline: Uses regex patterns - keeps app functional without Azure
#
# Why two modes?
# Enterprise systems must be resilient. If Azure goes down,
# The Public Trustee cannot stop processing estates.
# Graceful degradation is a non-functional requirement (NFR).
#
# Microsoft Learn - Azure AI Language PII detection:
# https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/overview
#
# Australian Privacy Act 1988 - TFN Rule:
# https://www.legislation.gov.au/Details/C2021C00139

import re
import os
import json
from datetime import datetime
from dotenv import load_dotenv

# Load environment variables from .env file
# This is to access Azure keys without hardcoding them 
load_dotenv()

# ============================================================
# RISK CONFIGURATION
# Based on Australian Privacy Act 1988 and Queesland
# Government Information Security Policy
#
# Queensland Government Information Security Policy:
# https://www.qgcio.qld.gov.au/products/qgea-documents
# ============================================================

# Risk levels assigned to each PII category
# These drive the overall risk score and HITL routing
PII_RISK_LEVELS = {
    # CRISTICAL - own legislation, mandatory breach notification
    'AUTaxFileNumber': 'CRITICAL',
    'AUMedicareNumber': 'CRITICAL',

    # HIGH - direct financial fraud possible
    'CreditCardNumber': 'HIGH',
    'AUBankAccountNumber': 'HIGH',
    'PhoneNumber': 'HIGH',
    'Email': 'HIGH',

    # MEDIUM - risk multiplier, dangerous in combination
    'Person': 'MEDIUM',
    'Address': 'MEDIUM',
    'Date': 'MEDIUM',
    'IPAddress': 'MEDIUM',
    'Organisation': 'MEDIUM',

    # LOW - contextual risk only
    'Age': 'LOW',
    'Gender': 'LOW',
    'Nationality': 'LOW', 
}

# Risk scores used to calculate overall document risk
RISK_SCORES = {
    'CRITICAL: 2.0,'
    'HIGH': 1.0,
    'MEDIUM': 0.5,
    'LOW': 0.1
}

# Threshold abov whi h DQO human review is required
# Architect decision: 3.0 means finsing 2 CRISTICAL items
HITL_THRESHOLD = 3.0

# Confidence threshold for auto-redaction vs human review
# Below this score, human must verify before redacting
CONFIDENCE_THRESHOLD = 0.70

def redact_text(text: str, findings: list) -> str:
        """
        Replaces detected PII with category labels.
        
        Examples:
        Input: "Call John on 0412 345 678"
        Output: "Call John on [PhoneNumber]"

        Why [CATEGORY] labels instead of *** or XXXXX?
        Labels tell the DQO WHAT was redacted, not just THAT
        something was redacted. This enables better decisions.

        Why process in reverse order?
        Replacing text changes character positions. If we replace
        left to right, positions after the first replacement are
        wrong. Reverse order means each replacement doesn't affect
        positions of remaining replacements.

        Privacy by design reference:
        https://www.oaic.gov.au/privacy/privacy-guidance-for-organisations-and-government-agencies/privacy-impact-assessments
        """

        # If nothing was found, return original text unchanged
        if not findings:
            return text # no PII found, nothing to redact
        
        # Sort finding by offset in REVERSE order
        # Critical: must replace from end to start
        # Otherwise replacing earlier text shifts later positions
        sorted_findings = sorted(
            findings,
            key=lambda f: f['offset'],  # sort by character position
            reverse=True        # highest position first
        )

        # Work on a mutable version of the text
        redacted = text # start with original 

        for finding in sorted_findings:
            start = finding['offset']   # where PII starts
            end = start + finding['length']  # where PII ends
            label = f"[{finding['category']}]"  # replacement label

            # Replace the PII with the label
            # text[:start] = everything BEFORE the PII
            # label = the replacement
            # text[end:] = everything AFTER the PII
            redacted = redacted[:start] + label + redacted[end:]

        return redacted # return the cleaned text

def scan_pii_offline(text: str, context: str = "unknown") -> dict:
    """
    Offline PII scanner using regex patterns.
    Runs when Azure AI Language is unavailable.
    
    Why regex for offline mode?
    - Zero dependencies - no internet needed
    - Transparent and auditable - anyone can read a regex
    - Fast - no API call latency
    - Catches obvious PII patterns reliably
    
    Limitation: Less accurate than Azure AI Language.
    Cannot detect names or organisations reliably.
    Always flags offline mode in results for transparency.
    
    Reges reference:
    https://docs.python.org/3/library/re.html
    """

    # Australian-specific PII patterns
    # Each pattern is a tuple: (category, regex_pattern, risk_level)
    patterns = [
        (
            'AUTaxFileNumber',
            r'\b\d{3}\s?\d{3}\s?\d{3}\b',
            'CRITICAL'
        ),
        (
            'AUMedicareNumber',
            r'\b[2-6]\d{9,10}\b',
            'CRITICAL'
        ),
        (
            'Email',
            r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'HIGH'
        ),
        (
            'CreditCardNumber',
            r'\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b',
            'HIGH'
        ),
        (
            'AUBankAccountNumber',
            r'\b\d{3}-?\d{3}\s\d{6,10}\b',
            'HIGH'
        ),
        (
            'Date',
            r'\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b',
            'MEDIUM'
        ),
        (
            'IPAddress',
            r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b',
            'MEDIUM'
        )   
    ]

    findings = []

    for category, pattern, risk_level in patterns:
        # Fina all matches in the text
        matches = re.finditer(pattern, text)

        for match in matches:
            finding = {
                'category': category,
                'text': match.group(),
                'offset': match.start(),
                'length': len(match.group()),
                'confidence_score': 0.75,
                'risk_level': risk_level,
                'risk_score': RISK_SCORES.get(risk_level, 0.1),
                'source_context': context,
                'detection_method': 'regex_offline'
            }
            findings.append(finding)

    # Calculate overall document risk score
    total_risk = sum(f['risk_score'] for f in findings)
    overall_risk = min(total_risk, 5.0)

    return {
        'pii_found': len(findings) > 0,
        'finding_count': len(findings),
        'findings': findings,
        'overall_risk_score': round(overall_risk, 2),
        'requires_human_review': overall_risk > HITL_THRESHOLD,
        'redacted_text': redact_text(text, findings),
        'scan_mode': 'OFFLINE',
        'timestamp': datetime.now().isoformat(),
        'source_context': context,
        'limitation': 'Offline regex scan - names and organisations not detected'
    }

def scan_pii_online(text: str, context: str = "unknown") -> dict:
    """
    Online PII scanner using Azure AI Language.
    Runs when Azure is available.
    More accurate than offline - detects names, organisations,
    and Australian-specific identifiers linke TFN and Medicare.
    
    Azure AI Language PII docs:
    https://learn.microsoft.com/en-us/azure/ai-services/language-service/personally-identifiable-information/overview
    """

    # Import Azure SDK here, inside the function
    # Why here and not at the top of the file?
    # If Azure SDK isn't installed, the whole file crashes on import.
    # Importing inside the function means offline mode still works
    # even if the Azure library has an issue.
    from azure.ai.textanalytics import TextAnalyticsClient
    from azure.core.credentials import AzureKeyCredential

    # Read credentials from .env file
    # os.getenv reads environment variables loaded by load_dotenv()
    # The second argument is the default if the variable isn't found
    endpoint = os.getenv('AZURE_LANGUAGE_ENDPOINT', '') # your endpoint URL
    key = os.getenv('AZURE_LANGUAGE_KEY', '') # API key 

    # Validate credentials exist before making API call
    # Why validate? A clear error message is better than 
    # a cryptic Azure authentication error 3 lines later
    if not endpoint or not key:
        print("WARNING: Azure credentials not found in .env file")
        print("Falling back to offline mode...")
        return scan_pii_offline(text, context) 
    
    # Create the Azure client
    # AzureKeyCredential wraps your key in a secure credential object
    # TextAnalyticsClient is the connection to Azure AI Language
    credential = AzureKeyCredential(key)
    client = TextAnalyticsClient(
        endpoint=endpoint,       # where to connect
        credential=credential    # how to authenticate
    )

    # Call Azure PII recognition
    # Why wrap in try/except?
    # Network calls can fail - timeout, Azure outage, wrong credentials.
    # try/except catches the error gracefully instead of crashing.
    try:
        # Azure expects a list of documents even for one document
        # Why a list? Azure is designed for batch processing -
        # you can send 100 documents in one call for efficiency
        documents = [text]

        response = client.recognize_pii_entities(
            documents,
            language="en",        
            categories_filter=[         # only check categoris we care about 
                "Person",
                "PhoneNumber",
                "Email",
                "Address",
                "Date",
                "AUTaxFileNumber",
                "CreditCardNumber",
                "AUBankAccountNumber",
                "IPAddress",
                "Organization"
            ]
        )

        findings = [] # empty basket - ready to collect results

        # Process each document result
        # We only sent one document but Azure returns a list
        for doc in response:

            # Always check for errors first
            #Azure returns errors per-document, not as exceptions
            # Without this check, accessing doc.entities on an
            # error object causes AttributeError and crashes
            if doc.is_error:
                print(f"Azure error: {doc.error.message}")
                return scan_pii_offline(text, context) # fallback
            
            # Process each detected entity
            for entity in doc.entities:

                # Look up risk level from our configuration
                # .get() with default means unknown categories get LOW risk
                risk_level = PII_RISK_LEVELS.get(entity.category, 'LOW')
                risk_score = RISK_SCORES.get(risk_level, 0.1)

                finding = {
                    'category': entity.category,
                    'text': entity.text,
                    'offset': entity.offset,
                    'length': entity.length,
                    'confidence_score': entity.confidence_score,
                    'risk_level': risk_level,
                    'risk_score': risk_score,
                    'source_context': context,
                    'detection_method': 'azure_online'
                }
                findings.append(finding)

        # Calculate overall risk score for the whole document
        total_risk = sum(f['risk_score'] for f in findings)
        overall_risk = min(total_risk, 5.0)

        return {
            'pii_found': len(findings) > 0,
            'finding_count': len(findings),
            'findings': findings,
            'overall_risk_score': round(overall_risk, 2),
            'requires_human_review': overall_risk > HITL_THRESHOLD,
            'redacted_text': redact_text(text, findings),
            'scan_mode': 'ONLINE',
            'timestamp': datetime.now().isoformat(),
            'scan_mode': 'ONLINE',
            'timestamp': datetime.now().isoformat(),
            'source_context': context
        }

    # This runs if ANYTHING in the try block fails
    except Exception as e:
        # Log the error so we know what happened
        print(f"Azure scan failed: {str(e)}")
        print("Falling back to offline mode...")
        # Graceful degradation - use offline instead of crashing
        return scan_pii_offline(text, context)

def scan_text_for_pii(text: str, context: str = "unknown") -> dict:
    """
    Main PII scanning function.
    Automatically chooses online or offline mode.
    
    This is the ONLY function other files need to call.
    They don't need to know which mode is running - 
    they just call this and get consistent results back.
    
    This pattern is called abstraction - hiding complexity
    behind a simple interface. A core architecture principle.
    
    Microsoft Learn - Well Architected Framework:
    https://learn.microsoft.com/en-us/azure/well-architected/
    """

    # Check if Azure credentials exist in .env file
    endpoint = os.getenv('AZURE_LANGUAGE_ENDPOINT', '')
    key = os.getenv('AZURE_LANGUAGE_KEY', '')
    
    # Decide which mode to use
    azure_available = bool(endpoint and key) 

    if azure_available:
        # Both credentials present - attempt online scan
        print(f"Scanning with Azure AI Language: {context}")
        return scan_pii_online(text, context) # returns online results
    else:
        # Missing credentials - use offline mode
        print(f"Scanning in offline mode: {context}")
        return scan_pii_offline(text, context) # returns offline results
    
if __name__ == "__main__":
    # This block only runs when you execute pii_scanner.py directly
    # It does NOT run when main.py imports this file
    # This is how we test this file in isolation

    print("="*50)
    print("GUARDIAN PII Scanner - Test Run")
    print("="*50)

    # Test text simulating a Public Trustee document
    # Deliberately contains multiple PII types
    test_text = """
    Estate File: QPT-0042
    Beneficiary: Margaret Johnson
    Date of Birth: 15/03/1962
    TFN: 432 567 891
    Medicare: 29876543210
    Email: margaret.johnson@gmail.com
    Phone: 0412 345 678
    Address: 42 Coronation Drive, Toowong QLD 4066
    BSB: 124-001 Account: 12345678
    Notes: Client contacted 12/03/2026 regarding estate distribution.
    """

    print("\nTest document:")
    print(test_text)
    print("\nScanning for PII...")
    print("-"*50)

    # Run the scan
    result = scan_text_for_pii(test_text, context="test_document")

    # Display results
    print(f"\nScan mode: {result['scan_mode']}")
    print(f"PII found: {result['pii_found']}")
    print(f"Total findings: {result['finding_count']}")
    print(f"Overall risk score: {result['overall_risk_score']}/5.0")
    print(f"Requires human review: {result['requires_human_review']}")

    print(f"\nFindings breakdown:")
    for finding in result['findings']:
        print(f" [{finding['risk_level']}] {finding['category']}: {finding['text']}")
        print(f"       Confidence: {finding['confidence_score']}")

    print(f"\nRedacted version:")
    print(result['redacted_text'])

    print("\n" + "="*50)
    print("Test complete.")
    print("="*50)
