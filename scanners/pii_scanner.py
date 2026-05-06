# pii_scanner.py
# Purpose: Scan text for PII and return structured results
# with risk scores, redacted text, and audit-ready findings.
#
# Two modes:
#   Online: Uses Azure AI Language PII detection + Australian regex override layer
#   Offline: Uses regex patterns only
#
# Human-in-the-Lead principle:
# Guardian detects and recommends. Humans decide.

import re
import os
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

# ============================================================
# RISK CONFIGURATION
# ============================================================

PII_RISK_LEVELS = {
    # CRITICAL - highly sensitive Australian identifiers
    "AUTaxFileNumber": "CRITICAL",
    "AUMedicareNumber": "CRITICAL",

    # HIGH - fraud, identity, contact, and financial risk
    "CreditCardNumber": "HIGH",
    "AUBankAccountNumber": "HIGH",
    "PhoneNumber": "HIGH",
    "Email": "HIGH",

    # MEDIUM - contextual risk / risk multiplier
    "Person": "MEDIUM",
    "Address": "MEDIUM",
    "Date": "MEDIUM",
    "DateTime": "LOW",
    "IPAddress": "MEDIUM",
    "Organisation": "MEDIUM",
    "Organization": "MEDIUM",

    # LOW - contextual risk only
    "Age": "LOW",
    "Gender": "LOW",
    "Nationality": "LOW",
}

RISK_SCORES = {
    "CRITICAL": 2.0,
    "HIGH": 1.0,
    "MEDIUM": 0.5,
    "LOW": 0.1,
}

HITL_THRESHOLD = 3.0
CONFIDENCE_THRESHOLD = 0.70


# ============================================================
# AUSTRALIAN REGEX PATTERNS
# ============================================================

AU_REGEX_PATTERNS = [
    {
        "category": "AUTaxFileNumber",
        "pattern": r"\b\d{3}\s?\d{3}\s?\d{3}\b",
        "risk_level": "CRITICAL",
        "confidence_score": 0.95,
        "detection_method": "guardian_au_regex",
    },
    {
        "category": "AUMedicareNumber",
        "pattern": r"\b[2-6]\d{3}\s?\d{5}\s?\d\b",
        "risk_level": "CRITICAL",
        "confidence_score": 0.95,
        "detection_method": "guardian_au_regex",
    },
    {
        "category": "Email",
        "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
        "risk_level": "HIGH",
        "confidence_score": 0.90,
        "detection_method": "guardian_au_regex",
    },
    {
        "category": "PhoneNumber",
        "pattern": r"\b(?:\+61\s?|0)4\d{2}\s?\d{3}\s?\d{3}\b",
        "risk_level": "HIGH",
        "confidence_score": 0.90,
        "detection_method": "guardian_au_regex",
    },
    {
        "category": "CreditCardNumber",
        "pattern": r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        "risk_level": "HIGH",
        "confidence_score": 0.85,
        "detection_method": "guardian_au_regex",
    },
    {
        "category": "AUBankAccountNumber",
        "pattern": r"\b\d{3}-?\d{3}\s?\d{6,10}\b",
        "risk_level": "HIGH",
        "confidence_score": 0.80,
        "detection_method": "guardian_au_regex",
    },
    {
        "category": "Date",
        "pattern": r"\b\d{1,2}[\/\-]\d{1,2}[\/\-]\d{2,4}\b",
        "risk_level": "MEDIUM",
        "confidence_score": 0.75,
        "detection_method": "guardian_au_regex",
    },
    {
        "category": "IPAddress",
        "pattern": r"\b(?:\d{1,3}\.){3}\d{1,3}\b",
        "risk_level": "MEDIUM",
        "confidence_score": 0.80,
        "detection_method": "guardian_au_regex",
    },
]


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def finding_key(finding: dict) -> tuple:
    """
    Creates a stable key so duplicate findings can be removed.
    We deduplicate by exact character position and text.
    """
    return (
        finding.get("offset"),
        finding.get("length"),
        finding.get("text"),
    )


def overlaps(a: dict, b: dict) -> bool:
    """
    Returns True if two findings overlap in the original text.
    """
    a_start = a["offset"]
    a_end = a["offset"] + a["length"]

    b_start = b["offset"]
    b_end = b["offset"] + b["length"]

    return a_start < b_end and b_start < a_end


def should_keep_azure_finding(azure_finding: dict, regex_findings: list) -> bool:
    """
    Decides whether to keep an Azure AI Language finding after Guardian's
    Australian rules layer has run.

    This removes noisy or misleading Azure classifications where Guardian
    has a better local classification.
    """

    category = azure_finding.get("category")
    value = azure_finding.get("text", "").strip()
    confidence = azure_finding.get("confidence_score", 0)

    # Suppress labels that Azure may mistake for organisations.
    # In the demo text, "TFN" and "Medicare" are field labels, not organisations.
    if category in ["Organization", "Organisation"] and value.lower() in [
        "tfn",
        "tax file number",
        "medicare",
        "medicare number",
    ]:
        return False

    # Suppress low-confidence numeric date fragments, such as "15",
    # when Guardian regex has found a fuller date nearby.
    if category in ["DateTime", "Date"] and confidence < 0.70:
        if value.isdigit():
            return False

    # Suppress Azure phone findings that do not look like AU mobile numbers.
    # This prevents bank account numbers like "12345678" being shown as phones.
    if category == "PhoneNumber":
        normalised = value.replace(" ", "").replace("-", "")
        looks_like_au_mobile = (
            normalised.startswith("04")
            or normalised.startswith("+614")
            or normalised.startswith("614")
        )

        if not looks_like_au_mobile:
            # Keep it only if Guardian did not classify the same span
            # as a stronger Australian identifier.
            overlaps_guardian_critical = any(
                overlaps(azure_finding, regex_finding)
                and regex_finding["category"] in [
                    "AUTaxFileNumber",
                    "AUMedicareNumber",
                    "AUBankAccountNumber",
                    "CreditCardNumber",
                ]
                for regex_finding in regex_findings
            )

            if overlaps_guardian_critical:
                return False

            # If it is just a short digit sequence, suppress it.
            digits_only = "".join(ch for ch in value if ch.isdigit())
            if len(digits_only) < 10:
                return False

    # Suppress Azure findings that overlap with stronger Guardian regex findings.
    for regex_finding in regex_findings:
        if overlaps(azure_finding, regex_finding):
            regex_category = regex_finding["category"]

            stronger_guardian_categories = [
                "AUTaxFileNumber",
                "AUMedicareNumber",
                "AUBankAccountNumber",
                "CreditCardNumber",
                "Date",
                "PhoneNumber",
                "Email",
                "IPAddress",
            ]

            if regex_category in stronger_guardian_categories:
                return False

    return True


def apply_australian_regex_layer(
    text: str,
    existing_findings: list,
    context: str,
) -> list:
    """
    Adds Guardian's Australian-specific classification layer.

    Azure AI Language provides broad PII detection.
    Guardian AU rules correct and strengthen classification for
    Australian identifiers such as TFN, Medicare and mobile numbers.
    """

    regex_findings = []

    for item in AU_REGEX_PATTERNS:
        for match in re.finditer(item["pattern"], text):
            category = item["category"]
            risk_level = item["risk_level"]

            regex_findings.append(
                {
                    "category": category,
                    "text": match.group(),
                    "offset": match.start(),
                    "length": len(match.group()),
                    "confidence_score": item["confidence_score"],
                    "risk_level": risk_level,
                    "risk_score": RISK_SCORES.get(risk_level, 0.1),
                    "source_context": context,
                    "detection_method": item["detection_method"],
                }
            )

    # Keep only useful Azure findings after Guardian AU rules have run.
    filtered_azure_findings = [
        finding
        for finding in existing_findings
        if should_keep_azure_finding(finding, regex_findings)
    ]

    combined = filtered_azure_findings + regex_findings

    # Remove exact duplicates.
    seen = set()
    deduped = []

    for finding in combined:
        key = finding_key(finding)
        if key not in seen:
            seen.add(key)
            deduped.append(finding)

    # Sort by original text order.
    deduped.sort(key=lambda f: f["offset"])

    return deduped


def redact_text(text: str, findings: list) -> str:
    """
    Replaces detected PII with category labels.

    Example:
        Input:  "Call John on 0412 345 678"
        Output: "Call John on [PhoneNumber]"
    """

    if not findings:
        return text

    sorted_findings = sorted(
        findings,
        key=lambda f: f["offset"],
        reverse=True,
    )

    redacted = text

    for finding in sorted_findings:
        start = finding["offset"]
        end = start + finding["length"]
        label = f"[{finding['category']}]"
        redacted = redacted[:start] + label + redacted[end:]

    return redacted


def build_scan_result(
    text: str,
    findings: list,
    context: str,
    scan_mode: str,
    limitation: str = None,
) -> dict:
    """
    Builds a consistent scan result object for online and offline modes.
    """

    total_risk = sum(f["risk_score"] for f in findings)
    overall_risk = min(total_risk, 5.0)

    result = {
        "pii_found": len(findings) > 0,
        "finding_count": len(findings),
        "findings": findings,
        "overall_risk_score": round(overall_risk, 2),
        "requires_human_review": overall_risk >= HITL_THRESHOLD,
        "redacted_text": redact_text(text, findings),
        "scan_mode": scan_mode,
        "timestamp": datetime.now().isoformat(),
        "source_context": context,
    }

    if limitation:
        result["limitation"] = limitation

    return result


# ============================================================
# SCANNERS
# ============================================================

def scan_pii_offline(text: str, context: str = "unknown") -> dict:
    """
    Offline PII scanner using Guardian regex patterns.
    """

    findings = apply_australian_regex_layer(
        text=text,
        existing_findings=[],
        context=context,
    )

    return build_scan_result(
        text=text,
        findings=findings,
        context=context,
        scan_mode="OFFLINE",
        limitation="Offline regex scan - names and organisations may not be detected reliably.",
    )


def scan_pii_online(text: str, context: str = "unknown") -> dict:
    """
    Online PII scanner using Azure AI Language,
    followed by Guardian's Australian-specific regex override layer.
    """

    try:
        from azure.ai.textanalytics import TextAnalyticsClient
        from azure.core.credentials import AzureKeyCredential
    except ImportError:
        print("WARNING: Azure SDK not installed. Falling back to offline mode.")
        return scan_pii_offline(text, context)

    endpoint = os.getenv("AZURE_LANGUAGE_ENDPOINT", "")
    key = os.getenv("AZURE_LANGUAGE_KEY", "")

    if not endpoint or not key:
        print("WARNING: Azure AI Language credentials not found. Falling back to offline mode.")
        return scan_pii_offline(text, context)

    credential = AzureKeyCredential(key)
    client = TextAnalyticsClient(endpoint=endpoint, credential=credential)

    try:
        response = client.recognize_pii_entities(
            [text],
            language="en",
            categories_filter=[
                "Person",
                "PhoneNumber",
                "Email",
                "Address",
                "Date",
                "DateTime",
                "AUTaxFileNumber",
                "AUMedicareNumber",
                "CreditCardNumber",
                "AUBankAccountNumber",
                "IPAddress",
                "Organization",
            ],
        )

        azure_findings = []

        for doc in response:
            if doc.is_error:
                print(f"Azure AI Language error: {doc.error.message}")
                return scan_pii_offline(text, context)

            for entity in doc.entities:
                risk_level = PII_RISK_LEVELS.get(entity.category, "LOW")

                azure_findings.append(
                    {
                        "category": entity.category,
                        "text": entity.text,
                        "offset": entity.offset,
                        "length": entity.length,
                        "confidence_score": entity.confidence_score,
                        "risk_level": risk_level,
                        "risk_score": RISK_SCORES.get(risk_level, 0.1),
                        "source_context": context,
                        "detection_method": "azure_language_pii",
                    }
                )

        final_findings = apply_australian_regex_layer(
            text=text,
            existing_findings=azure_findings,
            context=context,
        )

        return build_scan_result(
            text=text,
            findings=final_findings,
            context=context,
            scan_mode="ONLINE_PLUS_GUARDIAN_AU_RULES",
        )

    except Exception as e:
        print(f"Azure AI Language scan failed: {str(e)}")
        print("Falling back to offline mode.")
        return scan_pii_offline(text, context)


def scan_text_for_pii(text: str, context: str = "unknown") -> dict:
    """
    Main PII scanning interface.

    Other Guardian modules should call this function only.
    It decides whether to use Azure AI Language or offline regex.
    """

    endpoint = os.getenv("AZURE_LANGUAGE_ENDPOINT", "")
    key = os.getenv("AZURE_LANGUAGE_KEY", "")

    azure_available = bool(endpoint and key)

    if azure_available:
        print(f"Scanning with Azure AI Language + Guardian AU rules: {context}")
        return scan_pii_online(text, context)

    print(f"Scanning in offline mode: {context}")
    return scan_pii_offline(text, context)


# ============================================================
# LOCAL TEST
# ============================================================

if __name__ == "__main__":
    print("=" * 50)
    print("GUARDIAN PII Scanner - Test Run")
    print("=" * 50)

    test_text = """
    Estate File: QPT-0042
    Beneficiary: Margaret Johnson
    Date of Birth: 15/03/1962
    TFN: 432 567 891
    Medicare: 2987 65432 1
    Email: margaret.johnson@gmail.com
    Phone: 0412 345 678
    Address: 42 Coronation Drive, Toowong QLD 4066
    BSB: 124-001 Account: 12345678
    Notes: Client contacted 12/03/2026 regarding estate distribution.
    """

    print("\nTest document:")
    print(test_text)
    print("\nScanning for PII...")
    print("-" * 50)

    result = scan_text_for_pii(test_text, context="test_document")

    print(f"\nScan mode: {result['scan_mode']}")
    print(f"PII found: {result['pii_found']}")
    print(f"Total findings: {result['finding_count']}")
    print(f"Overall risk score: {result['overall_risk_score']}/5.0")
    print(f"Requires human review: {result['requires_human_review']}")

    print("\nFindings breakdown:")
    for finding in result["findings"]:
        print(f" [{finding['risk_level']}] {finding['category']}: {finding['text']}")
        print(f"       Confidence: {finding['confidence_score']}")
        print(f"       Method: {finding['detection_method']}")

    print("\nRedacted version:")
    print(result["redacted_text"])

    print("\n" + "=" * 50)
    print("Test complete.")
    print("=" * 50)