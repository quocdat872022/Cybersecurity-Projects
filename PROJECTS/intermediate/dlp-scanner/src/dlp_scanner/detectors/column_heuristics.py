"""
©AngelaMos | 2026
column_heuristics.py

Database schema column names are a strong metadata signal for sensitive
data: a column named "ssn" in an "employees" table is almost certainly
storing Social Security Numbers even before the data itself is inspected.

This module maps glob-style column name patterns to the detection rule
IDs they imply, so the database scanner can apply a modest pre-boost to
matches found in columns whose names are suggestive of sensitive content.

The boost is deliberately modest (+0.20 by default): column names are a
strong signal but not definitive evidence (a column named "ssn_backup_old"
might be empty, encrypted, or otherwise not contain live SSNs), so this
augments rather than replaces content-based detection.
"""


import fnmatch


COLUMN_NAME_BOOST: float = 0.20

# rule_id -> glob patterns (matched against the lowercased column name)
COLUMN_NAME_RULE_PATTERNS: dict[str, list[str]] = {
    "PII_SSN": [
        "*ssn*",
        "*social_sec*",
        "*social_security*",
    ],
    "FIN_CREDIT_CARD_VISA": [
        "*credit_card*",
        "*card_num*",
        "*card_number*",
        "*cc_num*",
        "*pan*",
    ],
    "FIN_CREDIT_CARD_MC": [
        "*credit_card*",
        "*card_num*",
        "*card_number*",
        "*cc_num*",
        "*pan*",
    ],
    "FIN_CREDIT_CARD_AMEX": [
        "*credit_card*",
        "*card_num*",
        "*card_number*",
        "*cc_num*",
        "*pan*",
    ],
    "FIN_CREDIT_CARD_DISC": [
        "*credit_card*",
        "*card_num*",
        "*card_number*",
        "*cc_num*",
        "*pan*",
    ],
    "PII_EMAIL": [
        "*email*",
        "*e_mail*",
    ],
    "PII_DOB": [
        "*dob*",
        "*date_of_birth*",
        "*birthday*",
        "*birth_date*",
        "*patient_dob*",
    ],
    "PII_PHONE": [
        "*phone*",
        "*mobile*",
        "*cell*",
        "*telephone*",
    ],
    "PII_PHONE_INTL": [
        "*phone*",
        "*mobile*",
        "*cell*",
        "*telephone*",
    ],
    "FIN_IBAN": [
        "*iban*",
        "*bank_account*",
        "*account_num*",
        "*account_number*",
    ],
    "HEALTH_MEDICAL_RECORD": [
        "*mrn*",
        "*medical_record*",
        "*patient_id*",
        "*chart_num*",
    ],
    "PII_PASSPORT_US": [
        "*passport*",
    ],
    "PII_PASSPORT_UK": [
        "*passport*",
    ],
    "PII_DRIVERS_LICENSE": [
        "*driver*license*",
        "*drivers_license*",
        "*dl_num*",
        "*dl_number*",
    ],
    "PII_DRIVERS_LICENSE_FL": [
        "*driver*license*",
        "*drivers_license*",
        "*dl_num*",
        "*dl_number*",
    ],
    "PII_DRIVERS_LICENSE_IL": [
        "*driver*license*",
        "*drivers_license*",
        "*dl_num*",
        "*dl_number*",
    ],
}


def matched_column_pattern(
    column_name: str,
    rule_id: str,
) -> str | None:
    """
    Return the glob pattern that matched this column name for a
    rule, or None if the column name gives no signal for that rule
    """
    if not column_name:
        return None

    patterns = COLUMN_NAME_RULE_PATTERNS.get(rule_id)
    if not patterns:
        return None

    normalized = column_name.strip().lower()
    for pattern in patterns:
        if fnmatch.fnmatch(normalized, pattern):
            return pattern

    return None


def column_name_boost(
    column_name: str,
    rule_id: str,
    boost: float = COLUMN_NAME_BOOST,
) -> float:
    """
    Return the confidence boost to apply given a column name's
    similarity to the sensitive-data pattern implied by a rule
    """
    if matched_column_pattern(column_name, rule_id) is not None:
        return boost
    return 0.0