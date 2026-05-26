"""
pii_extended.py
---------------
Extended PII detection rules not covered by the core pii.py ruleset.

Currently contains:
  - DATE_OF_BIRTH_RULE  (HIPAA identifier #5, GDPR personal data)

Design notes
~~~~~~~~~~~~
Date strings are *extremely* common in non-PII contexts ("Order date",
"Invoice date", "Created on", …).  To keep precision high we use:

  1. A low base_score (0.12) so a bare date match barely registers.
  2. Strong context keywords ("date of birth", "dob", "birthday", …) that
     push the score into actionable territory via the normal context-boost
     mechanism your engine applies.
  3. A validate() function that rejects calendar-impossible dates so we
     don't flag strings like "99/99/9999".
"""

import re
from dlp_scanner.detectors.base import DetectionRule
from datetime import datetime
from typing import Optional

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_MONTH_ABBR = {
    "jan": 1, "feb": 2, "mar": 3, "apr": 4,
    "may": 5, "jun": 6, "jul": 7, "aug": 8,
    "sep": 9, "oct": 10, "nov": 11, "dec": 12,
}

# Reasonable year window: 1900–current year.  Adjust upper bound as needed.
_YEAR_MIN = 1900
_YEAR_MAX = 2100


def _valid_date(year: int, month: int, day: int) -> bool:
    """Return True only if (year, month, day) is a real calendar date."""
    try:
        datetime(year, month, day)
        return _YEAR_MIN <= year <= _YEAR_MAX
    except ValueError:
        return False


def validate_date_of_birth(value: str) -> bool:
    """
    Returns True if the matched string represents
    a valid calendar date.
    """

    # --- Format 1: MM/DD/YYYY ---
    m = re.fullmatch(
        r"(?P<m1>\d{1,2})/(?P<d1>\d{1,2})/(?P<y1>\d{4})",
        value
    )
    if m:
        return _valid_date(
            int(m.group("y1")),
            int(m.group("m1")),
            int(m.group("d1")),
        )

    # --- Format 2: YYYY-MM-DD ---
    m = re.fullmatch(
        r"(?P<y2>\d{4})-(?P<m2>\d{2})-(?P<d2>\d{2})",
        value
    )
    if m:
        return _valid_date(
            int(m.group("y2")),
            int(m.group("m2")),
            int(m.group("d2")),
        )

    # --- Format 3: DD-Mon-YYYY ---
    m = re.fullmatch(
        r"(?P<d3>\d{1,2})-(?P<mon>[A-Za-z]{3})-(?P<y3>\d{4})",
        value
    )
    if m:
        month_num = _MONTH_ABBR.get(m.group("mon").lower())
        if month_num is None:
            return False

        return _valid_date(
            int(m.group("y3")),
            month_num,
            int(m.group("d3")),
        )

    return False



DATE_OF_BIRTH_PATTERN = re.compile(
    r"(?:"
    # MM/DD/YYYY
    r"\b(?:0?[1-9]|1[0-2])/(?:0?[1-9]|[12]\d|3[01])/(?:19|20)\d{2}\b"
    r"|"
    # YYYY-MM-DD
    r"\b(?:19|20)\d{2}-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12]\d|3[01])\b"
    r"|"
    # DD-Mon-YYYY
    r"\b(?:0?[1-9]|[12]\d|3[01])-"
    r"(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)-"
    r"(?:19|20)\d{2}\b"
    r")",
    re.IGNORECASE,
)

DATE_OF_BIRTH_CONTEXT = [
    # Direct labels
    "date of birth",
    "date_of_birth",
    "dateofbirth",
    "dob",
    "d.o.b",
    "d.o.b.",
    # Clinical / registration language
    "born on",
    "born:",
    "born",
    "birth date",
    "birth_date",
    "birthdate",
    "birthday",
    "patient dob",
    "patient birth",
    "member dob",
    # Form-field labels
    "age",          # lower weight – 'age' alone is weak but helps in combos
]


PII_EXTENDED_RULES: list[DetectionRule] = [
    DetectionRule(
        rule_id = "PII_DOB",
        rule_name = "US Date of Birth",
        pattern = DATE_OF_BIRTH_PATTERN,
        base_score = 0.12,
        context_keywords = DATE_OF_BIRTH_CONTEXT,
        validator = validate_date_of_birth,
        compliance_frameworks = [
            "HIPAA",
            "GDPR",
        ],
    ),
]