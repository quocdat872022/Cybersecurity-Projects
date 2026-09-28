"""
©AngelaMos | 2026
body_features.py

Feature extraction over free-form text (Challenge 5:
Request Body Analysis via Error Logs)

extract_body_features computes entropy, length, attack
pattern matches, encoded-char detection, and special
character ratio over arbitrary text — typically the
message field of a ParsedErrorEntry, which sometimes
carries the payload that triggered the error (an oversized
or malformed body, a Content-Type exploit, or an injection
payload upstream rejected)

These are a supplementary, error-log-only feature set. They
are NOT part of the 35-dim FEATURE_ORDER used by the ML
ensemble — folding them in would require expanding the
feature vector and retraining all 3 models (see learn/
04-CHALLENGES.md, Challenge 5). They're surfaced alongside
correlated access-log context for analyst triage and
logging instead

Connects to:
  core/features/
    patterns        - ATTACK_COMBINED, ENCODED_CHARS
  core/ingestion/
    error_parsers   - ParsedErrorEntry.message is the
                      typical input
  core/ingestion/
    error_pipeline  - calls this per parsed error entry
"""

import math
from collections import Counter

from app.core.features.patterns import ATTACK_COMBINED, ENCODED_CHARS


def _shannon_entropy(s: str) -> float:
    """
    Compute Shannon entropy of a string.
    """
    if not s:
        return 0.0
    length = len(s)
    counts = Counter(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def extract_body_features(text: str) -> dict[str, int | float | bool]:
    """
    Extract entropy, length, and attack-pattern signals from free-form text.
    """
    non_alnum = sum(1 for c in text if not c.isalnum())
    length = len(text)

    return {
        "body_length": length,
        "body_entropy": _shannon_entropy(text),
        "body_special_char_ratio": non_alnum / length if length else 0.0,
        "body_has_encoded_chars": bool(ENCODED_CHARS.search(text)),
        "body_has_attack_pattern": bool(ATTACK_COMBINED.search(text)),
    }