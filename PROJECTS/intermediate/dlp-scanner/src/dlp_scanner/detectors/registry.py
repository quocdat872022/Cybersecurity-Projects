"""
©AngelaMos | 2026
registry.py
"""


import fnmatch
from pathlib import Path

from dlp_scanner.detectors.base import (
    DetectionRule,
    DetectorMatch,
)
from dlp_scanner.detectors.context import (
    apply_context_boost,
)
from dlp_scanner.detectors.entropy import EntropyDetector
from dlp_scanner.detectors.pattern import PatternDetector
from dlp_scanner.detectors.rules.credentials import (
    CREDENTIAL_RULES,
)
from dlp_scanner.detectors.rules.custom import load_custom_rules
from dlp_scanner.detectors.rules.financial import (
    FINANCIAL_RULES,
)
from dlp_scanner.detectors.rules.health import HEALTH_RULES
from dlp_scanner.detectors.rules.pii import PII_RULES
from dlp_scanner.detectors.rules.pii_extended import PII_EXTENDED_RULES



ALL_RULES: list[DetectionRule] = [
    *PII_RULES,
    *PII_EXTENDED_RULES,
    *FINANCIAL_RULES,
    *CREDENTIAL_RULES,
    *HEALTH_RULES,
]

BUILTIN_RULE_IDS: frozenset[str] = frozenset(r.rule_id for r in ALL_RULES)


class DetectorRegistry:
    """
    Central registry that loads, filters, and runs all detectors

    Rules come from two sources: the built-in Python rule modules
    (ALL_RULES) and, optionally, user-authored YAML rules loaded
    from `custom_rules_dir`. Custom rules are namespaced under
    CUSTOM_ and can never override a built-in rule id -- see
    detectors/rules/custom.py for the full safety model.
    """
    def __init__(
        self,
        enable_patterns: list[str] | None = None,
        disable_patterns: list[str] | None = None,
        allowlist_values: frozenset[str] | None = None,
        context_window_tokens: int = 10,
        entropy_threshold: float = 7.2,
        enable_entropy: bool = True,
        custom_rules_dir: str | Path | None = None,
    ) -> None:
        custom_rules: list[DetectionRule] = []
        if custom_rules_dir:
            custom_rules = load_custom_rules(
                custom_rules_dir,
                builtin_rule_ids = BUILTIN_RULE_IDS,
            )

        combined_rules = [*ALL_RULES, *custom_rules]

        active_rules = _filter_rules(
            combined_rules,
            enable_patterns or ["*"],
            disable_patterns or [],
        )

        self._pattern_detector = PatternDetector(
            rules = active_rules,
            allowlist_values = allowlist_values,
        )
        self._entropy_detector = (
            EntropyDetector(threshold = entropy_threshold)
            if enable_entropy else None
        )
        self._context_window = context_window_tokens
        self._custom_rule_count = len(custom_rules)

    def detect(self, text: str) -> list[DetectorMatch]:
        """
        Run all detectors against text and return scored matches
        """
        matches = self._pattern_detector.detect(text)
        matches = apply_context_boost(
            text,
            matches,
            window_tokens = self._context_window,
        )

        if self._entropy_detector is not None:
            entropy_matches = (self._entropy_detector.detect(text))
            matches.extend(entropy_matches)

        return matches

    @property
    def rule_count(self) -> int:
        """
        Return the number of active pattern rules
        """
        return len(self._pattern_detector._rules)

    @property
    def custom_rule_count(self) -> int:
        """
        Return the number of successfully loaded custom rules
        """
        return self._custom_rule_count


def _filter_rules(
    rules: list[DetectionRule],
    enable_patterns: list[str],
    disable_patterns: list[str],
) -> list[DetectionRule]:
    """
    Filter rules by enable/disable glob patterns
    """
    filtered: list[DetectionRule] = []

    for rule in rules:
        enabled = any(
            fnmatch.fnmatch(rule.rule_id,
                            pat) for pat in enable_patterns
        )
        disabled = any(
            fnmatch.fnmatch(rule.rule_id,
                            pat) for pat in disable_patterns
        )
        if enabled and not disabled:
            filtered.append(rule)

    return filtered