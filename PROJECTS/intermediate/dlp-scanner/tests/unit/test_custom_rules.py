"""
©AngelaMos | 2026
test_custom_rules.py
"""


import pytest

from dlp_scanner.detectors.rules.custom import load_custom_rules
from dlp_scanner.detectors.registry import BUILTIN_RULE_IDS


pytestmark = pytest.mark.unit


def _write(tmp_path, name: str, content: str):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir(exist_ok = True)
    (rules_dir / name).write_text(content)
    return rules_dir


def test_loads_a_valid_rule(tmp_path):
    rules_dir = _write(
        tmp_path,
        "sample.yml",
        """
        rules:
          - id: CUSTOM_BR_CPF
            name: "Brazilian CPF"
            pattern: '\\b\\d{3}\\.\\d{3}\\.\\d{3}-\\d{2}\\b'
            base_score: 0.4
            context_keywords: ["cpf"]
            compliance: ["LGPD"]
            validator: "mod11"
        """,
    )

    rules = load_custom_rules(rules_dir, builtin_rule_ids = frozenset())

    assert len(rules) == 1
    assert rules[0].rule_id == "CUSTOM_BR_CPF"
    assert rules[0].validator is not None


def test_missing_directory_returns_empty_list(tmp_path):
    rules = load_custom_rules(tmp_path / "does-not-exist")
    assert rules == []


def test_rejects_id_without_custom_prefix(tmp_path):
    rules_dir = _write(
        tmp_path,
        "bad_id.yml",
        """
        rules:
          - id: PII_SSN
            name: "Impersonating a built-in"
            pattern: '\\d{9}'
            base_score: 0.5
        """,
    )

    rules = load_custom_rules(rules_dir)

    assert rules == []


def test_rejects_id_colliding_with_builtin(tmp_path):
    rules_dir = _write(
        tmp_path,
        "collide.yml",
        """
        rules:
          - id: CUSTOM_DUPE
            name: "First"
            pattern: 'abc'
            base_score: 0.5
        """,
    )

    rules = load_custom_rules(
        rules_dir,
        builtin_rule_ids = frozenset({"CUSTOM_DUPE"}),
    )

    assert rules == []


def test_rejects_duplicate_ids_within_directory(tmp_path):
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "a.yml").write_text(
        """
        rules:
          - id: CUSTOM_DUPE
            name: "First"
            pattern: 'abc'
            base_score: 0.5
        """
    )
    (rules_dir / "b.yml").write_text(
        """
        rules:
          - id: CUSTOM_DUPE
            name: "Second"
            pattern: 'xyz'
            base_score: 0.5
        """
    )

    rules = load_custom_rules(rules_dir)

    assert len(rules) == 1


def test_rejects_catastrophic_backtracking_pattern(tmp_path):
    rules_dir = _write(
        tmp_path,
        "redos.yml",
        """
        rules:
          - id: CUSTOM_REDOS
            name: "Nested quantifier"
            pattern: '([A-Za-z]+)+@'
            base_score: 0.5
        """,
    )

    rules = load_custom_rules(rules_dir)

    assert rules == []


def test_rejects_unknown_validator(tmp_path):
    rules_dir = _write(
        tmp_path,
        "bad_validator.yml",
        """
        rules:
          - id: CUSTOM_BAD_VALIDATOR
            name: "Unknown validator"
            pattern: 'abc'
            base_score: 0.5
            validator: "does_not_exist"
        """,
    )

    rules = load_custom_rules(rules_dir)

    assert rules == []


def test_one_bad_rule_does_not_block_the_rest(tmp_path):
    rules_dir = _write(
        tmp_path,
        "mixed.yml",
        """
        rules:
          - id: BAD_NO_PREFIX
            name: "Bad"
            pattern: 'abc'
            base_score: 0.5
          - id: CUSTOM_GOOD
            name: "Good"
            pattern: 'abc'
            base_score: 0.5
        """,
    )

    rules = load_custom_rules(rules_dir)

    assert len(rules) == 1
    assert rules[0].rule_id == "CUSTOM_GOOD"


def test_custom_rules_never_collide_with_real_builtins(tmp_path):
    rules_dir = _write(
        tmp_path,
        "impersonate.yml",
        """
        rules:
          - id: PII_EMAIL
            name: "Trying to override the real email rule"
            pattern: '.*'
            base_score: 1.0
        """,
    )

    rules = load_custom_rules(
        rules_dir,
        builtin_rule_ids = BUILTIN_RULE_IDS,
    )

    assert rules == []