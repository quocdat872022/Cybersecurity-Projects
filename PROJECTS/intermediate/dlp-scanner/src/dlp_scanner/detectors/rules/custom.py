"""
©AngelaMos | 2026
custom.py

Loader for user-defined detection rules written in YAML instead of
Python. See rules/README.md for the schema and rules/examples/ for
sample rule files.

Safety model
------------
Custom rules are user-supplied and therefore untrusted input, so
this loader treats every rule as potentially hostile:

  * rule ids must be namespaced under CUSTOM_ so they can never
    shadow or override a built-in rule id
  * patterns are rejected outright if they match a known
    catastrophic-backtracking shape (nested quantified groups)
  * every pattern that passes the static check is still probed
    against adversarial strings in an isolated process with a hard
    wall-clock timeout; a pattern that doesn't finish in time is
    rejected rather than trusted
  * a single malformed rule (bad schema, bad pattern, unknown
    validator) is logged and skipped -- it never aborts loading the
    rest of the file or the rest of the rules directory
"""


from __future__ import annotations

import re
import threading
from multiprocessing import Process, Queue
from pathlib import Path
from typing import Any

import structlog
from pydantic import BaseModel, Field, ValidationError, field_validator
from ruamel.yaml import YAML

from dlp_scanner.constants import Severity
from dlp_scanner.detectors.base import DetectionRule
from dlp_scanner.detectors.validators import get_validator
from dlp_scanner.constants import CUSTOM_RULE_PREFIX, MAX_PATTERN_LENGTH, REDOS_PROBE_TIMEOUT_SECONDS


# Adversarial inputs used to smoke-test a pattern before it is
# trusted with real scan data. None of these are "correct" matches
# for any legitimate rule; they exist purely to make a
# catastrophically backtracking pattern spin.
_REDOS_PROBES: tuple[str, ...] = (
    "a" * 32 + "!",
    "a" * 48 + "X",
    ("ab" * 24) + "!",
    " " * 40 + "\t",
)

# Classic catastrophic-backtracking shape: a group that is itself
# quantified, containing content that is *also* quantified, e.g.
# (a+)+, (a*)*, (\d+)*, ([a-z]+)+. This is a heuristic, not a
# formal proof of ReDoS safety -- it's the cheap first filter
# before the more expensive dynamic probe below.
_NESTED_QUANTIFIER_RE = re.compile(r"\([^()]*[+*][^()]*\)[+*]")


log = structlog.get_logger()



class CustomRuleSpec(BaseModel):
    """
    Schema for a single user-defined rule entry in a rules YAML file
    """
    id: str
    name: str
    pattern: str = Field(max_length = MAX_PATTERN_LENGTH)
    base_score: float = Field(ge = 0.0, le = 1.0)
    context_keywords: list[str] = Field(default_factory = list)
    compliance: list[str] = Field(default_factory = list)
    validator: str | None = None
    severity_override: Severity | None = None

    @field_validator("id")
    @classmethod
    def _id_is_namespaced_and_valid(cls, value: str) -> str:
        """
        Enforce the CUSTOM_ namespace so user rules can never shadow
        or override a built-in rule id
        """
        if not re.fullmatch(r"[A-Z0-9_]+", value):
            raise ValueError(
                "Rule id must be upper snake case "
                "(letters, digits, underscore only), "
                f"got '{value}'"
            )
        if not value.startswith(CUSTOM_RULE_PREFIX):
            raise ValueError(
                f"Custom rule id must start with "
                f"'{CUSTOM_RULE_PREFIX}' so it cannot collide "
                f"with a built-in rule id, got '{value}'"
            )
        return value


def load_custom_rules(
    rules_dir: str | Path,
    builtin_rule_ids: frozenset[str] = frozenset(),
) -> list[DetectionRule]:
    """
    Load and validate every *.yml/*.yaml rule file in a directory

    Missing or non-directory paths return an empty list rather than
    raising, since custom rules are an optional feature.
    """
    path = Path(rules_dir)
    if not path.exists() or not path.is_dir():
        return []

    yaml = YAML(typ = "safe")
    loaded: list[DetectionRule] = []
    seen_ids: set[str] = set()

    rule_files = sorted({*path.glob("*.yml"), *path.glob("*.yaml")})

    for rule_file in rule_files:
        try:
            raw = yaml.load(rule_file) or {}
        except Exception as exc:
            log.warning(
                "custom_rules_file_unreadable",
                path = str(rule_file),
                error = str(exc),
            )
            continue

        entries = raw.get("rules", []) if isinstance(raw, dict) else []
        if not isinstance(entries, list):
            log.warning(
                "custom_rules_file_malformed",
                path = str(rule_file),
                reason = "'rules' key must be a list",
            )
            continue

        for entry in entries:
            rule = _load_one(entry, rule_file, builtin_rule_ids, seen_ids)
            if rule is not None:
                loaded.append(rule)
                seen_ids.add(rule.rule_id)

    log.info(
        "custom_rules_loaded",
        count = len(loaded),
        directory = str(path),
    )
    return loaded


def _load_one(
    entry: Any,
    source_file: Path,
    builtin_rule_ids: frozenset[str],
    seen_ids: set[str],
) -> DetectionRule | None:
    """
    Validate and compile a single rule entry, or return None
    """
    try:
        spec = CustomRuleSpec.model_validate(entry)
    except ValidationError as exc:
        log.warning(
            "custom_rule_schema_invalid",
            path = str(source_file),
            error = str(exc),
        )
        return None

    if spec.id in builtin_rule_ids:
        log.warning(
            "custom_rule_shadows_builtin",
            rule_id = spec.id,
            path = str(source_file),
        )
        return None

    if spec.id in seen_ids:
        log.warning(
            "custom_rule_duplicate_id",
            rule_id = spec.id,
            path = str(source_file),
        )
        return None

    rule = _spec_to_rule(spec, source_file)
    if rule is None:
        log.warning(
            "custom_rule_rejected",
            rule_id = spec.id,
            path = str(source_file),
        )
        return None

    return rule


def _spec_to_rule(
    spec: CustomRuleSpec,
    source_file: Path,
) -> DetectionRule | None:
    """
    Convert a validated spec into a compiled DetectionRule
    """
    compiled = _compile_safe(spec.pattern, rule_id = spec.id)
    if compiled is None:
        return None

    try:
        validator = get_validator(spec.validator)
    except ValueError as exc:
        log.warning(
            "custom_rule_unknown_validator",
            rule_id = spec.id,
            path = str(source_file),
            error = str(exc),
        )
        return None

    return DetectionRule(
        rule_id = spec.id,
        rule_name = spec.name,
        pattern = compiled,
        base_score = spec.base_score,
        context_keywords = spec.context_keywords,
        validator = validator,
        compliance_frameworks = spec.compliance,
        severity_override = spec.severity_override,
    )


# --------------------------------------------------------------- #
# ReDoS-safe compilation
# --------------------------------------------------------------- #


def _compile_safe(
    pattern_str: str,
    rule_id: str,
) -> re.Pattern[str] | None:
    """
    Compile a user-supplied pattern only if it passes safety checks
    """
    if len(pattern_str) > MAX_PATTERN_LENGTH:
        log.warning(
            "custom_rule_pattern_too_long",
            rule_id = rule_id,
            length = len(pattern_str),
        )
        return None

    if _NESTED_QUANTIFIER_RE.search(pattern_str):
        log.warning(
            "custom_rule_pattern_nested_quantifier",
            rule_id = rule_id,
            pattern = pattern_str,
        )
        return None

    try:
        compiled = re.compile(pattern_str)
    except re.error as exc:
        log.warning(
            "custom_rule_pattern_invalid_regex",
            rule_id = rule_id,
            pattern = pattern_str,
            error = str(exc),
        )
        return None

    if not _is_pattern_timing_safe(pattern_str):
        log.warning(
            "custom_rule_pattern_redos_suspected",
            rule_id = rule_id,
            pattern = pattern_str,
        )
        return None

    return compiled


def _is_pattern_timing_safe(pattern_str: str) -> bool:
    """
    Smoke-test a pattern against adversarial probes under a timeout

    Runs each probe in an isolated child process so that a
    catastrophically backtracking match can actually be killed
    rather than just abandoned in-process (which would leak a
    spinning thread indefinitely). Falls back to a best-effort
    daemon-thread timeout if process isolation is unavailable in
    the current environment (e.g. some sandboxes disallow fork).
    """
    for probe in _REDOS_PROBES:
        if not _probe_with_process(pattern_str, probe):
            return False
    return True


def _match_worker(
    pattern_str: str,
    probe: str,
    result_queue: "Queue[bool]",
) -> None:
    """
    Child-process entry point: compile and match, report success
    """
    try:
        re.compile(pattern_str).search(probe)
        result_queue.put(True)
    except Exception:
        result_queue.put(False)


def _probe_with_process(pattern_str: str, probe: str) -> bool:
    """
    Run one ReDoS probe in a killable child process

    Returns False (unsafe) if the process times out, crashes, or
    process isolation itself is unavailable and the threaded
    fallback also times out.
    """
    try:
        result_queue: "Queue[bool]" = Queue()
        proc = Process(
            target = _match_worker,
            args = (pattern_str, probe, result_queue),
            daemon = True,
        )
        proc.start()
    except Exception as exc:
        log.warning(
            "custom_rule_process_isolation_unavailable",
            error = str(exc),
        )
        return _probe_with_thread(pattern_str, probe)

    proc.join(REDOS_PROBE_TIMEOUT_SECONDS)

    if proc.is_alive():
        proc.terminate()
        proc.join(0.1)
        if proc.is_alive():
            proc.kill()
        return False

    try:
        return bool(result_queue.get_nowait())
    except Exception:
        return False


def _probe_with_thread(pattern_str: str, probe: str) -> bool:
    """
    Best-effort fallback timeout using a daemon thread

    A regex match stuck in catastrophic backtracking cannot be
    forcibly killed from Python threading, so a timed-out thread is
    simply abandoned (it will keep burning CPU on that one probe
    until the interpreter exits, or effectively forever). This path
    only runs when process isolation itself failed to start, and it
    still correctly rejects the pattern rather than trusting it.
    """
    done = threading.Event()

    def _run() -> None:
        try:
            re.compile(pattern_str).search(probe)
        except Exception:
            pass
        finally:
            done.set()

    thread = threading.Thread(target = _run, daemon = True)
    thread.start()
    finished = done.wait(REDOS_PROBE_TIMEOUT_SECONDS)
    return finished