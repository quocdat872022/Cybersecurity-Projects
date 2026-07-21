"""
©AngelaMos | 2026
validators.py

Registry of named validator functions that custom (YAML-defined)
rules can reference by string instead of writing Python. Built-in
Python rules (financial.py, health.py, ...) keep their own local
validator functions; this module exists specifically so that
`validator: "luhn"` in a rule YAML file resolves to a real callable.
"""


from collections.abc import Callable

import structlog


log = structlog.get_logger()

Validator = Callable[[str], bool]

VALIDATOR_REGISTRY: dict[str, Validator] = {}


def register_validator(name: str) -> Callable[[Validator], Validator]:
    """
    Decorator that adds a validator function to the named registry
    """
    def decorator(fn: Validator) -> Validator:
        if name in VALIDATOR_REGISTRY:
            log.warning(
                "validator_name_redefined",
                name = name,
            )
        VALIDATOR_REGISTRY[name] = fn
        return fn

    return decorator


@register_validator("luhn")
def luhn_check(value: str) -> bool:
    """
    Validate a number using the Luhn algorithm

    Applies to most major credit card numbers.
    """
    digits = [int(d) for d in value if d.isdigit()]
    if len(digits) < 13:
        return False

    odd_digits = digits[-1 ::-2]
    even_digits = digits[-2 ::-2]
    total = sum(odd_digits)
    for d in even_digits:
        total += sum(divmod(d * 2, 10))
    return total % 10 == 0


@register_validator("mod97")
def mod97_check(value: str) -> bool:
    """
    Validate an alphanumeric identifier using the mod-97 algorithm

    This is the ISO 7064 MOD 97-10 scheme used by IBAN numbers:
    move the first four characters to the end, convert letters to
    numbers (A=10 ... Z=35), and check the result mod 97 == 1.
    """
    cleaned = "".join(ch for ch in value if ch.isalnum()).upper()
    if len(cleaned) < 15 or len(cleaned) > 34:
        return False

    rearranged = cleaned[4 :] + cleaned[: 4]
    numeric_chars: list[str] = []
    for char in rearranged:
        if char.isalpha():
            numeric_chars.append(str(ord(char) - ord("A") + 10))
        else:
            numeric_chars.append(char)

    try:
        return int("".join(numeric_chars)) % 97 == 1
    except ValueError:
        return False


@register_validator("mod11")
def mod11_check(value: str) -> bool:
    """
    Validate a numeric identifier using a generic mod-11 checksum

    Treats the final digit as a check digit, weights the remaining
    digits by descending place value starting at len(body) + 1, and
    compares 11 - (sum mod 11) against the check digit (mapping a
    result of 10 or 11 to 0, the common convention). This is a
    generic mod-11 scheme; it is not a substitute for a
    country-specific algorithm (e.g. Brazilian CPF has its own
    two-check-digit procedure) but is useful as a default/example
    validator for user-authored rules.
    """
    digits = [int(d) for d in value if d.isdigit()]
    if len(digits) < 2:
        return False

    check_digit = digits[-1]
    body = digits[:-1]
    weights = range(len(body) + 1, 1, -1)
    total = sum(d * w for d, w in zip(body, weights, strict = False))
    remainder = total % 11
    expected = 11 - remainder
    if expected >= 10:
        expected = 0
    return expected == check_digit


@register_validator("none")
def no_validation(value: str) -> bool:  # noqa: ARG001
    """
    Always-pass validator for rules that only want regex + context
    """
    return True


def get_validator(name: str | None) -> Validator | None:
    """
    Resolve a validator by name, raising for unknown names

    Returns None (meaning "no validator") when name is None or
    empty, matching DetectionRule.validator semantics.
    """
    if not name:
        return None

    try:
        return VALIDATOR_REGISTRY[name]
    except KeyError as exc:
        raise ValueError(
            f"Unknown validator '{name}'. Available validators: "
            f"{', '.join(sorted(VALIDATOR_REGISTRY))}"
        ) from exc