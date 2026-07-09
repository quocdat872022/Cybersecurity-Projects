"""
©AngelaMos | 2026
auth.py

JWT and password utilities

Handles Argon2id password hashing and verification, JWT creation
and decoding, Bearer token extraction from requests, and informational
password strength assessment used at registration time.

Key exports:
  hash_password - Argon2id hash of a plaintext password
  verify_password - verify and optionally rehash if Argon2 params are stale
  verify_password_timing_safe - constant-time wrapper used at login
  create_access_token - sign a JWT with user_id as subject
  decode_access_token - verify and decode a JWT
  extract_bearer_token - pull token from Authorization header or query param
  check_password_strength - informational strength/entropy assessment

Connects to:
  config.py - reads SECRET_KEY, JWT_ALGORITHM, JWT_EXPIRATION_HOURS
  core/decorators/endpoint.py - calls decode_access_token, extract_bearer_token
  controllers/auth_ctrl.py - calls hash_password, verify_password, create_access_token,
    check_password_strength
  cli.py - calls hash_password
"""

import math
import re
from pathlib import Path
from typing import Any
from datetime import (
    datetime,
    timedelta,
    UTC,
)

import jwt
from flask import request
from pwdlib import PasswordHash

from app.config import settings


password_hasher = PasswordHash.recommended()

DUMMY_HASH = password_hasher.hash("dummy_password_for_timing_attack_prevention")


def hash_password(password: str) -> str:
    """
    Hash a plaintext password with Argon2id
    """
    return password_hasher.hash(password)


def verify_password(
    plain_password: str,
    hashed_password: str,
) -> tuple[bool,
           str | None]:
    """
    Verify password and return new hash if Argon2 params are outdated
    """
    try:
        return password_hasher.verify_and_update(
            plain_password,
            hashed_password,
        )
    except Exception:
        return False, None


def verify_password_timing_safe(
    plain_password: str,
    hashed_password: str | None,
) -> tuple[bool,
           str | None]:
    """
    Verify with constant-time behavior to prevent user enumeration
    """
    if hashed_password is None:
        password_hasher.verify(plain_password, DUMMY_HASH)
        return False, None
    return verify_password(plain_password, hashed_password)


def create_access_token(
    user_id: str,
    extra_claims: dict[str,
                       Any] | None = None,
) -> str:
    """
    Create a signed JWT with user_id as subject
    """
    now = datetime.now(UTC)
    payload: dict[str,
                  Any] = {
                      "sub": user_id,
                      "iat": now,
                      "exp": now + timedelta(
                          hours = settings.JWT_EXPIRATION_HOURS,
                      ),
                  }
    if extra_claims:
        payload.update(extra_claims)
    return jwt.encode(
        payload,
        settings.SECRET_KEY,
        algorithm = settings.JWT_ALGORITHM,
    )


def decode_access_token(token: str) -> dict[str, Any]:
    """
    Decode and validate a JWT returning the payload
    """
    return jwt.decode(  # type: ignore[no-any-return]
        token,
        settings.SECRET_KEY,
        algorithms = [settings.JWT_ALGORITHM],
        options = {"require": ["exp",
                               "sub",
                               "iat"]},
    )


def extract_bearer_token() -> str | None:
    """
    Extract JWT from Authorization header or query param fallback for SSE
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        return auth_header[7 :]
    return request.args.get("token")


# =============================================================================
# Password strength assessment
#
# Purely informational. Does not gate registration; the schema-level
# min_length constraint is the only hard requirement. This gives the
# frontend enough signal to nudge users toward stronger passwords.
# =============================================================================

# Curated common-password set covering the most frequently reused passwords
# and their obvious variants. If a full wordlist (e.g. SecLists' rockyou
# top 10k, one password per line) is placed at app/data/common_passwords.txt,
# it is merged in automatically at import time without any code changes.
_EMBEDDED_COMMON_PASSWORDS = frozenset({
    "password", "password1", "password123", "password1234",
    "123456", "1234567", "12345678", "123456789", "1234567890",
    "12345", "654321", "111111", "000000", "121212", "123123",
    "1q2w3e4r", "1qaz2wsx", "qazwsx", "qwerty", "qwerty123",
    "qwertyuiop", "asdfgh", "asdfghjkl", "zxcvbnm", "zxcvbn",
    "letmein", "letmein123", "welcome", "welcome1", "admin",
    "administrator", "root", "toor", "changeme", "trustno1",
    "monkey", "monkey123", "dragon", "dragon123", "master",
    "master123", "iloveyou", "iloveyou1", "iloveyou2", "sunshine",
    "princess", "princess1", "football", "football1", "baseball",
    "superman", "batman", "starwars", "abc123", "abcd1234",
    "abcdefgh", "shadow", "michael", "jennifer", "jordan23",
    "hunter2", "hunter", "freedom", "whatever", "nothing",
    "flower", "summer", "winter", "autumn", "ninja",
    "mustang", "hockey", "soccer", "biteme", "matrix",
    "cheese", "chicken", "banana", "orange", "purple",
    "asdf1234", "aaaaaa", "aaaaaaaa", "11111111", "88888888",
    "internet", "computer", "iceman", "silver", "golden",
    "yellow", "orange1", "loveme", "trustme", "secret",
    "passw0rd", "passw0rd1", "p@ssword", "p@ssw0rd", "p@ssw0rd1",
    "letmein1", "access", "access14", "login", "guest",
    "guest123", "test123", "testing", "temp123", "changeme1",
    "default", "system", "server", "network", "security",
    "qwer1234", "asdf4321", "zaq12wsx", "1qazxsw2", "2wsx3edc",
    "1a2b3c4d", "a1b2c3d4", "correcthorse", "battery", "staple",
    "google", "facebook", "instagram", "twitter", "amazon1",
    "apple123", "microsoft1", "windows1", "linux123", "ubuntu1",
})


def _load_common_passwords() -> frozenset[str]:
    """
    Merge the embedded common-password set with an optional bundled wordlist
    """
    wordlist_path = Path(__file__).resolve().parent.parent / "data" / "common_passwords.txt"
    if not wordlist_path.exists():
        return _EMBEDDED_COMMON_PASSWORDS

    try:
        with wordlist_path.open(encoding = "utf-8", errors = "ignore") as f:
            extra = {line.strip().lower() for line in f if line.strip()}
        return _EMBEDDED_COMMON_PASSWORDS | frozenset(extra)
    except OSError:
        return _EMBEDDED_COMMON_PASSWORDS


COMMON_PASSWORDS = _load_common_passwords()

# Keyboard-walk substrings, checked case-insensitively against the raw input
KEYBOARD_PATTERNS = (
    "qwertyuiop", "qwertyui", "qwerty", "qwertz", "asdfghjkl",
    "asdfgh", "asdf", "zxcvbnm", "zxcvbn", "zxcv",
    "1qaz2wsx", "1qaz", "qazwsx", "2wsx3edc", "poiuytrewq",
    "mnbvcxz", "lkjhgfdsa", "0987654321", "1234567890",
    "!@#$%^&*()", "!qaz2wsx",
)

_LEET_MAP = str.maketrans({
    "@": "a",
    "4": "a",
    "0": "o",
    "1": "i",
    "3": "e",
    "$": "s",
    "5": "s",
    "!": "i",
    "+": "t",
})

_REPEATED_RUN_RE = re.compile(r"(.)\1{2,}")
_MIN_SEQUENTIAL_RUN = 4


def _normalize_leetspeak(password: str) -> str:
    """
    Lowercase and substitute common leetspeak characters for pattern matching
    """
    return password.lower().translate(_LEET_MAP)


def _contains_common_password(password: str) -> bool:
    """
    Check the password (and a leetspeak-normalized variant) against the
    common password set, matching whole strings and meaningful substrings
    """
    lowered = password.lower()
    normalized = _normalize_leetspeak(password)

    for candidate in (lowered, normalized):
        if candidate in COMMON_PASSWORDS:
            return True
        for common in COMMON_PASSWORDS:
            if len(common) >= 6 and common in candidate:
                return True
    return False


def _contains_keyboard_pattern(password: str) -> bool:
    """
    Check for keyboard-walk substrings (qwerty, asdf, etc.)
    """
    lowered = password.lower()
    return any(pattern in lowered for pattern in KEYBOARD_PATTERNS)


def _find_repeated_runs(password: str) -> list[str]:
    """
    Return each contiguous run of 3+ identical characters
    """
    return _REPEATED_RUN_RE.findall(password)


def _has_sequential_run(password: str, min_run: int = _MIN_SEQUENTIAL_RUN) -> bool:
    """
    Detect ascending or descending runs of consecutive characters
    (e.g. 'abcd', '4321') of at least min_run length
    """
    lowered = password.lower()
    ascending = descending = 1

    for i in range(1, len(lowered)):
        prev_ord = ord(lowered[i - 1])
        curr_ord = ord(lowered[i])

        ascending = ascending + 1 if curr_ord - prev_ord == 1 else 1
        descending = descending + 1 if prev_ord - curr_ord == 1 else 1

        if ascending >= min_run or descending >= min_run:
            return True
    return False


def _character_space(password: str) -> int:
    """
    Estimate the character space size based on which classes are present
    """
    space = 0
    if re.search(r"[a-z]", password):
        space += 26
    if re.search(r"[A-Z]", password):
        space += 26
    if re.search(r"[0-9]", password):
        space += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        space += 32
    return space


def calculate_entropy(password: str) -> float:
    """
    Estimate password entropy in bits: length * log2(character_space)
    """
    space = _character_space(password)
    if space <= 1 or not password:
        return 0.0
    return round(len(password) * math.log2(space), 1)


def check_password_strength(password: str) -> dict[str, Any]:
    """
    Assess password strength for informational feedback

    Returns a dict with: strength ("weak" | "medium" | "strong"),
    score (int), entropy_bits (float), feedback (list[str])
    """
    feedback: list[str] = []
    score = 0

    # Length scoring
    if len(password) >= 12:
        score += 2
    elif len(password) >= 8:
        score += 1
    else:
        feedback.append("Use at least 12 characters for a stronger password")

    # Character class variety
    has_lower = bool(re.search(r"[a-z]", password))
    has_upper = bool(re.search(r"[A-Z]", password))
    has_digit = bool(re.search(r"[0-9]", password))
    has_symbol = bool(re.search(r"[^a-zA-Z0-9]", password))
    score += sum([has_lower, has_upper, has_digit, has_symbol])

    if not has_upper:
        feedback.append("Add an uppercase letter")
    if not has_digit:
        feedback.append("Add a number")
    if not has_symbol:
        feedback.append("Add a symbol")

    # Common password check (case-insensitive, leetspeak-aware)
    is_common = _contains_common_password(password)
    if is_common:
        score = 0
        feedback.append("This password is very common and easily guessed")

    # Keyboard walk detection
    if _contains_keyboard_pattern(password):
        score -= 2
        feedback.append("Avoid keyboard patterns like 'qwerty' or 'asdf'")

    # Sequential character detection
    if _has_sequential_run(password):
        score -= 1
        feedback.append("Avoid sequential characters like 'abcd' or '4321'")

    # Repeated character detection
    repeated_runs = _find_repeated_runs(password)
    if repeated_runs:
        penalty = min(len(repeated_runs) * 2, 6)
        score -= penalty
        feedback.append("Avoid repeated characters like 'aaaa'")

    entropy_bits = calculate_entropy(password)

    # Reward genuinely long, high-entropy passphrases even if they only use
    # a couple of character classes (e.g. "correct-horse-battery-staple")
    if entropy_bits >= 100 and not is_common:
        score += 2
    elif entropy_bits >= 70 and not is_common:
        score += 1

    score = max(score, 0)

    if score < 3:
        strength = "weak"
    elif score < 5:
        strength = "medium"
    else:
        strength = "strong"

    if not feedback and strength == "strong":
        feedback.append("Strong password")

    return {
        "strength": strength,
        "score": score,
        "entropy_bits": entropy_bits,
        "feedback": feedback,
    }