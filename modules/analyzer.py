"""
modules/analyzer.py

Password Strength Analyzer
---------------------------
Purely offline, mathematical analysis of a password string. No network
calls, no OS credential access. Computes Shannon-style entropy based on
character-set size, checks basic complexity rules, and flags matches
against a small hardcoded list of known-weak passwords.
"""

import math
import re

# Small, hardcoded sample of extremely common / breached passwords.
# This is illustrative only -- a real audit would use a much larger,
# externally supplied wordlist (e.g. rockyou.txt) loaded by the user.
COMMON_WEAK_PASSWORDS = {
    "123456", "123456789", "password", "qwerty", "abc123",
    "111111", "123123", "letmein", "iloveyou", "admin",
    "welcome", "monkey", "password1", "qwerty123", "12345678",
    "dragon", "football", "baseball", "trustno1", "login",
}


def _charset_size(password: str) -> int:
    """Estimate the size of the character pool a password draws from."""
    size = 0
    if re.search(r"[a-z]", password):
        size += 26
    if re.search(r"[A-Z]", password):
        size += 26
    if re.search(r"[0-9]", password):
        size += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        # Printable ASCII symbols, rough estimate
        size += 32
    return size or 1  # avoid log(0)


def calculate_entropy(password: str) -> float:
    """
    Calculate password entropy in bits using the standard formula:

        entropy = length * log2(charset_size)

    This is a simplified, widely-used approximation (NIST-style) and
    does not account for dictionary-word patterns -- that is handled
    separately by complexity / weak-list checks.
    """
    if not password:
        return 0.0
    charset_size = _charset_size(password)
    entropy = len(password) * math.log2(charset_size)
    return round(entropy, 2)


def check_complexity(password: str) -> dict:
    """Return a dict of boolean complexity checks."""
    return {
        "length_ok_12": len(password) >= 12,
        "length_ok_8": len(password) >= 8,
        "has_lowercase": bool(re.search(r"[a-z]", password)),
        "has_uppercase": bool(re.search(r"[A-Z]", password)),
        "has_digit": bool(re.search(r"[0-9]", password)),
        "has_symbol": bool(re.search(r"[^a-zA-Z0-9]", password)),
        "no_repeated_chars": not bool(re.search(r"(.)\1{2,}", password)),
    }


def is_common_weak_password(password: str) -> bool:
    """Check (case-insensitive) membership in the hardcoded weak list."""
    return password.lower() in COMMON_WEAK_PASSWORDS


def calculate_score(password: str) -> dict:
    """
    Combine entropy + complexity + weak-list checks into a single
    0-100 security score along with the supporting details.

    Scoring model (illustrative, not a formal standard):
      - Up to 60 points from entropy (scaled, capped at 100 bits)
      - Up to 40 points from complexity checks (length, char classes)
      - Hard penalty / cap if the password is a known weak password
    """
    if not password:
        return {
            "score": 0,
            "entropy_bits": 0.0,
            "complexity": check_complexity(""),
            "is_common_weak": False,
            "rating": "No password entered",
        }

    entropy = calculate_entropy(password)
    complexity = check_complexity(password)
    common_weak = is_common_weak_password(password)

    # Entropy contributes up to 60 points, scaled against a 100-bit ceiling
    entropy_score = min(entropy, 100) / 100 * 60

    # Complexity contributes up to 40 points (roughly ~5.7 pts per check)
    complexity_checks_passed = sum(complexity.values())
    total_checks = len(complexity)
    complexity_score = (complexity_checks_passed / total_checks) * 40

    score = round(entropy_score + complexity_score)

    # Known-weak passwords are capped hard regardless of math above
    if common_weak:
        score = min(score, 5)

    score = max(0, min(100, score))

    if score >= 80:
        rating = "Strong"
    elif score >= 60:
        rating = "Moderate"
    elif score >= 35:
        rating = "Weak"
    else:
        rating = "Very Weak"

    if common_weak:
        rating = "Critically Weak (Known Common Password)"

    return {
        "score": score,
        "entropy_bits": entropy,
        "complexity": complexity,
        "is_common_weak": common_weak,
        "rating": rating,
    }
