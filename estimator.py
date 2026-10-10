"""
modules/estimator.py

Mock Cracking Time Estimator
-------------------------------
Pure mathematics. Given a password's entropy (in bits), estimates how
long an OFFLINE brute-force search of the keyspace would take at an
assumed hardware hash rate. No hashing, cracking, or network activity
is actually performed -- this is a theoretical calculation used for
educational "what if" illustration in an audit report.
"""

import math

# Assumed offline attacker hashing throughput (hashes/sec).
# 10 billion/sec is a commonly cited illustrative figure for fast
# offline GPU cracking against a weak/unsalted hash. Real-world speed
# varies hugely by hash algorithm (bcrypt/argon2 are far slower).
DEFAULT_HASHES_PER_SECOND = 10_000_000_000

SECONDS_PER_MINUTE = 60
SECONDS_PER_HOUR = SECONDS_PER_MINUTE * 60
SECONDS_PER_DAY = SECONDS_PER_HOUR * 24
SECONDS_PER_YEAR = SECONDS_PER_DAY * 365.25


def estimate_seconds_to_crack(
    entropy_bits: float,
    hashes_per_second: int = DEFAULT_HASHES_PER_SECOND,
) -> float:
    """
    Estimate average time-to-crack in seconds.

    Keyspace size = 2^entropy_bits
    On average, a brute-force search finds the match after searching
    half the keyspace, so:

        avg_seconds = (2^entropy_bits / 2) / hashes_per_second
    """
    if entropy_bits <= 0:
        return 0.0
    keyspace = 2 ** entropy_bits
    avg_attempts = keyspace / 2
    return avg_attempts / hashes_per_second


def format_duration(seconds: float) -> str:
    """Convert a raw seconds value into a human-readable duration string."""
    if seconds < 1:
        return "Instantly (< 1 second)"
    if seconds < SECONDS_PER_MINUTE:
        return f"{seconds:.1f} seconds"
    if seconds < SECONDS_PER_HOUR:
        return f"{seconds / SECONDS_PER_MINUTE:.1f} minutes"
    if seconds < SECONDS_PER_DAY:
        return f"{seconds / SECONDS_PER_HOUR:.1f} hours"
    if seconds < SECONDS_PER_YEAR:
        return f"{seconds / SECONDS_PER_DAY:.1f} days"

    years = seconds / SECONDS_PER_YEAR
    if years < 1_000:
        return f"{years:,.1f} years"
    if years < 1_000_000:
        return f"{years / 1_000:,.1f} thousand years"
    if years < 1_000_000_000:
        return f"{years / 1_000_000:,.1f} million years"
    if years < 1_000_000_000_000:
        return f"{years / 1_000_000_000:,.1f} billion years"
    return f"{years:.2e} years (effectively uncrackable)"


def estimate_crack_time(
    entropy_bits: float,
    hashes_per_second: int = DEFAULT_HASHES_PER_SECOND,
) -> dict:
    """Convenience wrapper returning both raw seconds and formatted text."""
    seconds = estimate_seconds_to_crack(entropy_bits, hashes_per_second)
    return {
        "seconds": seconds,
        "human_readable": format_duration(seconds),
        "assumed_hash_rate": hashes_per_second,
    }
