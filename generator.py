"""
modules/generator.py

Auditing Dictionary Generator
-------------------------------
Given a base keyword (e.g. a company name, pet name, project name),
generates a list of candidate password permutations commonly used in
*defensive* password audits -- i.e. this produces a wordlist a blue
team could check an organization's existing password hashes against
OFFLINE, to find employees reusing predictable passwords.

This module performs no network activity and does not attempt to
authenticate against any live system. It only generates text strings.
"""

from typing import List

LEET_MAP = {
    "a": "4",
    "e": "3",
    "i": "1",
    "o": "0",
    "s": "5",
    "t": "7",
    "b": "8",
    "g": "9",
}

COMMON_SUFFIXES = [
    "!", "1", "123", "01", "2023", "2024", "2025",
    "!!", "#1", "99", "@", "$",
]

COMMON_PREFIXES = [
    "", "!", "@",
]


def apply_leet_substitution(word: str) -> List[str]:
    """
    Generate leet-speak variants of a word.

    Returns both a "full substitution" variant (every eligible character
    replaced) and the original, since auditors often check both forms.
    """
    variants = set()
    variants.add(word)

    full_sub = "".join(LEET_MAP.get(ch.lower(), ch) for ch in word)
    variants.add(full_sub)

    # Partial substitutions: replace one letter type at a time
    for target_char, replacement in LEET_MAP.items():
        if target_char in word.lower():
            partial = "".join(
                replacement if ch.lower() == target_char else ch
                for ch in word
            )
            variants.add(partial)

    return list(variants)


def toggle_case_variants(word: str) -> List[str]:
    """Generate common capitalization patterns for a word."""
    if not word:
        return [""]
    variants = {
        word.lower(),
        word.upper(),
        word.capitalize(),
        word[0].lower() + word[1:].upper() if len(word) > 1 else word.lower(),
        word.swapcase(),
    }
    return list(variants)


def append_common_suffixes(words: List[str], suffixes: List[str] = None) -> List[str]:
    """Append each suffix in `suffixes` to each word in `words`."""
    suffixes = suffixes if suffixes is not None else COMMON_SUFFIXES
    results = []
    for w in words:
        results.append(w)  # keep the bare word too
        for suf in suffixes:
            results.append(f"{w}{suf}")
    return results


def prepend_common_prefixes(words: List[str], prefixes: List[str] = None) -> List[str]:
    """Prepend each prefix in `prefixes` to each word in `words`."""
    prefixes = prefixes if prefixes is not None else COMMON_PREFIXES
    results = []
    for w in words:
        for pre in prefixes:
            results.append(f"{pre}{w}")
    return results


def generate_wordlist(base_keyword: str, max_entries: int = 500) -> List[str]:
    """
    Build a full auditing wordlist from a single base keyword by
    chaining: case variants -> leet substitutions -> suffixes/prefixes.

    `max_entries` caps the output so the UI / downloads stay manageable.
    """
    base_keyword = base_keyword.strip()
    if not base_keyword:
        return []

    all_variants = set()

    case_variants = toggle_case_variants(base_keyword)
    for cv in case_variants:
        all_variants.update(apply_leet_substitution(cv))

    all_variants.update(case_variants)

    with_suffixes = append_common_suffixes(list(all_variants))
    with_prefixes = prepend_common_prefixes(with_suffixes)

    final_list = sorted(set(with_prefixes), key=lambda s: (len(s), s))

    return final_list[:max_entries]
