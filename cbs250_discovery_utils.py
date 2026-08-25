"""Pure helpers for CBS250 safe context-help discovery."""
from __future__ import annotations

import string

# CBS CLI keywords are case-insensitive. Lower-case shards cover alphabetic
# keywords while digits cover numeric literal alternatives. '*' is kept because
# CBS help exposes it as a literal option in a few command families.
SHARD_ALPHABET = tuple(string.ascii_lowercase + string.digits + "*")

PAGER_MARKERS = (
    "More: <space>",
    "Quit: q or CTRL+Z",
)


def has_more_prompt(text: str) -> bool:
    return any(marker in text for marker in PAGER_MARKERS)


def build_help_query(context_prefix: str, shard: str = "") -> str:
    """Build a help-only query with no CR/LF.

    Examples:
      context='', shard='' -> '?'
      context='show', shard='' -> 'show ?'
      context='', shard='s' -> 's?'
      context='show', shard='s' -> 'show s?'
    """
    context = " ".join(context_prefix.strip().split())
    shard = shard.strip()
    if any(ch in shard for ch in "\r\n") or any(ch in context for ch in "\r\n"):
        raise ValueError("Help query components must not contain CR/LF")
    if shard:
        return f"{context} {shard}?" if context else f"{shard}?"
    return f"{context} ?" if context else "?"


def merge_unique_items(existing: list, incoming: list) -> list:
    """Merge HelpItem-like objects by token while preserving first-seen order."""
    seen = {getattr(item, "token", None) for item in existing}
    out = list(existing)
    for item in incoming:
        token = getattr(item, "token", None)
        if token not in seen:
            out.append(item)
            seen.add(token)
    return out
