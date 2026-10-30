"""
TRACEE Canonical JSON Serialization

Provides deterministic JSON serialization for data that will be
hashed or recorded as part of the TRACEE evidence-integrity system.
"""

from __future__ import annotations

import json
from typing import Any


CANONICAL_ENCODING = "utf-8"
CANONICAL_SEPARATORS = (",", ":")
CANONICAL_SORT_KEYS = True


class CanonicalizationError(ValueError):
    """Raised when data cannot be represented canonically."""


def canonicalize(data: Any) -> bytes:
    """
    Serialize JSON-compatible data into deterministic UTF-8 bytes.

    Rules:
    - Dictionary keys are sorted.
    - Whitespace is removed.
    - Unicode is encoded as UTF-8.
    - NaN and Infinity are rejected.
    - No trailing newline is added.
    """

    try:
        serialized = json.dumps(
            data,
            sort_keys=CANONICAL_SORT_KEYS,
            separators=CANONICAL_SEPARATORS,
            ensure_ascii=False,
            allow_nan=False,
        )
    except (TypeError, ValueError) as exc:
        raise CanonicalizationError(
            f"Data cannot be canonicalized: {exc}"
        ) from exc

    return serialized.encode(CANONICAL_ENCODING)


def canonicalize_text(data: Any) -> str:
    """Return the canonical representation as UTF-8 text."""

    return canonicalize(data).decode(CANONICAL_ENCODING)
