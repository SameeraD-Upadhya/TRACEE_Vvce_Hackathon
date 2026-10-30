"""
TRACEE Canonicalization Tests

Tests the deterministic JSON representation used by TRACEE
for cryptographic hashing and metadata binding.
"""

from __future__ import annotations

import math

import pytest

from src.tracee.canonical import (
    CanonicalizationError,
    canonicalize,
    canonicalize_text,
)


def test_canonicalization_is_deterministic() -> None:
    """Equivalent dictionaries must produce identical bytes."""

    first = {
        "z": 3,
        "a": 1,
        "nested": {
            "beta": 2,
            "alpha": 1,
        },
    }

    second = {
        "nested": {
            "alpha": 1,
            "beta": 2,
        },
        "a": 1,
        "z": 3,
    }

    assert canonicalize(first) == canonicalize(second)


def test_canonicalization_returns_utf8_bytes() -> None:
    """Canonicalization must return UTF-8 encoded bytes."""

    value = {
        "message": "TRACEE evidence",
    }

    result = canonicalize(value)

    assert isinstance(result, bytes)
    assert result.decode("utf-8") == (
        '{"message":"TRACEE evidence"}'
    )


def test_canonicalization_has_no_trailing_newline() -> None:
    """Canonical JSON must not contain a trailing newline."""

    result = canonicalize(
        {
            "event": "LOGIN",
        }
    )

    assert not result.endswith(b"\n")


def test_canonicalization_uses_compact_json() -> None:
    """Canonical JSON must use compact separators."""

    result = canonicalize(
        {
            "a": 1,
            "b": 2,
        }
    )

    assert result == b'{"a":1,"b":2}'


def test_canonicalization_preserves_unicode() -> None:
    """Unicode characters must remain valid UTF-8."""

    result = canonicalize(
        {
            "message": "TRACEE – evidence",
        }
    )

    assert "TRACEE – evidence" in result.decode("utf-8")


def test_canonicalization_rejects_non_finite_float() -> None:
    """NaN and infinity must never enter canonical data."""

    with pytest.raises(CanonicalizationError):
        canonicalize(
            {
                "value": math.nan,
            }
        )


def test_canonicalization_rejects_positive_infinity() -> None:
    """Positive infinity must be rejected."""

    with pytest.raises(CanonicalizationError):
        canonicalize(
            {
                "value": math.inf,
            }
        )


def test_canonicalization_rejects_negative_infinity() -> None:
    """Negative infinity must be rejected."""

    with pytest.raises(CanonicalizationError):
        canonicalize(
            {
                "value": -math.inf,
            }
        )


def test_canonicalize_text_matches_bytes() -> None:
    """Text output must represent the same canonical bytes."""

    value = {
        "evidence_id": "TRACE-EV-000001",
        "sequence": 1,
    }

    text = canonicalize_text(value)
    raw = canonicalize(value)

    assert text.encode("utf-8") == raw
