"""
TRACEE Evidence ID Tests

Tests the stable evidence-ID format used by the V0.1
evidence-integrity foundation.
"""

from __future__ import annotations

import pytest

from src.tracee.ids import (
    EvidenceIDError,
    EVIDENCE_ID_PREFIX,
    EVIDENCE_ID_WIDTH,
    format_evidence_id,
    is_valid_evidence_id,
    parse_evidence_id,
)


def test_evidence_id_prefix() -> None:
    """The evidence-ID prefix must remain stable."""

    assert EVIDENCE_ID_PREFIX == "TRACE-EV-"


def test_evidence_id_width() -> None:
    """The evidence-ID numeric portion must remain six digits."""

    assert EVIDENCE_ID_WIDTH == 6


@pytest.mark.parametrize(
    ("sequence", "expected"),
    [
        (1, "TRACE-EV-000001"),
        (2, "TRACE-EV-000002"),
        (42, "TRACE-EV-000042"),
        (999999, "TRACE-EV-999999"),
    ],
)
def test_format_evidence_id(
    sequence: int,
    expected: str,
) -> None:
    """Valid sequence numbers must produce stable IDs."""

    assert format_evidence_id(sequence) == expected


@pytest.mark.parametrize(
    "sequence",
    [
        0,
        -1,
        1000000,
    ],
)
def test_format_evidence_id_rejects_invalid_sequence(
    sequence: int,
) -> None:
    """Out-of-range sequence numbers must be rejected."""

    with pytest.raises(EvidenceIDError):
        format_evidence_id(sequence)


def test_format_evidence_id_rejects_boolean() -> None:
    """Boolean values must not be accepted as sequence numbers."""

    with pytest.raises(EvidenceIDError):
        format_evidence_id(True)


@pytest.mark.parametrize(
    "evidence_id",
    [
        "TRACE-EV-000001",
        "TRACE-EV-000002",
        "TRACE-EV-000042",
        "TRACE-EV-999999",
    ],
)
def test_is_valid_evidence_id_accepts_valid_ids(
    evidence_id: str,
) -> None:
    """Correctly formatted IDs must validate."""

    assert is_valid_evidence_id(evidence_id) is True


@pytest.mark.parametrize(
    "evidence_id",
    [
        "",
        "TRACE-EV-1",
        "TRACE-EV-00000",
        "TRACE-EV-0000000",
        "TRACE-EV-000000",
        "TRACE-EV-1000000",
        "trace-ev-000001",
        "TRACE-EV-ABCDEF",
        "TRACE-EV-000001 ",
        " TRACE-EV-000001",
        "TRACE-000001",
        "TRACE-EV-",
    ],
)
def test_is_valid_evidence_id_rejects_invalid_ids(
    evidence_id: str,
) -> None:
    """Malformed IDs must fail validation."""

    assert is_valid_evidence_id(evidence_id) is False


@pytest.mark.parametrize(
    ("evidence_id", "expected"),
    [
        ("TRACE-EV-000001", 1),
        ("TRACE-EV-000002", 2),
        ("TRACE-EV-000042", 42),
        ("TRACE-EV-999999", 999999),
    ],
)
def test_parse_evidence_id(
    evidence_id: str,
    expected: int,
) -> None:
    """Valid evidence IDs must parse back to their sequence number."""

    assert parse_evidence_id(evidence_id) == expected


@pytest.mark.parametrize(
    "evidence_id",
    [
        "",
        "TRACE-EV-000000",
        "TRACE-EV-1000000",
        "TRACE-EV-ABCDEF",
        "invalid",
    ],
)
def test_parse_evidence_id_rejects_invalid_ids(
    evidence_id: str,
) -> None:
    """Invalid IDs must raise EvidenceIDError when parsed."""

    with pytest.raises(EvidenceIDError):
        parse_evidence_id(evidence_id)


def test_format_and_parse_are_inverse_operations() -> None:
    """Formatting and parsing must round-trip correctly."""

    for sequence in [1, 2, 42, 100, 999999]:
        evidence_id = format_evidence_id(sequence)

        assert parse_evidence_id(
            evidence_id
        ) == sequence
