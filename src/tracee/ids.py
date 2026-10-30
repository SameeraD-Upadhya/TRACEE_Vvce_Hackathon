"""
TRACEE Evidence ID Generation

Defines the format and generation rules for evidence identifiers.

Evidence IDs are intentionally separate from hashing and storage so that
identity management remains deterministic and independently testable.

Valid evidence IDs represent sequence numbers from 1 through 999999.
"""

from __future__ import annotations

import re


EVIDENCE_ID_PREFIX = "TRACE-EV-"
EVIDENCE_ID_WIDTH = 6

_EVIDENCE_ID_PATTERN = re.compile(
    rf"^{re.escape(EVIDENCE_ID_PREFIX)}\d{{{EVIDENCE_ID_WIDTH}}}$"
)


class EvidenceIDError(ValueError):
    """Raised when an evidence ID is invalid."""


def format_evidence_id(sequence: int) -> str:
    """
    Format a positive evidence sequence number as a TRACEE evidence ID.

    Examples:
        1      -> TRACE-EV-000001
        42     -> TRACE-EV-000042
        999999 -> TRACE-EV-999999
    """

    if not isinstance(sequence, int) or isinstance(sequence, bool):
        raise EvidenceIDError(
            "Evidence sequence must be an integer"
        )

    if sequence <= 0:
        raise EvidenceIDError(
            "Evidence sequence must be greater than zero"
        )

    if sequence >= 10**EVIDENCE_ID_WIDTH:
        raise EvidenceIDError(
            f"Evidence sequence exceeds {EVIDENCE_ID_WIDTH} digits"
        )

    return (
        f"{EVIDENCE_ID_PREFIX}"
        f"{sequence:0{EVIDENCE_ID_WIDTH}d}"
    )


def is_valid_evidence_id(value: str) -> bool:
    """
    Return True only when value represents a valid TRACEE
    evidence sequence.

    The identifier must:
        1. Match the required textual format.
        2. Represent a sequence greater than zero.
        3. Represent a sequence within the six-digit range.
    """

    if not isinstance(value, str):
        return False

    if _EVIDENCE_ID_PATTERN.fullmatch(value) is None:
        return False

    sequence_text = value[
        len(EVIDENCE_ID_PREFIX):
    ]

    sequence = int(sequence_text)

    return 1 <= sequence < 10**EVIDENCE_ID_WIDTH


def parse_evidence_id(value: str) -> int:
    """
    Extract the numeric sequence from a valid evidence ID.
    """

    if not is_valid_evidence_id(value):
        raise EvidenceIDError(
            f"Invalid evidence ID: {value!r}"
        )

    return int(
        value[len(EVIDENCE_ID_PREFIX):]
    )
