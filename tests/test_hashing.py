"""
TRACEE Hashing Tests

Tests the SHA-256 hashing primitives used by the V0.1
evidence-integrity foundation.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from src.tracee.hashing import (
    DEFAULT_CHUNK_SIZE,
    HashingError,
    sha256_bytes,
    sha256_file,
    validate_sha256,
)


def test_sha256_bytes_known_vector() -> None:
    """SHA-256 must match the standard known vector for 'abc'."""

    result = sha256_bytes(b"abc")

    assert result == (
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad"
    )


def test_sha256_bytes_empty_input() -> None:
    """SHA-256 of empty bytes must match the standard vector."""

    result = sha256_bytes(b"")

    assert result == (
        "e3b0c44298fc1c149afbf4c8996fb924"
        "27ae41e4649b934ca495991b7852b855"
    )


def test_sha256_file_matches_byte_hash(
    evidence_file: Path,
) -> None:
    """File hashing must produce the same digest as byte hashing."""

    data = evidence_file.read_bytes()

    expected = sha256_bytes(data)
    actual = sha256_file(evidence_file)

    assert actual == expected


def test_sha256_file_accepts_string_path(
    evidence_file: Path,
) -> None:
    """File hashing must accept string paths."""

    result = sha256_file(str(evidence_file))

    assert result == sha256_bytes(
        evidence_file.read_bytes()
    )


def test_sha256_file_streaming(
    test_root: Path,
) -> None:
    """File hashing must work correctly across multiple chunks."""

    path = test_root / "large.bin"

    data = bytes(range(256)) * 10000
    path.write_bytes(data)

    expected = sha256_bytes(data)
    actual = sha256_file(
        path,
        chunk_size=1024,
    )

    assert actual == expected


def test_default_chunk_size_is_one_megabyte() -> None:
    """The default hashing chunk size must remain stable."""

    assert DEFAULT_CHUNK_SIZE == 1024 * 1024


@pytest.mark.parametrize(
    "chunk_size",
    [
        0,
        -1,
    ],
)
def test_sha256_file_rejects_invalid_chunk_size(
    evidence_file: Path,
    chunk_size: int,
) -> None:
    """Non-positive chunk sizes must be rejected."""

    with pytest.raises(HashingError):
        sha256_file(
            evidence_file,
            chunk_size=chunk_size,
        )


def test_sha256_file_rejects_missing_file(
    test_root: Path,
) -> None:
    """Hashing a missing evidence file must fail explicitly."""

    missing = test_root / "missing.bin"

    with pytest.raises(HashingError):
        sha256_file(missing)


@pytest.mark.parametrize(
    "value",
    [
        "ba7816bf8f01cfea414140de5dae2223"
        "b00361a396177a9cb410ff61f20015ad",
        "0" * 64,
        "f" * 64,
    ],
)
def test_validate_sha256_accepts_valid_digest(
    value: str,
) -> None:
    """Valid lowercase 64-character SHA-256 digests must pass."""

    assert validate_sha256(value) is True


@pytest.mark.parametrize(
    "value",
    [
        "",
        "abc",
        "A" * 64,
        "g" * 64,
        "0" * 63,
        "0" * 65,
    ],
)
def test_validate_sha256_rejects_invalid_digest(
    value: str,
) -> None:
    """Malformed SHA-256 digests must be rejected."""

    assert validate_sha256(value) is False
