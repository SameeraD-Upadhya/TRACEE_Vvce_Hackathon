"""
TRACEE Streaming SHA-256 Hashing

Provides deterministic SHA-256 hashing for evidence files and
canonical byte sequences.

This module deliberately contains no vault, chain, or ingestion logic.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import BinaryIO


DEFAULT_CHUNK_SIZE = 1024 * 1024  # 1 MiB
SHA256_HEX_LENGTH = 64


class HashingError(ValueError):
    """Raised when a hashing operation receives invalid input."""


def sha256_bytes(data: bytes) -> str:
    """
    Calculate SHA-256 for an in-memory byte sequence.

    Returns:
        Lowercase hexadecimal SHA-256 digest.
    """

    if not isinstance(data, bytes):
        raise HashingError("sha256_bytes() requires bytes")

    return hashlib.sha256(data).hexdigest()


def _sha256_stream(
    stream: BinaryIO,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Calculate SHA-256 from a binary stream.

    The stream is consumed from its current position.
    """

    if chunk_size <= 0:
        raise HashingError("chunk_size must be greater than zero")

    digest = hashlib.sha256()

    while True:
        chunk = stream.read(chunk_size)

        if not chunk:
            break

        digest.update(chunk)

    return digest.hexdigest()


def sha256_file(
    path: str | Path,
    *,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
) -> str:
    """
    Calculate SHA-256 for a file using streaming reads.

    The entire file is never loaded into memory.
    """

    file_path = Path(path)

    if not file_path.is_file():
        raise HashingError(f"File does not exist: {file_path}")

    try:
        with file_path.open("rb") as stream:
            return _sha256_stream(
                stream,
                chunk_size=chunk_size,
            )
    except OSError as exc:
        raise HashingError(
            f"Unable to read file: {file_path}"
        ) from exc


def validate_sha256(value: str) -> bool:
    """
    Validate the structural form of a SHA-256 hexadecimal digest.
    """

    if not isinstance(value, str):
        return False

    if len(value) != SHA256_HEX_LENGTH:
        return False

    return all(character in "0123456789abcdef" for character in value)
