"""
TRACEE Test Configuration

Provides reusable pytest fixtures for the V0.1 foundation test suite.

All test state is isolated inside pytest's temporary directory.
Tests must never modify the repository's real evidence, vault,
investigation, or runtime directories.
"""

from __future__ import annotations

from pathlib import Path

import pytest


@pytest.fixture
def test_root(tmp_path: Path) -> Path:
    """Return an isolated temporary root directory for one test."""

    return tmp_path


@pytest.fixture
def vault_root(test_root: Path) -> Path:
    """Return an isolated TRACEE vault path."""

    return test_root / "vault"


@pytest.fixture
def evidence_file(test_root: Path) -> Path:
    """Create and return a small deterministic evidence file."""

    path = test_root / "evidence.log"

    path.write_text(
        "TRACEE V0.1 automated test evidence\n",
        encoding="utf-8",
    )

    return path


@pytest.fixture
def second_evidence_file(test_root: Path) -> Path:
    """Create and return a second distinct evidence file."""

    path = test_root / "evidence2.log"

    path.write_text(
        "TRACEE V0.1 second automated test evidence\n",
        encoding="utf-8",
    )

    return path
