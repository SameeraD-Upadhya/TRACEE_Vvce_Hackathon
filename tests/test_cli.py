"""
TRACEE Command-Line Interface Tests

Tests command parsing, command execution, output, and exit codes
for the TRACEE V0.2 CLI.

All tests use temporary evidence and vault directories.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from tracee.cli import main
from tracee.errors import ExitCode
from tracee.ingest import ingest_file


def metadata_path(
    vault_root: Path,
    evidence_id: str,
) -> Path:
    """Return the metadata path for an evidence object."""

    return (
        vault_root
        / "records"
        / f"{evidence_id}.json"
    )


def chain_path(vault_root: Path) -> Path:
    """Return the persisted evidence-chain path."""

    return vault_root / "chain" / "chain.jsonl"


def seed_evidence(
    evidence_file: Path,
    vault_root: Path,
) -> str:
    """Create a valid evidence object for CLI tests."""

    metadata, _ = ingest_file(
        evidence_file,
        vault_root,
    )

    return metadata.evidence_id


@pytest.mark.parametrize(
    ("arguments", "expected_command"),
    [
        (
            ["ingest", "--vault", "/tmp/vault", "/tmp/evidence.log"],
            "ingest",
        ),
        (
            ["verify", "--vault", "/tmp/vault", "TRACE-EV-000001"],
            "verify",
        ),
        (
            ["verify-chain", "--vault", "/tmp/vault"],
            "verify-chain",
        ),
        (
            [
                "verify-metadata",
                "--vault",
                "/tmp/vault",
                "TRACE-EV-000001",
            ],
            "verify-metadata",
        ),
        (
            ["metadata", "--vault", "/tmp/vault", "TRACE-EV-000001"],
            "metadata",
        ),
        (
            ["collect-windows-events", "--vault", "/tmp/vault", "--channel", "Application"],
            "collect-windows-events",
        ),
    ],
)
def test_cli_parser_accepts_supported_commands(
    arguments: list[str],
    expected_command: str,
) -> None:
    """The CLI parser must accept all supported commands."""

    from tracee.cli import build_parser

    parsed = build_parser().parse_args(arguments)

    assert parsed.command == expected_command


def test_cli_version(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The version option must display the CLI version and exit."""

    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])

    assert exc_info.value.code == 0
    assert "TRACEE CLI 0.2.0" in capsys.readouterr().out


def test_cli_windows_collector_dispatch_is_explicit_and_reports_only_summary(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    from types import SimpleNamespace
    from tracee import cli

    created = {}

    class FakeCollector:
        def __init__(self, vault, **limits):
            created["vault"] = vault
            created["limits"] = limits

        def collect(self, channel):
            created["channel"] = channel
            return SimpleNamespace(
                channel=channel,
                record_count=2,
                serialized_bytes=840,
                evidence_id="TRACE-EV-000001",
                sha256="a" * 64,
                verification_state="VALID",
                verification_message="Evidence is valid.",
            )

    monkeypatch.setattr(cli, "WindowsEventLogCollector", FakeCollector)
    result = main([
        "collect-windows-events", "--vault", str(tmp_path / "vault"),
        "--channel", "Application", "--max-records", "20",
        "--max-record-bytes", "8192", "--max-batch-bytes", "65536",
        "--provider", "Synthetic-Provider", "--event-id", "1000",
    ])
    output = capsys.readouterr().out

    assert result == int(ExitCode.SUCCESS)
    assert created["channel"] == "Application"
    assert created["limits"] == {
        "max_records": 20,
        "max_record_bytes": 8192,
        "max_batch_bytes": 65536,
        "provider_name": "Synthetic-Provider",
        "event_id": 1000,
    }
    assert "Records: 2" in output
    assert "Evidence ID: TRACE-EV-000001" in output
    assert "Verification: VALID" in output
    assert "<Event" not in output


def test_cli_windows_collector_rejects_unsupported_channel() -> None:
    from tracee.cli import build_parser

    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args([
            "collect-windows-events", "--vault", "/tmp/vault", "--channel", "Security",
        ])
    assert exc_info.value.code == 2


def test_cli_rejects_missing_vault_argument() -> None:
    """The ingest command must require a vault path."""

    with pytest.raises(SystemExit) as exc_info:
        main(["ingest", "/tmp/evidence.log"])

    assert exc_info.value.code == 2


def test_cli_ingest_success(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Successful ingestion must return success and print evidence details."""

    result = main(
        [
            "ingest",
            "--vault",
            str(vault_root),
            str(evidence_file),
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.SUCCESS)
    assert "[PASS] Evidence ingestion completed" in output
    assert "TRACE-EV-000001" in output
    assert "SHA-256:" in output
    assert "Chain sequence: 1" in output


def test_cli_ingest_rejects_duplicate_evidence(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Duplicate evidence must return the configured duplicate exit code."""

    arguments = [
        "ingest",
        "--vault",
        str(vault_root),
        str(evidence_file),
    ]

    assert main(arguments) == int(ExitCode.SUCCESS)
    capsys.readouterr()

    result = main(arguments)
    output = capsys.readouterr().out

    assert result == int(ExitCode.DUPLICATE_EVIDENCE)
    assert "[ERROR]" in output
    assert "already exists" in output.lower()


def test_cli_ingest_missing_source_returns_error(
    test_root: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A nonexistent source must fail with the ingestion exit code."""

    missing_source = test_root / "missing-evidence.log"

    result = main(
        [
            "ingest",
            "--vault",
            str(vault_root),
            str(missing_source),
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.INGESTION_FAILURE)
    assert "[ERROR]" in output
    assert "does not exist" in output


def test_cli_verify_valid_evidence(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The verify command must succeed for valid evidence."""

    evidence_id = seed_evidence(
        evidence_file,
        vault_root,
    )

    result = main(
        [
            "verify",
            "--vault",
            str(vault_root),
            evidence_id,
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.SUCCESS)
    assert "[PASS] Evidence verified" in output
    assert "State: VALID" in output


def test_cli_verify_missing_evidence_returns_missing_code(
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A valid-format but nonexistent evidence ID must return MISSING."""

    result = main(
        [
            "verify",
            "--vault",
            str(vault_root),
            "TRACE-EV-000999",
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.EVIDENCE_MISSING)
    assert "[ERROR]" in output
    assert "State: MISSING" in output


def test_cli_verify_detects_metadata_tampering(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Changing metadata without updating its chain binding must be detected."""

    evidence_id = seed_evidence(
        evidence_file,
        vault_root,
    )

    path = metadata_path(
        vault_root,
        evidence_id,
    )

    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    data["original_filename"] = "modified-filename.log"

    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    result = main(
        [
            "verify",
            "--vault",
            str(vault_root),
            evidence_id,
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.EVIDENCE_TAMPERED)
    assert "State: TAMPERED" in output


def test_cli_verify_chain_success(
    evidence_file: Path,
    second_evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The chain command must verify a valid multi-record chain."""

    seed_evidence(evidence_file, vault_root)
    seed_evidence(second_evidence_file, vault_root)

    result = main(
        [
            "verify-chain",
            "--vault",
            str(vault_root),
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.SUCCESS)
    assert "[PASS] Evidence chain verified" in output
    assert "2 record(s)" in output


def test_cli_verify_chain_detects_corruption(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The chain command must fail when a record hash is corrupted."""

    seed_evidence(evidence_file, vault_root)

    path = chain_path(vault_root)

    records = [
        json.loads(line)
        for line in path.read_text(
            encoding="utf-8"
        ).splitlines()
        if line.strip()
    ]

    records[0]["record_hash"] = "0" * 64

    path.write_text(
        "".join(
            json.dumps(
                record,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
            for record in records
        ),
        encoding="utf-8",
    )

    result = main(
        [
            "verify-chain",
            "--vault",
            str(vault_root),
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.VERIFICATION_FAILURE)
    assert "[ERROR] Chain verification failed" in output


def test_cli_verify_metadata_success(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The metadata verification command must succeed for valid records."""

    evidence_id = seed_evidence(
        evidence_file,
        vault_root,
    )

    result = main(
        [
            "verify-metadata",
            "--vault",
            str(vault_root),
            evidence_id,
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.SUCCESS)
    assert "[PASS] Metadata verified" in output
    assert "Metadata hash matches chain" in output


def test_cli_verify_metadata_detects_tampering(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Metadata verification must reject modified metadata."""

    evidence_id = seed_evidence(
        evidence_file,
        vault_root,
    )

    path = metadata_path(
        vault_root,
        evidence_id,
    )

    data = json.loads(
        path.read_text(
            encoding="utf-8"
        )
    )

    data["original_filename"] = "changed.log"

    path.write_text(
        json.dumps(data),
        encoding="utf-8",
    )

    result = main(
        [
            "verify-metadata",
            "--vault",
            str(vault_root),
            evidence_id,
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.VERIFICATION_FAILURE)
    assert "[ERROR] Metadata verification failed" in output


def test_cli_metadata_success(
    evidence_file: Path,
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The metadata command must display the persisted metadata fields."""

    evidence_id = seed_evidence(
        evidence_file,
        vault_root,
    )

    result = main(
        [
            "metadata",
            "--vault",
            str(vault_root),
            evidence_id,
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.SUCCESS)
    assert "[PASS] Metadata record loaded" in output
    assert f"Evidence ID: {evidence_id}" in output
    assert "Original filename:" in output
    assert "SHA-256:" in output
    assert "Ingested at:" in output


def test_cli_metadata_missing_record_returns_error(
    vault_root: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Reading nonexistent metadata must return a nonzero exit code."""

    result = main(
        [
            "metadata",
            "--vault",
            str(vault_root),
            "TRACE-EV-000999",
        ]
    )

    output = capsys.readouterr().out

    assert result == int(ExitCode.VAULT_FAILURE)
    assert "[ERROR]" in output
    assert "does not exist" in output
