"""Cross-platform file-lock regression tests."""

from __future__ import annotations

import multiprocessing
import time
from pathlib import Path

from tracee.activity import ActivityLog
from tracee.ids import format_evidence_id
from tracee.locking import exclusive_file_lock
from tracee.services import TraceeService
from tracee.vault import FilesystemVaultStore


def _write_locked_pair(lock_path: str, output_path: str, label: str, gate) -> None:
    with open(lock_path, "r+b") as lock_file:
        gate.wait(timeout=10)
        with exclusive_file_lock(lock_file):
            with open(output_path, "a", encoding="ascii") as output:
                output.write(f"start-{label}\n")
                output.flush()
                time.sleep(0.15)
                output.write(f"end-{label}\n")
                output.flush()


def _ingest_concurrently(vault_path: str, source_path: str, gate) -> None:
    gate.wait(timeout=10)
    TraceeService(vault_path).ingest(source_path)


def _append_activity_concurrently(vault_path: str, index: int, gate) -> None:
    gate.wait(timeout=10)
    ActivityLog(vault_path).append(
        event_type="evidence_viewed",
        actor="unauthenticated_local_client",
        outcome="success",
        evidence_id=format_evidence_id(index),
    )


def test_file_lock_serializes_independent_processes(tmp_path: Path) -> None:
    lock_path = tmp_path / "vault.lock"
    output_path = tmp_path / "critical-sections.log"
    lock_path.write_bytes(b"")
    output_path.write_text("", encoding="ascii")

    context = multiprocessing.get_context("spawn")
    gate = context.Barrier(3)
    workers = [
        context.Process(
            target=_write_locked_pair,
            args=(str(lock_path), str(output_path), label, gate),
        )
        for label in ("one", "two")
    ]
    for worker in workers:
        worker.start()
    gate.wait(timeout=10)
    for worker in workers:
        worker.join(timeout=10)
        assert not worker.is_alive()
        assert worker.exitcode == 0

    lines = output_path.read_text(encoding="ascii").splitlines()
    assert len(lines) == 4
    assert lines[0].startswith("start-")
    assert lines[1] == "end-" + lines[0].removeprefix("start-")
    assert lines[2].startswith("start-")
    assert lines[3] == "end-" + lines[2].removeprefix("start-")
    assert lock_path.read_bytes() == b""


def test_vault_ingestion_is_serialized_across_processes(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    FilesystemVaultStore(vault_path).initialize()
    sources = []
    for index in range(2):
        source = tmp_path / f"evidence-{index}.bin"
        source.write_bytes(bytes([index, 0, 255]) * 2048)
        sources.append(source)

    context = multiprocessing.get_context("spawn")
    gate = context.Barrier(3)
    workers = [
        context.Process(
            target=_ingest_concurrently,
            args=(str(vault_path), str(source), gate),
        )
        for source in sources
    ]
    for worker in workers:
        worker.start()
    gate.wait(timeout=10)
    for worker in workers:
        worker.join(timeout=20)
        assert not worker.is_alive()
        assert worker.exitcode == 0

    service = TraceeService(vault_path)
    for evidence_id in ("TRACE-EV-000001", "TRACE-EV-000002"):
        assert service.verify(evidence_id).state.value == "VALID"
    assert (vault_path / "chain" / "chain.jsonl").read_text(encoding="utf-8").count("\n") == 2


def test_activity_log_serializes_hash_chain_across_processes(tmp_path: Path) -> None:
    vault_path = tmp_path / "vault"
    FilesystemVaultStore(vault_path).initialize()
    context = multiprocessing.get_context("spawn")
    gate = context.Barrier(5)
    workers = [
        context.Process(
            target=_append_activity_concurrently,
            args=(str(vault_path), index, gate),
        )
        for index in range(1, 5)
    ]
    for worker in workers:
        worker.start()
    gate.wait(timeout=10)
    for worker in workers:
        worker.join(timeout=20)
        assert not worker.is_alive()
        assert worker.exitcode == 0

    entries = ActivityLog(vault_path).recent(20)
    assert len(entries) == 4
    assert len({entry["event_id"] for entry in entries}) == 4
    newest_first = entries
    for newer, older in zip(newest_first, newest_first[1:]):
        assert newer["previous_hash"] == older["record_hash"]
