from __future__ import annotations

import json
import os
import stat
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

from tracee.analysis import AnalysisError
from tracee.journal_collector import CollectorError, JournalCollector
from tracee.locking import exclusive_file_lock
from tracee.services import TraceeService
from tracee.verify import VerificationState


def journal_record(index: int, *, cursor: str | None = None, message: str | None = None) -> bytes:
    record = {
        "__CURSOR": cursor if cursor is not None else f"cursor-{index}",
        "__REALTIME_TIMESTAMP": str(1792319400000000 + index),
        "MESSAGE": message if message is not None else f"synthetic event {index}",
        "_SYSTEMD_UNIT": "synthetic.service",
    }
    return json.dumps(record, separators=(",", ":"), ensure_ascii=False).encode() + b"\n"


class FakeJournalctl:
    def __init__(self, records: list[bytes] | None = None) -> None:
        self.records = list(records or [])
        self.calls: list[list[str]] = []
        self.error: Exception | None = None
        self.over_limit = False
        self.records_on_tail: list[bytes] = []

    def __call__(self, args, **kwargs) -> bytes:
        self.calls.append(list(args))
        if self.error:
            raise self.error
        if "--lines=1" in args:
            if self.records_on_tail:
                self.records.extend(self.records_on_tail)
                self.records_on_tail.clear()
            return self.records[-1] if self.records else b""
        since_arg = next((arg for arg in args if arg.startswith("--since=")), None)
        cursor_arg = next((arg for arg in args if arg.startswith("--after-cursor=")), None)
        if since_arg:
            watermark = datetime.fromisoformat(since_arg.split("=", 1)[1].replace("Z", "+00:00"))
            watermark_us = int(watermark.timestamp() * 1_000_000)
            selected = [raw for raw in self.records if int(json.loads(raw)["__REALTIME_TIMESTAMP"]) >= watermark_us]
        elif cursor_arg:
            after = cursor_arg.split("=", 1)[1]
            index = next((i for i, raw in enumerate(self.records) if json.loads(raw)["__CURSOR"] == after), None)
            selected = self.records[index + 1:] if index is not None else self.records
        else:
            selected = self.records
        if self.over_limit:
            return b"".join(selected)
        output = bytearray()
        for raw in selected:
            if output and len(output) + len(raw) > kwargs["max_batch_bytes"]:
                break
            if len(raw) > kwargs["max_record_bytes"]:
                return raw
            output.extend(raw)
            if output.count(b"\n") >= kwargs["max_records"]:
                break
        return bytes(output)


def make_collector(tmp_path: Path, runner: FakeJournalctl, **kwargs) -> JournalCollector:
    return JournalCollector(
        tmp_path / "vault", tmp_path / "collector-state", runner=runner, **kwargs
    )


def read_state(collector: JournalCollector) -> dict:
    return json.loads(collector.state_file.read_text(encoding="utf-8"))


def chain_records(vault: Path) -> list[dict]:
    path = vault / "chain" / "chain.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]


def test_tail_initialization_skips_existing_history_and_persists_cursor(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(1), journal_record(2)])
    collector = make_collector(tmp_path, runner)
    assert collector.run_once() == 0
    state = read_state(collector)
    assert state["initial_position"] == "tail"
    assert state["initialized"] is True
    assert state["committed_cursor"] == "cursor-2"
    assert chain_records(tmp_path / "vault") == []


def test_explicit_beginning_collects_oldest_records(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(1), journal_record(2)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    assert collector.run_once() == 1
    records = chain_records(tmp_path / "vault")
    assert len(records) == 1
    assert read_state(collector)["committed_cursor"] == "cursor-2"


def test_empty_initial_tail_is_persisted_then_collects_newly_available_records(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    monkeypatch.setattr(module, "_utc_now", lambda: datetime.fromtimestamp(1792319399, timezone.utc))
    runner = FakeJournalctl()
    collector = make_collector(tmp_path, runner)
    assert collector.run_once() == 0
    assert read_state(collector)["initialized"] is True
    assert read_state(collector)["bootstrap"] == {"phase": "since", "since_utc": "2026-10-18T10:29:59.000000Z"}
    runner.records.append(journal_record(1))
    assert collector.run_once() == 1
    assert read_state(collector)["committed_cursor"] == "cursor-1"
    assert read_state(collector)["bootstrap"] is None
    since_calls = [call for call in runner.calls if any(arg.startswith("--since=") for arg in call)]
    assert since_calls
    assert all("--after-cursor=cursor-1" not in call for call in since_calls)
    assert not any(
        "--lines=all" in call
        and not any(arg.startswith("--after-cursor=") for arg in call)
        and not any(arg.startswith("--since=") for arg in call)
        for call in runner.calls
    )


def test_empty_tail_bootstrap_captures_multiple_new_records_in_order(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    monkeypatch.setattr(module, "_utc_now", lambda: datetime.fromtimestamp(1792319399, timezone.utc))
    runner = FakeJournalctl()
    collector = make_collector(tmp_path, runner, batch_size=2)
    assert collector.run_once() == 0
    runner.records.extend([journal_record(1), journal_record(2), journal_record(3)])
    assert collector.run_once() == 1
    state = read_state(collector)
    assert state["committed_cursor"] == "cursor-2"
    first = chain_records(tmp_path / "vault")[0]
    stored = collector.service.vault.evidence_path(first["evidence_id"]).read_bytes()
    assert stored == journal_record(1) + journal_record(2)
    assert collector.run_once() == 1
    assert read_state(collector)["committed_cursor"] == "cursor-3"
    assert len(chain_records(tmp_path / "vault")) == 2


def test_record_arriving_during_empty_tail_probe_is_not_skipped(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    monkeypatch.setattr(module, "_utc_now", lambda: datetime.fromtimestamp(1792319399, timezone.utc))
    runner = FakeJournalctl()
    runner.records_on_tail.append(journal_record(1))
    collector = make_collector(tmp_path, runner)
    assert collector.run_once() == 0
    assert read_state(collector)["committed_cursor"] is None
    assert read_state(collector)["bootstrap"]["phase"] == "since"
    assert collector.run_once() == 1
    assert read_state(collector)["committed_cursor"] == "cursor-1"
    assert len(chain_records(tmp_path / "vault")) == 1


def test_empty_tail_bootstrap_survives_process_restart(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    monkeypatch.setattr(module, "_utc_now", lambda: datetime.fromtimestamp(1792319399, timezone.utc))
    runner = FakeJournalctl()
    first = make_collector(tmp_path, runner)
    assert first.run_once() == 0
    runner.records.extend([journal_record(1), journal_record(2)])
    restarted = make_collector(tmp_path, runner)
    assert restarted.run_once() == 1
    assert read_state(restarted)["committed_cursor"] == "cursor-2"
    assert len(chain_records(tmp_path / "vault")) == 1
    assert any(any(arg.startswith("--since=2026-10-18T10:29:59.000000Z") for arg in call) for call in runner.calls)


def test_interrupted_tail_probe_fails_closed_on_restart(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    monkeypatch.setattr(module, "_utc_now", lambda: datetime.fromtimestamp(1792319399, timezone.utc))
    runner = FakeJournalctl()
    collector = make_collector(tmp_path, runner)

    def interrupt_probe(**kwargs):
        raise KeyboardInterrupt

    monkeypatch.setattr(collector, "_query", interrupt_probe)
    with pytest.raises(KeyboardInterrupt):
        collector.run_once()
    state = read_state(collector)
    assert state["bootstrap"]["phase"] == "probing"
    restarted = make_collector(tmp_path, runner)
    with pytest.raises(CollectorError) as failure:
        restarted.run_once()
    assert failure.value.code == "bootstrap_recovery_required"
    assert read_state(restarted)["committed_cursor"] is None


def test_malformed_bootstrap_watermark_fails_closed(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    monkeypatch.setattr(module, "_utc_now", lambda: datetime.fromtimestamp(1792319399, timezone.utc))
    runner = FakeJournalctl()
    collector = make_collector(tmp_path, runner)
    collector.run_once()
    state = read_state(collector)
    state["bootstrap"]["since_utc"] = "2026-10-18"
    collector.state_file.write_text(json.dumps(state), encoding="utf-8")
    with pytest.raises(CollectorError) as failure:
        collector.run_once()
    assert failure.value.code == "state_invalid"
    assert read_state(collector)["committed_cursor"] is None


def test_older_checkpoint_schema_is_not_reinterpreted(tmp_path: Path) -> None:
    collector = make_collector(tmp_path, FakeJournalctl())
    collector.state_path.mkdir()
    collector.state_file.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
    with pytest.raises(CollectorError) as failure:
        collector.run_once()
    assert failure.value.code == "state_incompatible"


def test_backward_wall_clock_fails_closed_during_empty_tail_bootstrap(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    times = iter([
        datetime.fromtimestamp(1792319399, timezone.utc),
        datetime.fromtimestamp(1792319398, timezone.utc),
    ])
    monkeypatch.setattr(module, "_utc_now", lambda: next(times))
    runner = FakeJournalctl()
    collector = make_collector(tmp_path, runner)
    assert collector.run_once() == 0
    with pytest.raises(CollectorError) as failure:
        collector.run_once()
    assert failure.value.code == "bootstrap_clock_moved"
    assert read_state(collector)["committed_cursor"] is None


def test_ordered_batches_resume_after_last_committed_cursor(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(i) for i in range(1, 6)])
    collector = make_collector(tmp_path, runner, initial_position="beginning", batch_size=2)
    assert collector.run_once() == 1
    assert read_state(collector)["committed_cursor"] == "cursor-2"
    assert collector.run_once() == 1
    assert read_state(collector)["committed_cursor"] == "cursor-4"
    assert collector.run_once() == 1
    assert read_state(collector)["committed_cursor"] == "cursor-5"
    assert len(chain_records(tmp_path / "vault")) == 3
    assert any("--after-cursor=cursor-2" in call for call in runner.calls)


def test_next_batch_is_not_skipped_when_more_than_batch_size_is_available(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(i) for i in range(1, 4)])
    collector = make_collector(tmp_path, runner, initial_position="beginning", batch_size=2)
    collector.run_once()
    assert read_state(collector)["committed_cursor"] == "cursor-2"
    collector.run_once()
    assert read_state(collector)["committed_cursor"] == "cursor-3"


def test_exact_jsonl_bytes_are_acquired_through_tracee_service(tmp_path: Path) -> None:
    original = journal_record(1, message="quote \" and unicode π") + journal_record(2)
    runner = FakeJournalctl(original.splitlines(keepends=True))
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    collector.run_once()
    evidence_id = chain_records(tmp_path / "vault")[0]["evidence_id"]
    stored = TraceeService(tmp_path / "vault").vault.evidence_path(evidence_id).read_bytes()
    assert stored == original
    assert TraceeService(tmp_path / "vault").verify(evidence_id).state is VerificationState.VALID


def test_automatic_analysis_uses_systemd_journal_parser_and_realtime_timestamps(tmp_path: Path) -> None:
    collector = make_collector(tmp_path, FakeJournalctl([journal_record(1)]), initial_position="beginning")
    collector.run_once()
    state = read_state(collector)
    service = TraceeService(tmp_path / "vault")
    chain = chain_records(tmp_path / "vault")[0]
    summaries, total = collector.analysis_service.list_analyses(chain["evidence_id"], limit=10)
    assert total == 1
    analysis = collector.analysis_service.load_analysis(chain["evidence_id"], summaries[0]["analysis_id"])
    assert analysis["parser"] == "systemd_journal"
    observation_timestamp = analysis["observations"][0]["timestamp"]
    assert observation_timestamp["raw_value"] == "2026-10-18T10:30:00.000001Z"
    assert observation_timestamp["normalized_extent"]["earliest_utc"] == "2026-10-18T10:30:00.000001Z"
    assert service.verify(chain["evidence_id"]).state is VerificationState.VALID
    assert state["last_completed"]["last_cursor"] == "cursor-1"


def test_restart_with_no_pending_batch_continues_from_checkpoint(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(1)])
    first = make_collector(tmp_path, runner, initial_position="beginning")
    first.run_once()
    runner.records.append(journal_record(2))
    restarted = make_collector(tmp_path, runner, initial_position="beginning")
    assert restarted.run_once() == 1
    assert len(chain_records(tmp_path / "vault")) == 2


def test_restart_recovers_unprocessed_staged_batch_after_acquisition_error(tmp_path: Path, monkeypatch) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    original_ingest = collector.service.ingest
    calls = 0

    def fail_once(source):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise OSError("private failure detail")
        return original_ingest(source)

    monkeypatch.setattr(collector.service, "ingest", fail_once)
    with pytest.raises(CollectorError, match="Evidence acquisition failed"):
        collector.run_once()
    assert collector.staged_file.exists()
    restarted = make_collector(tmp_path, runner, initial_position="beginning")
    assert restarted.run_once() == 1
    assert read_state(restarted)["committed_cursor"] == "cursor-1"


def test_crash_after_ingestion_before_evidence_id_is_recorded_resolves_duplicate(tmp_path: Path, monkeypatch) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    original_write = collector._write_state

    def fail_after_ingest(state):
        if state["pending"] is not None and state["pending"]["evidence_id"] is not None:
            raise CollectorError("simulated_crash", "simulated checkpoint interruption")
        return original_write(state)

    monkeypatch.setattr(collector, "_write_state", fail_after_ingest)
    with pytest.raises(CollectorError, match="simulated checkpoint interruption"):
        collector.run_once()
    assert len(chain_records(tmp_path / "vault")) == 1
    restarted = make_collector(tmp_path, runner, initial_position="beginning")
    restarted.run_once()
    assert len(chain_records(tmp_path / "vault")) == 1
    assert read_state(restarted)["committed_cursor"] == "cursor-1"


def test_analysis_failure_retries_without_reingestion(tmp_path: Path, monkeypatch) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    original_analyze = collector.analysis_service.analyze
    calls = 0

    def fail_once(evidence_id, parser_name):
        nonlocal calls
        calls += 1
        if calls == 1:
            raise AnalysisError("simulated", "failure", 503)
        return original_analyze(evidence_id, parser_name)

    monkeypatch.setattr(collector.analysis_service, "analyze", fail_once)
    with pytest.raises(CollectorError, match="Automatic systemd journal analysis failed"):
        collector.run_once()
    assert read_state(collector)["pending"]["phase"] == "acquired"
    restarted = make_collector(tmp_path, runner, initial_position="beginning")
    restarted.run_once()
    assert len(chain_records(tmp_path / "vault")) == 1
    assert restarted.analysis_service.list_analyses(chain_records(tmp_path / "vault")[0]["evidence_id"])[1] == 1


def test_crash_after_analysis_before_cursor_commit_reuses_stored_analysis(tmp_path: Path, monkeypatch) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    original_write = collector._write_state

    def interrupt_after_analysis(state):
        if state["pending"] is not None and state["pending"]["phase"] == "analyzed":
            raise CollectorError("simulated_crash", "simulated crash after analysis")
        return original_write(state)

    monkeypatch.setattr(collector, "_write_state", interrupt_after_analysis)
    with pytest.raises(CollectorError, match="simulated crash after analysis"):
        collector.run_once()
    evidence_id = chain_records(tmp_path / "vault")[0]["evidence_id"]
    assert collector.analysis_service.list_analyses(evidence_id)[1] == 1
    restarted = make_collector(tmp_path, runner, initial_position="beginning")
    restarted.run_once()
    assert restarted.analysis_service.list_analyses(evidence_id)[1] == 1
    assert read_state(restarted)["committed_cursor"] == "cursor-1"


def test_analysis_recovery_does_not_create_repeated_runs(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    collector.run_once()
    evidence_id = chain_records(tmp_path / "vault")[0]["evidence_id"]
    assert collector.analysis_service.list_analyses(evidence_id)[1] == 1


@pytest.mark.parametrize("damage", ["tampered", "missing"])
def test_verification_failure_keeps_cursor_pending_and_preserves_actual_state(tmp_path: Path, monkeypatch, damage: str) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")

    def fail_analysis(evidence_id, parser_name):
        raise AnalysisError("simulated", "leave acquired evidence pending", 503)

    monkeypatch.setattr(collector.analysis_service, "analyze", fail_analysis)
    with pytest.raises(CollectorError):
        collector.run_once()
    state = read_state(collector)
    evidence_id = state["pending"]["evidence_id"]
    evidence_path = collector.service.vault.evidence_path(evidence_id)
    if damage == "tampered":
        evidence_path.chmod(stat.S_IREAD | stat.S_IWRITE)
        evidence_path.write_bytes(b"modified evidence")
    else:
        evidence_path.chmod(stat.S_IREAD | stat.S_IWRITE)
        evidence_path.unlink()
    restarted = make_collector(tmp_path, runner, initial_position="beginning")
    with pytest.raises(CollectorError, match="Automatic systemd journal analysis failed"):
        restarted.run_once()
    assert read_state(restarted)["committed_cursor"] is None
    assert read_state(restarted)["pending"]["evidence_id"] == evidence_id


def test_empty_read_cycle_does_not_change_acquired_evidence_or_chain(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    collector.run_once()
    service = TraceeService(tmp_path / "vault")
    eid = chain_records(tmp_path / "vault")[0]["evidence_id"]
    evidence_path = service.vault.evidence_path(eid)
    metadata_path = service.vault.record_path(eid)
    chain_path = service.vault.chain_path
    before = (evidence_path.read_bytes(), metadata_path.read_bytes(), chain_path.read_bytes())
    assert collector.run_once() == 0
    after = (evidence_path.read_bytes(), metadata_path.read_bytes(), chain_path.read_bytes())
    assert after == before
    assert runner.records == [journal_record(1)]
    assert collector.run_once() == 0
    assert collector.analysis_service.list_analyses(eid)[1] == 1


@pytest.mark.parametrize("raw", [b"{bad}\n", b"[]\n", b'{"_CURSOR":"wrong"}\n', b'{"__CURSOR":""}\n', b'{"__CURSOR":7}\n'])
def test_malformed_json_and_invalid_or_missing_cursor_fail_closed(tmp_path: Path, raw: bytes) -> None:
    collector = make_collector(tmp_path, FakeJournalctl([raw]), initial_position="beginning")
    with pytest.raises(CollectorError):
        collector.run_once()
    assert read_state(collector)["committed_cursor"] is None
    assert chain_records(tmp_path / "vault") == []


def test_record_byte_limit_fails_without_advancing_cursor(tmp_path: Path) -> None:
    raw = journal_record(1, message="x" * 200)
    collector = make_collector(tmp_path, FakeJournalctl([raw]), initial_position="beginning", max_record_bytes=100)
    with pytest.raises(CollectorError, match="record limit"):
        collector.run_once()
    assert read_state(collector)["committed_cursor"] is None


def test_batch_byte_limit_fails_for_first_unfit_record(tmp_path: Path) -> None:
    raw = journal_record(1)
    collector = make_collector(tmp_path, FakeJournalctl([raw]), initial_position="beginning", max_batch_bytes=len(raw) - 1)
    with pytest.raises(CollectorError) as failure:
        collector.run_once()
    assert failure.value.code == "batch_limit_exceeded"
    checkpoint = read_state(collector)
    assert checkpoint["committed_cursor"] is None
    assert checkpoint["pending"] is None
    # Re-query with a sufficient bound and prove the rejected cursor was not
    # consumed or lost when the first batch could not be staged.
    retry = make_collector(tmp_path, collector.runner, initial_position="beginning", max_batch_bytes=len(raw))
    assert retry.run_once() == 1
    assert read_state(retry)["committed_cursor"] == "cursor-1"


def test_event_count_limit_processes_earliest_records_only(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(i) for i in range(1, 4)])
    collector = make_collector(tmp_path, runner, initial_position="beginning", batch_size=1)
    collector.run_once()
    assert read_state(collector)["committed_cursor"] == "cursor-1"
    collector.run_once()
    assert read_state(collector)["committed_cursor"] == "cursor-2"


def test_runner_error_and_permission_failure_are_actionable_and_do_not_commit(tmp_path: Path) -> None:
    runner = FakeJournalctl()
    runner.error = PermissionError("host path and internal detail")
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    with pytest.raises(CollectorError, match="Permission was denied") as error:
        collector.run_once()
    assert "host path" not in str(error.value)
    assert read_state(collector)["committed_cursor"] is None


def test_state_symlink_is_rejected(tmp_path: Path) -> None:
    collector = make_collector(tmp_path, FakeJournalctl(), initial_position="beginning")
    collector.state_path.mkdir()
    target = tmp_path / "outside.json"
    target.write_text("{}", encoding="utf-8")
    try:
        collector.state_file.symlink_to(target)
    except OSError as exc:
        if os.name == "nt" and getattr(exc, "winerror", None) == 1314:
            pytest.skip(
                "Creating symbolic links requires a Windows privilege "
                "that is unavailable in this test environment."
            )
        raise
    with pytest.raises(CollectorError, match="symbolic link"):
        collector.run_once()


def test_invalid_or_incompatible_state_is_not_reset(tmp_path: Path) -> None:
    runner = FakeJournalctl()
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    collector.state_path.mkdir()
    collector.state_file.write_text('{"schema_version":99}', encoding="utf-8")
    before = collector.state_file.read_bytes()
    with pytest.raises(CollectorError, match="unsupported schema"):
        collector.run_once()
    assert collector.state_file.read_bytes() == before


def test_state_cannot_be_reused_with_different_vault_or_mode(tmp_path: Path) -> None:
    runner = FakeJournalctl()
    first = make_collector(tmp_path, runner, initial_position="beginning")
    first.run_once()
    different_mode = make_collector(tmp_path, runner, initial_position="tail")
    with pytest.raises(CollectorError, match="different vault or initial-position"):
        different_mode.run_once()


def test_unaccounted_staged_batch_fails_closed(tmp_path: Path) -> None:
    collector = make_collector(tmp_path, FakeJournalctl(), initial_position="beginning")
    collector.state_path.mkdir()
    collector.staged_file.write_bytes(journal_record(1))
    with pytest.raises(CollectorError, match="unaccounted staged batch"):
        collector.run_once()


def test_vault_and_state_paths_must_not_be_nested(tmp_path: Path) -> None:
    with pytest.raises(CollectorError, match="separate, non-nested"):
        JournalCollector(tmp_path / "vault", tmp_path / "vault" / "state", runner=FakeJournalctl())


def test_concurrent_collector_waits_for_exclusive_state_lock(tmp_path: Path) -> None:
    runner = FakeJournalctl()
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    collector._prepare_state_directory()
    with collector.lock_file.open("r+b") as stream:
        with exclusive_file_lock(stream, lock_path=collector.lock_file):
            completed = threading.Event()
            result: list[int] = []

            def work():
                result.append(collector.run_once())
                completed.set()

            worker = threading.Thread(target=work)
            worker.start()
            time.sleep(0.1)
            assert not completed.is_set()
        worker.join(timeout=5)
    assert completed.is_set()
    assert result == [0]


def test_sigterm_while_idle_stops_before_another_cycle_and_restores_handler(tmp_path: Path, monkeypatch) -> None:
    from signal import SIGTERM
    from tracee import journal_collector as module

    previous_handler = object()
    installed: dict[int, object] = {}
    signal_calls: list[tuple[int, object]] = []

    def fake_signal(signum, handler):
        signal_calls.append((signum, handler))
        if callable(handler):
            installed[signum] = handler
        return previous_handler

    monkeypatch.setattr(module.signal, "signal", fake_signal)
    real_event = threading.Event

    class StopDuringWait:
        def __init__(self) -> None:
            self.event = real_event()

        def set(self) -> None:
            self.event.set()

        def is_set(self) -> bool:
            return self.event.is_set()

        def wait(self, timeout=None) -> bool:
            installed[SIGTERM](SIGTERM, None)
            return self.event.wait(0)

    monkeypatch.setattr(module.threading, "Event", StopDuringWait)
    collector = make_collector(tmp_path, FakeJournalctl())
    cycles: list[str] = []
    monkeypatch.setattr(collector, "run_once", lambda: cycles.append("completed"))

    collector.run_forever()

    assert cycles == ["completed"]
    assert signal_calls == [(SIGTERM, installed[SIGTERM]), (SIGTERM, previous_handler)]


def test_sigterm_during_cycle_waits_for_cycle_completion_and_stops(tmp_path: Path, monkeypatch) -> None:
    from signal import SIGTERM
    from tracee import journal_collector as module

    previous_handler = object()
    installed: dict[int, object] = {}
    signal_calls: list[tuple[int, object]] = []

    def fake_signal(signum, handler):
        signal_calls.append((signum, handler))
        if callable(handler):
            installed[signum] = handler
        return previous_handler

    monkeypatch.setattr(module.signal, "signal", fake_signal)
    collector = make_collector(tmp_path, FakeJournalctl())
    cycle_state = {"started": False, "finished": False}
    cycles = 0

    def cycle():
        nonlocal cycles
        cycles += 1
        cycle_state["started"] = True
        installed[SIGTERM](SIGTERM, None)
        # The handler only requests a stop; in-flight work reaches completion.
        cycle_state["finished"] = True

    monkeypatch.setattr(collector, "run_once", cycle)
    collector.run_forever()

    assert cycles == 1
    assert cycle_state == {"started": True, "finished": True}
    assert signal_calls[-1] == (SIGTERM, previous_handler)


def test_continuous_collector_requires_main_thread_for_sigterm_handling(tmp_path: Path, monkeypatch) -> None:
    from tracee import journal_collector as module

    collector = make_collector(tmp_path, FakeJournalctl())
    signal_calls: list[object] = []
    monkeypatch.setattr(module.signal, "signal", lambda *args: signal_calls.append(args))
    failures: list[CollectorError] = []

    def invoke() -> None:
        try:
            collector.run_forever()
        except CollectorError as exc:
            failures.append(exc)

    worker = threading.Thread(target=invoke)
    worker.start()
    worker.join(timeout=5)
    assert not worker.is_alive()
    assert len(failures) == 1
    assert failures[0].code == "signal_handler_unavailable"
    assert signal_calls == []


def test_sigterm_handler_is_restored_when_cycle_errors(tmp_path: Path, monkeypatch) -> None:
    from signal import SIGTERM
    from tracee import journal_collector as module

    previous_handler = object()
    signal_calls: list[tuple[int, object]] = []

    def fake_signal(signum, handler):
        signal_calls.append((signum, handler))
        return previous_handler

    monkeypatch.setattr(module.signal, "signal", fake_signal)
    collector = make_collector(tmp_path, FakeJournalctl())

    def fail_cycle():
        raise CollectorError("state_invalid", "synthetic checkpoint error")

    monkeypatch.setattr(collector, "run_once", fail_cycle)
    with pytest.raises(CollectorError) as failure:
        collector.run_forever()

    assert failure.value.code == "state_invalid"
    assert signal_calls[-1] == (SIGTERM, previous_handler)


def test_ctrl_c_still_stops_continuous_collection_and_restores_handler(tmp_path: Path, monkeypatch) -> None:
    from signal import SIGTERM
    from tracee import journal_collector as module

    previous_handler = object()
    signal_calls: list[tuple[int, object]] = []

    def fake_signal(signum, handler):
        signal_calls.append((signum, handler))
        return previous_handler

    monkeypatch.setattr(module.signal, "signal", fake_signal)
    collector = make_collector(tmp_path, FakeJournalctl())

    def interrupt() -> None:
        raise KeyboardInterrupt

    monkeypatch.setattr(collector, "run_once", interrupt)

    collector.run_forever()

    assert signal_calls[-1] == (SIGTERM, previous_handler)


def test_interrupt_after_staging_leaves_recoverable_pending_batch(tmp_path: Path, monkeypatch) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    original_stage = collector._stage

    def stage_then_interrupt(data, state):
        staged = original_stage(data, state)
        raise KeyboardInterrupt

    monkeypatch.setattr(collector, "_stage", stage_then_interrupt)
    with pytest.raises(KeyboardInterrupt):
        collector.run_once()
    assert read_state(collector)["pending"]["phase"] == "staged"
    restarted = make_collector(tmp_path, runner, initial_position="beginning")
    restarted.run_once()
    assert read_state(restarted)["committed_cursor"] == "cursor-1"


def test_committed_cursor_with_leftover_completed_stage_is_cleaned_safely(tmp_path: Path) -> None:
    runner = FakeJournalctl([journal_record(1)])
    collector = make_collector(tmp_path, runner, initial_position="beginning")
    collector.run_once()
    data = collector.service.vault.evidence_path(chain_records(tmp_path / "vault")[0]["evidence_id"]).read_bytes()
    collector.staged_file.write_bytes(data)
    assert collector.run_once() == 0
    assert not collector.staged_file.exists()


def test_cli_options_are_explicit_and_defaults_are_local_collector_only() -> None:
    from tracee.cli import build_parser

    args = build_parser().parse_args([
        "collect-journal", "--vault", "/tmp/vault", "--state-dir", "/tmp/state", "--once",
    ])
    assert args.command == "collect-journal"
    assert args.once is True
    assert args.initial_position == "tail"
    assert args.interval_seconds == 5.0


@pytest.mark.parametrize("kwargs", [
    {"interval_seconds": 0}, {"batch_size": 0}, {"max_batch_bytes": 0},
    {"max_record_bytes": 0}, {"subprocess_timeout": float("inf")},
    {"initial_position": "reset"},
])
def test_collector_rejects_invalid_configuration(tmp_path: Path, kwargs: dict) -> None:
    with pytest.raises(CollectorError) as failure:
        make_collector(tmp_path, FakeJournalctl(), **kwargs)
    assert failure.value.code == "invalid_configuration"
