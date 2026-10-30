"""Cross-platform exclusive file locks used by vault storage."""

from __future__ import annotations

import errno
import os
import stat
import threading
import time
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Iterator


class FileLockError(OSError):
    """The platform could not provide the requested exclusive lock."""


_THREAD_LOCKS: dict[str, threading.Lock] = {}
_THREAD_LOCKS_GUARD = threading.Lock()


def _thread_lock_for(
    file_obj: IO[bytes], lock_path: str | Path | None
) -> threading.Lock:
    name = lock_path if lock_path is not None else getattr(file_obj, "name", None)
    if not isinstance(name, (str, bytes, os.PathLike)):
        raise FileLockError("Lock file has no filesystem path")
    key = os.path.normcase(str(Path(name).resolve()))
    with _THREAD_LOCKS_GUARD:
        return _THREAD_LOCKS.setdefault(key, threading.Lock())


def _windows_lock(file_obj: IO[bytes]) -> None:
    import msvcrt

    # Windows byte-range locks may extend beyond EOF, so an empty lock file
    # stays unchanged while byte zero serves as the shared lock range.
    file_obj.seek(0)
    while True:
        try:
            msvcrt.locking(file_obj.fileno(), msvcrt.LK_NBLCK, 1)
            return
        except OSError as exc:
            if exc.errno not in {errno.EACCES, errno.EAGAIN, errno.EDEADLK}:
                raise
            time.sleep(0.05)


def _windows_unlock(file_obj: IO[bytes]) -> None:
    import msvcrt

    file_obj.seek(0)
    msvcrt.locking(file_obj.fileno(), msvcrt.LK_UNLCK, 1)


@contextmanager
def exclusive_file_lock(
    file_obj: IO[bytes], *, lock_path: str | Path | None = None
) -> Iterator[None]:
    """Hold a blocking exclusive lock across threads and processes.

    POSIX uses ``flock``. Windows uses a blocking byte-range lock through
    ``msvcrt``. Unsupported platforms and lock failures raise instead of
    continuing without serialization.
    """

    process_lock = _thread_lock_for(file_obj, lock_path)
    with process_lock:
        if os.name == "nt":
            _windows_lock(file_obj)
            unlock = _windows_unlock
        elif os.name == "posix":
            import fcntl

            try:
                fcntl.flock(file_obj.fileno(), fcntl.LOCK_EX)
            except OSError as exc:
                raise FileLockError("Unable to acquire exclusive file lock") from exc

            def unlock(stream: IO[bytes]) -> None:
                fcntl.flock(stream.fileno(), fcntl.LOCK_UN)

        else:
            raise FileLockError(f"File locking is unsupported on {os.name!r}")

        try:
            yield
        finally:
            unlock(file_obj)


def set_private_permissions(path: str | Path, mode: int) -> None:
    """Apply POSIX permission bits; on Windows rely on inherited ACLs.

    Python's Windows ``chmod`` only implements the read-only attribute and
    cannot express private directory/file ACLs. Temporary and vault files
    therefore inherit access control from their parent directories there.
    """

    if os.name == "nt":
        return
    Path(path).chmod(mode)


def set_private_file_permissions(file_descriptor: int, mode: int) -> None:
    """Apply restrictive mode bits to an open file where supported."""

    if os.name != "nt":
        os.fchmod(file_descriptor, mode)


def set_read_only(path: str | Path) -> None:
    """Make stored evidence read-only using native permission semantics."""

    target = Path(path)
    if os.name == "nt":
        target.chmod(stat.S_IREAD)
    else:
        target.chmod(0o400)


def _clear_read_only_and_retry(function, path: str, _exc_info) -> None:
    Path(path).chmod(stat.S_IWRITE | stat.S_IREAD)
    function(path)


def remove_path(path: str | Path) -> None:
    """Remove files/directories, clearing Windows read-only attributes as needed."""

    target = Path(path)
    if target.is_dir() and not target.is_symlink():
        import shutil

        shutil.rmtree(target, onerror=_clear_read_only_and_retry)
    elif target.exists() or target.is_symlink():
        try:
            target.unlink()
        except PermissionError:
            target.chmod(stat.S_IWRITE | stat.S_IREAD)
            target.unlink()
