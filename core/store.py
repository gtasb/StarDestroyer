"""JSON state on disk: locked read-modify-write, atomic replace.

A file that fails to parse is moved aside and reported, never overwritten with an
empty document -- "unreadable" and "empty" are different facts.
"""

import contextlib
import json
import os
import pathlib
import threading
import time

_LOCKS: dict[str, threading.RLock] = {}
_GUARD = threading.Lock()


def read(path: pathlib.Path, default):
    try:
        for attempt in range(20):
            try:
                text = path.read_text(encoding="utf-8-sig")
                break
            except PermissionError:  # Windows: being replaced right now
                if attempt == 19:
                    raise
                time.sleep(0.02)
        return json.loads(text)
    except FileNotFoundError:
        return default
    except ValueError as exc:
        kept = path.with_name(f"{path.name}.corrupt-{time.strftime('%Y%m%d-%H%M%S')}")
        from . import logging
        with contextlib.suppress(OSError):
            path.replace(kept)
        logging.error("store", "unreadable file moved aside", file=str(path), kept=str(kept),
                      error=str(exc))
        return default


def write(path: pathlib.Path, data) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f"{path.name}.{os.getpid()}-{threading.get_ident()}.tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    for attempt in range(20):
        try:
            os.replace(tmp, path)
            return
        except PermissionError:  # Windows: a reader holds the target open
            if attempt == 19:
                raise
            time.sleep(0.02)


@contextlib.contextmanager
def lock(path: pathlib.Path):
    """Exclusive across threads and processes (the CLI is a separate process)."""
    key = str(path.resolve())
    with _GUARD:
        mutex = _LOCKS.setdefault(key, threading.RLock())
    with mutex:
        path.parent.mkdir(parents=True, exist_ok=True)
        fh = open(path.with_name(path.name + ".lock"), "a+b")
        try:
            _acquire(fh)
            yield
        finally:
            _release(fh)
            fh.close()


@contextlib.contextmanager
def update(path: pathlib.Path, default):
    with lock(path):
        data = read(path, default)
        yield data
        write(path, data)


if os.name == "nt":
    import msvcrt

    def _acquire(fh) -> None:
        while True:
            try:
                fh.seek(0)
                msvcrt.locking(fh.fileno(), msvcrt.LK_NBLCK, 1)
                return
            except OSError:
                time.sleep(0.05)

    def _release(fh) -> None:
        with contextlib.suppress(OSError):
            fh.seek(0)
            msvcrt.locking(fh.fileno(), msvcrt.LK_UNLCK, 1)
else:
    import fcntl

    def _acquire(fh) -> None:
        fcntl.flock(fh, fcntl.LOCK_EX)

    def _release(fh) -> None:
        fcntl.flock(fh, fcntl.LOCK_UN)
