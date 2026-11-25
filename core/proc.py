"""Child processes that a background task can cancel.

A task running in a worker thread sets a Control; engines run their binary through
run() so cancelling the task kills the process tree instead of orphaning it.
"""

import contextvars
import subprocess
import threading
import time


class Cancelled(BaseException):
    """BaseException so the engines' own `except Exception` cannot swallow it."""


class Control:
    def __init__(self, on_stage=None):
        self._event = threading.Event()
        self._lock = threading.Lock()
        self._pids: set[int] = set()
        self._on_stage = on_stage

    def cancel(self) -> None:
        self._event.set()
        from . import jobs
        with self._lock:
            pids = list(self._pids)
        for pid in pids:
            jobs.kill_tree(pid)

    def check(self) -> None:
        if self._event.is_set():
            raise Cancelled("任务已取消")

    def stage(self, text: str) -> None:
        self.check()
        if self._on_stage:
            self._on_stage(text)


_current: contextvars.ContextVar[Control | None] = contextvars.ContextVar("sd_control", default=None)


def use(control: Control | None):
    return _current.set(control)


def check() -> None:
    """Raise Cancelled when the surrounding task was cancelled. No-op outside one."""
    c = _current.get()
    if c:
        c.check()


def stage(text: str) -> None:
    """Tell the surrounding task what is happening now. No-op outside one."""
    c = _current.get()
    if c:
        c.stage(text)


def run(argv: list[str], timeout: float, input: str | None = None, **kw) -> subprocess.CompletedProcess:
    """subprocess.run for text output, killing the whole tree on timeout or cancel."""
    from . import jobs
    check()
    c = _current.get()
    proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL if input is None else subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True, encoding="utf-8",
                            errors="replace", **kw)
    if c:
        with c._lock:
            c._pids.add(proc.pid)
    started = time.monotonic()
    try:
        if c:
            c.check()  # cancelled between the first check and registration
        out, err = proc.communicate(input, timeout=timeout)
    except BaseException:
        jobs.kill_tree(proc.pid)
        proc.communicate()
        raise
    finally:
        if c:
            with c._lock:
                c._pids.discard(proc.pid)
    check()
    return subprocess.CompletedProcess(argv, proc.returncode, out, err)
