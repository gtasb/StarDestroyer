"""Long-running work goes here, never into a synchronous call.

submit() returns at once with a job id; the child runs in its own process
group / session so killing the agent does not kill the job.
"""

import contextlib
import json
import os
import pathlib
import re
import signal
import subprocess
import sys
import time
import uuid

JOBS_DIR = pathlib.Path(
    os.environ.get(
        "AUDIT_JOBS_DIR",
        pathlib.Path(__file__).resolve().parents[1] / ".work" / "jobs",
    )
)
JOBS_DIR.mkdir(parents=True, exist_ok=True)

_RUNNER = pathlib.Path(__file__).with_name("_runner.py")


def submit(command: str | list[str], cwd: str | None = None, label: str = "") -> dict:
    """A list runs without a shell and is what internal callers must use; a string
    is a shell command line the user wrote (the submit_job tool)."""
    jid = uuid.uuid4().hex[:8]
    d = JOBS_DIR / jid
    d.mkdir()
    (d / "state").write_text("running")
    if label:
        (d / "label").write_text(label, encoding="utf-8")

    argv = [sys.executable, str(_RUNNER), str(d), json.dumps(command)]
    if cwd:
        argv.append(cwd)
    with (d / "log").open("w", encoding="utf-8", errors="replace") as log:
        if os.name == "nt":
            flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, creationflags=flags, close_fds=True)
        else:
            proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=log,
                                    stderr=subprocess.STDOUT, start_new_session=True, close_fds=True)
    (d / "pid").write_text(str(proc.pid))
    from . import logging
    logging.info("jobs", "submitted", job_id=jid, label=label or "-")
    return {"job_id": jid}


def alive(pid: int) -> bool:
    if os.name != "nt":
        try:
            os.kill(pid, 0)
            return True
        except ProcessLookupError:
            return False
        except PermissionError:
            return True
    import ctypes
    k32 = ctypes.windll.kernel32
    handle = k32.OpenProcess(0x1000, False, pid)  # QUERY_LIMITED_INFORMATION
    if not handle:
        return False
    code = ctypes.c_ulong()
    ok = k32.GetExitCodeProcess(handle, ctypes.byref(code))
    k32.CloseHandle(handle)
    return bool(ok) and code.value == 259  # STILL_ACTIVE


def kill_tree(pid: int) -> None:
    if os.name == "nt":
        subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True)
    else:
        with contextlib.suppress(OSError):
            os.killpg(os.getpgid(pid), signal.SIGKILL)


def _dir(jid: str) -> pathlib.Path | None:
    # ids are ours; anything else could walk out of JOBS_DIR
    if not re.fullmatch(r"[0-9a-f]{8}", str(jid)):
        return None
    d = JOBS_DIR / jid
    return d if d.exists() else None


def _text(d: pathlib.Path, name: str) -> str | None:
    try:
        return (d / name).read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return None


def status(jid: str, tail: int = 40) -> dict:
    d = _dir(jid)
    if d is None:
        return {"job_id": jid, "state": "unknown"}
    state, pid = _text(d, "state") or "unknown", _text(d, "pid")
    if state == "running" and pid and not alive(int(pid)):
        # It may have finished between the two reads; only a missing exit is a loss.
        state = "done" if _text(d, "exit") is not None else "lost"
    lines = (_text(d, "log") or "").splitlines()
    return {
        "job_id": jid,
        "state": state,
        "exit": _text(d, "exit"),
        "label": _text(d, "label") or "",
        "tail": lines[-tail:],
    }


def cancel(jid: str) -> dict:
    d = _dir(jid)
    pid = _text(d, "pid") if d else None
    if status(jid)["state"] != "running" or not pid:
        return {"ok": False, "error": "任务不在运行"}
    kill_tree(int(pid))
    (d / "exit").write_text("cancelled")
    (d / "state").write_text("cancelled")
    return {"ok": True, "job_id": jid}


def wait(jid: str, timeout_s: float = 30, interval_s: float = 0.5, stop=None) -> dict:
    """Bounded wait. Callers must never block longer than the caller's budget;
    anything longer is polled via status() from the console. `stop` is polled
    between checks and may raise to abandon the wait."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        st = status(jid, tail=5)
        if st.get("state") != "running":
            return st
        if stop:
            stop()
        time.sleep(interval_s)
    st = status(jid, tail=5)
    st["timed_out"] = True
    return st
