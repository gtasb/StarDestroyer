"""Long-running work goes here, never into a synchronous call.

submit() returns at once with a job id; the child runs in its own process
group / session so killing the agent does not kill the job.
"""

import os
import pathlib
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


def submit(command: str, cwd: str | None = None, label: str = "") -> dict:
    jid = uuid.uuid4().hex[:8]
    d = JOBS_DIR / jid
    d.mkdir()
    (d / "state").write_text("running")
    if label:
        (d / "label").write_text(label)

    log = (d / "log").open("w", encoding="utf-8", errors="replace")
    argv = [sys.executable, str(_RUNNER), str(d), command]
    if cwd:
        argv.append(cwd)

    if os.name == "nt":
        flags = subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.DETACHED_PROCESS
        subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                         creationflags=flags, close_fds=True)
    else:
        subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT,
                         start_new_session=True, close_fds=True)
    log.close()
    from . import logging
    logging.info("jobs", "submitted", job_id=jid, label=label or "-")
    return {"job_id": jid}


def status(jid: str, tail: int = 40) -> dict:
    d = JOBS_DIR / jid
    if not d.exists():
        return {"job_id": jid, "state": "unknown"}
    log = d / "log"
    lines = log.read_text(encoding="utf-8", errors="replace").splitlines() if log.exists() else []
    return {
        "job_id": jid,
        "state": (d / "state").read_text().strip() if (d / "state").exists() else "unknown",
        "exit": (d / "exit").read_text().strip() if (d / "exit").exists() else None,
        "label": (d / "label").read_text().strip() if (d / "label").exists() else "",
        "tail": lines[-tail:],
    }


def wait(jid: str, timeout_s: int = 30, interval_s: float = 0.5) -> dict:
    """Bounded wait. Callers must never block longer than the caller's budget;
    anything longer is polled via status() from the console."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        st = status(jid, tail=5)
        if st.get("state") != "running":
            return st
        time.sleep(interval_s)
    st = status(jid, tail=5)
    st["timed_out"] = True
    return st


def mark(jid: str, name: str) -> None:
    (JOBS_DIR / jid / f"{name}.done").write_text("1")


def has(jid: str, name: str) -> bool:
    return (JOBS_DIR / jid / f"{name}.done").exists()


def path(jid: str) -> pathlib.Path:
    return JOBS_DIR / jid
