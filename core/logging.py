"""Unified logging.

One line per event, written to `.work/logs/stardestroyer.log` and kept in a
bounded in-memory ring. The file is the shared artifact: the web console and the
agent both read it, so what a user sees in the UI is exactly what was persisted.

Format is fixed-width enough to grep and parse:
    2026-11-24 20:30:12 INFO  tabby      build done  classes=52210 methods=388128
"""

import collections
import json
import os
import pathlib
import threading
import time

LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
LOG_DIR = pathlib.Path(os.environ.get("SD_LOG_DIR") or pathlib.Path(__file__).resolve().parents[1] / ".work" / "logs")
LOG_FILE = LOG_DIR / "stardestroyer.log"
MAX_BYTES = 5 * 1024 * 1024

_RING: collections.deque = collections.deque(maxlen=2000)
_LOCK = threading.Lock()
_SEQ = [0]


def _threshold() -> int:
    return LEVELS.get(os.environ.get("SD_LOG_LEVEL", "INFO").upper(), LEVELS["INFO"])


def _fmt(v) -> str:
    if isinstance(v, (int, float, bool)):
        return str(v)
    # Anything that could break the one-line format is quoted: paths and engine
    # messages come from the audited tree and must not be able to forge a line.
    if isinstance(v, str) and v.isprintable() and " " not in v:
        return v
    return json.dumps(v, ensure_ascii=False, default=str)


def log(level: str, component: str, message: str, /, **fields) -> dict | None:
    level = level.upper()
    if LEVELS.get(level, 20) < _threshold():
        return None
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    kv = "  " + " ".join(f"{k}={_fmt(v)}" for k, v in fields.items()) if fields else ""
    line = f"{ts} {level:<5} {component:<10} {message}{kv}".replace("\r", " ").replace("\n", " ")
    entry = {"seq": 0, "ts": ts, "level": level, "component": component,
             "message": message, "fields": fields}
    with _LOCK:
        _SEQ[0] += 1
        entry["seq"] = _SEQ[0]
        _RING.append(entry)
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            if LOG_FILE.exists() and LOG_FILE.stat().st_size > MAX_BYTES:
                LOG_FILE.replace(LOG_FILE.with_suffix(".log.1"))
            with LOG_FILE.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass  # logging must never break the operation it describes
    return entry


def debug(component: str, message: str, /, **f) -> None:
    log("DEBUG", component, message, **f)


def info(component: str, message: str, /, **f) -> None:
    log("INFO", component, message, **f)


def warn(component: str, message: str, /, **f) -> None:
    log("WARN", component, message, **f)


def error(component: str, message: str, /, **f) -> None:
    log("ERROR", component, message, **f)


def recent(since: int = 0, limit: int = 200) -> list[dict]:
    """In-process entries newer than `since` (cheap; used by tests/tools)."""
    with _LOCK:
        return [e for e in _RING if e["seq"] > since][-limit:]


def tail(n: int = 200, level: str | None = None) -> dict:
    """Last n lines of the shared log file, newest last."""
    if not LOG_FILE.exists():
        return {"path": str(LOG_FILE), "lines": [], "exists": False}
    try:
        lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError as exc:
        return {"path": str(LOG_FILE), "lines": [], "error": str(exc)}
    if level:
        tag = f" {level.upper():<5} "
        lines = [ln for ln in lines if tag in ln]
    return {"path": str(LOG_FILE), "lines": lines[-n:], "exists": True,
            "total": len(lines)}
