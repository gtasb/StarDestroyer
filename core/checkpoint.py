"""Where a scan had got to, so that stopping it does not throw the work away.

One file per project and kind of scan, written after every finished part. The key says
what the parts were computed from; when it no longer matches, they are worthless and
gone. A scan that finishes removes its checkpoint: the next one starts afresh.
"""

import hashlib
import os
import pathlib
import time

from . import profile, projects, store

VERSION = 2


def _dir(root: str) -> pathlib.Path:
    return projects.STORE / projects.project_id(root) / "checkpoints"


def fingerprint(root: str, names=None) -> str:
    """Identity of a tree by path, size and time; `names` limits it to certain file names."""
    p = pathlib.Path(root).resolve()
    h = hashlib.sha256()
    files = [p] if p.is_file() else [pathlib.Path(b) / f for b, dirs, fs in _walk(p) for f in sorted(fs)]
    for f in files:
        if names and not names(f.name):
            continue
        try:
            st = f.stat()
        except OSError:
            continue
        h.update(f"{f}\0{st.st_size}\0{st.st_mtime_ns}\0".encode())
    return h.hexdigest()[:16]


def _walk(p: pathlib.Path):
    for base, dirs, files in os.walk(p):
        dirs[:] = sorted(d for d in dirs if d not in profile.SKIP_DIRS)
        yield base, dirs, files


class Checkpoint:
    def __init__(self, root: str, kind: str, *key):
        self.file = _dir(root) / f"{kind}.json"
        self.key = hashlib.sha256(repr((VERSION, key)).encode()).hexdigest()[:24]
        self.total = 0
        data = store.read(self.file, {})
        self.parts: dict = data.get("parts", {}) if data.get("key") == self.key else {}
        self.resumed = len(self.parts)

    def get(self, name: str):
        return self.parts.get(name)

    def put(self, name: str, value) -> None:
        self.parts[name] = value
        store.write(self.file, {"key": self.key, "at": time.strftime("%Y-%m-%d %H:%M"), "total": max(self.total, len(self.parts)), "parts": self.parts})

    def done(self) -> None:
        self.file.unlink(missing_ok=True)


def summary(root: str) -> dict:
    """{kind: {done, total, at}} of scans that stopped halfway."""
    out = {}
    for f in _dir(root).glob("*.json"):
        d = store.read(f, {})
        if d.get("parts"):
            out[f.stem] = {"done": len(d["parts"]), "total": d.get("total", 0), "at": d.get("at", "")}
    return out


def clear(root: str, kind: str = "") -> None:
    """Start over."""
    for f in _dir(root).glob(f"{kind or '*'}.json"):
        f.unlink(missing_ok=True)
    if not kind or kind == "audit":
        for f in (projects.STORE / projects.project_id(root) / "sessions").glob("*.json"):
            f.unlink(missing_ok=True)


# ---- agent sessions -------------------------------------------------------------------
def session_file(root: str, unit: str) -> pathlib.Path:
    return projects.STORE / projects.project_id(root) / "sessions" / f"{unit}.json"
