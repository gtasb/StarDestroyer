"""Projects and their artifacts.

A project is a path the user audits repeatedly. Artifacts are written next to the
project record so the console can show "the last SCA result" without re-running
anything -- and so a restart does not lose the view.
"""

import hashlib
import json
import pathlib
import time

STORE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "projects"
INDEX = STORE / "projects.json"


def project_id(path: str) -> str:
    return hashlib.sha256(str(pathlib.Path(path).resolve()).encode()).hexdigest()[:12]


def _read_index() -> dict:
    if not INDEX.exists():
        return {"projects": {}, "active": ""}
    try:
        return json.loads(INDEX.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"projects": {}, "active": ""}


def _write_index(idx: dict) -> None:
    STORE.mkdir(parents=True, exist_ok=True)
    INDEX.write_text(json.dumps(idx, ensure_ascii=False, indent=2), encoding="utf-8")


def add(path: str, name: str = "") -> dict:
    p = pathlib.Path(path).resolve()
    if not p.exists():
        return {"ok": False, "error": f"路径不存在: {path}"}
    idx = _read_index()
    pid = project_id(str(p))
    entry = idx["projects"].get(pid) or {
        "id": pid, "path": str(p), "name": name or p.name,
        "created": time.strftime("%Y-%m-%d %H:%M"),
    }
    if name:
        entry["name"] = name
    idx["projects"][pid] = entry
    idx["active"] = pid
    _write_index(idx)
    return {"ok": True, "project": entry}


def list_all() -> dict:
    idx = _read_index()
    items = sorted(idx["projects"].values(), key=lambda x: x.get("created", ""), reverse=True)
    for it in items:
        it["artifacts"] = sorted(latest(it["path"]).keys())
    return {"ok": True, "active": idx.get("active", ""), "projects": items}


def activate(pid: str) -> dict:
    idx = _read_index()
    if pid not in idx["projects"]:
        return {"ok": False, "error": "项目不存在"}
    idx["active"] = pid
    _write_index(idx)
    return {"ok": True, "active": pid, "project": idx["projects"][pid]}


def get(pid: str) -> dict | None:
    return _read_index()["projects"].get(pid)


def _dir(path: str) -> pathlib.Path:
    d = STORE / project_id(path)
    d.mkdir(parents=True, exist_ok=True)
    return d


def save_artifact(project_path: str, kind: str, data) -> str:
    d = _dir(project_path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    f = d / f"{kind}-{stamp}.json"
    f.write_text(json.dumps(data, ensure_ascii=False, indent=2, default=str), encoding="utf-8")
    latest_file = d / "latest.json"
    latest = {}
    if latest_file.exists():
        try:
            latest = json.loads(latest_file.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            latest = {}
    latest[kind] = {"file": str(f), "at": stamp}
    latest_file.write_text(json.dumps(latest, ensure_ascii=False, indent=2), encoding="utf-8")
    return str(f)


def latest(project_path: str) -> dict:
    d = STORE / project_id(project_path)
    lf = d / "latest.json"
    if not lf.exists():
        return {}
    try:
        return json.loads(lf.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def load_artifact(project_path: str, kind: str):
    meta = latest(project_path).get(kind)
    if not meta:
        return None
    try:
        return json.loads(pathlib.Path(meta["file"]).read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None


def read_source(project_path: str, rel_path: str, max_bytes: int = 400_000) -> dict:
    """Read a file inside the project only; the UI must never escape the root."""
    root = pathlib.Path(project_path).resolve()
    target = (root / rel_path).resolve()
    if root not in target.parents and target != root:
        return {"ok": False, "error": "路径越界"}
    if not target.is_file():
        return {"ok": False, "error": "文件不存在"}
    try:
        text = target.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    return {"ok": True, "path": target.relative_to(root).as_posix(),
            "lines": text.splitlines(), "truncated": len(text) >= max_bytes}
