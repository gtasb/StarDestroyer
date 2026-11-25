"""Projects and their artifacts.

A project is a path the user audits repeatedly. Every run is kept next to the
project record: the console shows the latest one per kind without re-running
anything, and older ones stay reachable as history.
"""

import hashlib
import os
import pathlib
import shutil
import time
import uuid

from . import store

STORE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "projects"
KINDS = ("sast", "secrets", "triage", "graph", "tabby")
KEEP_RUNS = 20


def _index() -> pathlib.Path:
    return STORE / "projects.json"


def project_id(path: str) -> str:
    return hashlib.sha256(str(pathlib.Path(path).resolve()).encode()).hexdigest()[:12]


def add(path: str, name: str = "", **fields) -> dict:
    if not str(path).strip():
        return {"ok": False, "error": "请填写项目路径"}
    p = pathlib.Path(path).resolve()
    if not p.exists():
        return {"ok": False, "error": f"路径不存在: {path}"}
    pid = project_id(str(p))
    with store.update(_index(), {"projects": {}, "active": ""}) as idx:
        existed = pid in idx["projects"]
        entry = idx["projects"].get(pid) or {
            "id": pid, "path": str(p), "name": name or p.name,
            "created": time.strftime("%Y-%m-%d %H:%M"),
        }
        if name:
            entry["name"] = name
        entry.update({k: v for k, v in fields.items() if k in EDITABLE and v is not None})
        idx["projects"][pid] = entry
        idx["active"] = pid
    return {"ok": True, "project": entry, "existed": existed}


EDITABLE = ("name", "lang", "jar", "build", "indirect", "note")


def edit(pid: str, fields: dict) -> dict:
    with store.update(_index(), {"projects": {}, "active": ""}) as idx:
        entry = idx["projects"].get(pid)
        if not entry:
            return {"ok": False, "error": "项目不存在"}
        entry.update({k: str(v)[:500] for k, v in fields.items() if k in EDITABLE and v is not None})
        entry["name"] = entry.get("name") or pathlib.Path(entry["path"]).name
    return {"ok": True, "project": entry}


def remove(pid: str) -> dict:
    """Forget the project and its run records. The audited source is not touched."""
    with store.update(_index(), {"projects": {}, "active": ""}) as idx:
        if idx["projects"].pop(pid, None) is None:
            return {"ok": False, "error": "项目不存在"}
        if idx.get("active") == pid:
            idx["active"] = next(iter(idx["projects"]), "")
    from . import chat
    chat.forget(pid)
    shutil.rmtree(STORE / pid, ignore_errors=True)
    return {"ok": True}


def list_all() -> dict:
    idx = store.read(_index(), {"projects": {}, "active": ""})
    items = sorted(idx["projects"].values(), key=lambda x: x.get("created", ""), reverse=True)
    for it in items:
        it["runs"] = latest(it["path"])
        for kind, meta in it["runs"].items():  # runs filed before summaries existed
            if "summary" not in meta:
                meta["summary"] = summarize(kind, load_artifact(it["path"], kind) or {})
        for kind in ("secrets", "sast"):  # show what has been decided since
            if kind in it["runs"]:
                it["runs"][kind]["summary"].update(_now(findings(it["path"], kind)))
        it["artifacts"] = sorted(it["runs"])
        from . import audit
        it["audit"] = audit.summary(it["path"])
        for kind, meta in it["runs"].items():  # a gap an agent closed is not one any more
            mine = [g for g in it["audit"].get("engine_gaps") or [] if g["kind"] == kind and g["run"] == pathlib.Path(meta.get("file") or "").name]
            if mine and meta["summary"].get("gaps"):
                left = sum(not g["closed"] for g in mine)
                meta["summary"].update(gaps=left, complete=not left, by_agent=len(mine) - left)
        it["exists"] = pathlib.Path(it["path"]).exists()
    return {"ok": True, "active": idx.get("active", ""), "projects": items}


def _now(recs: list[dict]) -> dict:
    from . import pipeline
    live = [r for r in recs if r["status"] != "rejected"]
    return {**pipeline._counts(recs), "reportable": len(live), **pipeline.standing(recs)}


def activate(pid: str) -> dict:
    with store.update(_index(), {"projects": {}, "active": ""}) as idx:
        if pid not in idx["projects"]:
            return {"ok": False, "error": "项目不存在"}
        idx["active"] = pid
        project = idx["projects"][pid]
    return {"ok": True, "active": pid, "project": project}


def get(pid: str) -> dict | None:
    return store.read(_index(), {"projects": {}})["projects"].get(pid)


def _dir(path: str) -> pathlib.Path:
    return STORE / project_id(path)


def summarize(kind: str, data: dict) -> dict:
    """The few numbers a project list needs, so it never opens the full artifact."""
    out = {"complete": data.get("complete"), "gaps": len(data.get("incomplete_reasons") or [])}
    if kind in ("sast", "tabby", "secrets"):
        out.update(data.get("status_counts") or {})
        out["reportable"] = data.get("reportable", 0)
        out["severity"] = data.get("severity_counts") or {}
    if kind == "sast":
        out.update(language=data.get("language"), files=(data.get("coverage") or {}).get("files"))
    if kind == "triage":
        out.update({k: (data.get("stats") or {}).get(k) for k in ("dependencies", "kept", "ignored", "unresolved")})
    if kind == "graph":
        out.update(data.get("counts") or {})
    if kind == "tabby":
        out["chains"] = data.get("chains_total", data.get("chains"))
    return out


def save_artifact(project_path: str, kind: str, data) -> str:
    d = _dir(project_path)
    stamp = time.strftime("%Y%m%d-%H%M%S")
    f = d / f"{kind}-{stamp}-{uuid.uuid4().hex[:4]}.json"
    store.write(f, data)
    with store.update(d / "latest.json", {}) as idx:
        idx[kind] = {"file": str(f), "at": stamp,
                     "summary": summarize(kind, data) if isinstance(data, dict) else {}}
    for old in sorted(d.glob(f"{kind}-*.json"))[:-KEEP_RUNS]:
        old.unlink(missing_ok=True)
    return str(f)


def latest(project_path: str) -> dict:
    return store.read(_dir(project_path) / "latest.json", {})


def history(project_path: str) -> list[dict]:
    out = []
    for f in _dir(project_path).glob("*-*.json"):
        kind, _, rest = f.stem.partition("-")
        if kind in KINDS:
            out.append({"run": f.name, "kind": kind, "at": rest[:15],
                        "summary": summarize(kind, store.read(f, {}))})
    return sorted(out, key=lambda r: r["at"], reverse=True)


def load_artifact(project_path: str, kind: str, run: str = ""):
    d = _dir(project_path)
    if run:
        # run names come from the URL: only a plain file name of ours is accepted
        if run != pathlib.PurePath(run).name or not run.startswith(f"{kind}-") or not run.endswith(".json"):
            return None
        return store.read(d / run, None)
    meta = latest(project_path).get(kind)
    return store.read(pathlib.Path(meta["file"]), None) if meta else None


def findings(project_path: str, kind: str, run: str = "") -> list[dict]:
    """Every finding of a run, with the current human decisions applied."""
    from . import audit, decisions, pipeline
    if kind == "agent":
        return audit.findings(project_path)
    art = load_artifact(project_path, kind, run) or {}
    name = (art.get("artifacts") or {}).get("findings_json") or ""
    if not name or not inside(pipeline.SCANS_DIR, name):
        return []
    recs = store.read(pathlib.Path(name), [])
    decisions.apply(recs)
    return recs


def inside(root: pathlib.Path, path: str) -> bool:
    """Textual containment; abspath/join do no I/O, so a UNC path is never contacted."""
    base = os.path.normcase(str(root)).rstrip("\\/")
    want = os.path.normcase(os.path.abspath(os.path.join(root, path)))
    return want == base or want.startswith(base + os.sep)


def read_source(project_path: str, rel_path: str, max_bytes: int = 400_000) -> dict:
    """Read a file inside the project only; the UI must never escape the root."""
    root = pathlib.Path(project_path).resolve()
    # Compare the text first: merely resolving //host/share makes Windows connect
    # to it and hand over the user's NTLM response.
    # Absolute paths inside the root are fine; traces carry them.
    base = root if root.is_dir() else root.parent
    if not inside(base, rel_path):
        return {"ok": False, "error": "路径越界"}
    target = (base / rel_path).resolve()
    if base not in target.parents and target != base:
        return {"ok": False, "error": "路径越界"}
    if not target.is_file():
        # An agent may name a file without its directories; good enough if there is one.
        from . import profile
        tail, found = [x for x in rel_path.replace("\\", "/").split("/") if x not in ("", ".")], []
        for here, dirs, files in os.walk(base):
            dirs[:] = [d for d in dirs if d not in profile.SKIP_DIRS]
            if tail and tail[-1] in files and [*pathlib.Path(here).relative_to(base).parts, tail[-1]][-len(tail):] == tail:
                found.append(pathlib.Path(here) / tail[-1])
        if len(found) != 1:
            return {"ok": False, "error": f"有 {len(found)} 个同名文件，分不清是哪个" if found else "文件不存在"}
        target = found[0].resolve()
        if base not in target.parents:
            return {"ok": False, "error": "路径越界"}
    try:
        text = target.read_text(encoding="utf-8", errors="replace")[:max_bytes]
    except OSError as exc:
        return {"ok": False, "error": str(exc)}
    # splitlines() also breaks on \f and friends, which shifts every line number
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return {"ok": True, "path": target.relative_to(base).as_posix(),
            "lines": lines, "truncated": len(text) >= max_bytes}
