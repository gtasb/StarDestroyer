"""A scan that was stopped goes on where it was, and indirect dependencies are a choice."""

import json
import os
import pathlib
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import _env  # noqa: F401
from core import agents, checkpoint, decisions, epss, nvd, osv, pipeline, proc, projects, review, rulebase, rulegen, sca, sca_triage, tasks

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:500]}"))
    if not ok:
        FAILED.append(name)


def put(d: pathlib.Path, files: dict) -> str:
    for k, v in files.items():
        (d / k).parent.mkdir(parents=True, exist_ok=True)
        (d / k).write_text(v, encoding="utf-8")
    return str(d.resolve())


def parts(tmp) -> None:
    root = put(tmp / "app", {"a.py": "import os\nos.system(input())\n", "b.js": "eval(location.hash)\n", "c.go": "package main\n"})
    ran, stop_at, real = [], [None], pipeline.opengrep.run_scan

    def run(src, rules, at=None, **k):
        if at:
            return {"ok": True, "findings": []}
        if stop_at[0] is not None and len(ran) == stop_at[0]:
            raise proc.Cancelled()
        ran.append(rules)
        return {"ok": True, "findings": [], "total": 0, "errors": 0, "error_items": [], "scanned": [f"f{len(ran)}"], "raw": "x"}
    pipeline.opengrep.run_scan = run

    def scan(stop=None):
        ran.clear()
        stop_at[0] = stop
        try:
            return pipeline._engine(root, ["go", "js", "python"], [])
        except proc.Cancelled:
            return None
    check("a scan that is stopped", scan(2) is None and len(ran) == 2, ran)
    s = checkpoint.summary(root).get("sast", {})
    check("keeps its finished parts", s.get("done") == 2 and s.get("total") == 3, s)
    r = scan()
    check("and goes on with the rest", r["ok"] and len(ran) == 1 and r["resumed"] == 2, (ran, r))
    check("with what the finished parts found", sorted(r["scanned"]) == ["f1", "f2"] or len(r["scanned"]) == 3, r["scanned"])
    check("a finished scan leaves nothing behind, so the next one is whole", not checkpoint.summary(root) and scan() and len(ran) == 3, ran)
    scan(2)
    put(tmp / "app", {"a.py": "import os\nprint(1)\n# changed\n"})
    r = scan()
    check("changed source starts over", len(ran) == 3 and r["resumed"] == 0, ran)
    scan(2)
    checkpoint.clear(root, "sast")
    scan()
    check("so does a request to", len(ran) == 3, ran)
    pipeline.opengrep.run_scan = lambda *a, **k: {"ok": False, "error": "crash", "findings": [], "total": 0}
    r = pipeline._engine(root, ["go"], [])
    check("a part that failed is not kept as done", not r["ok"] and not checkpoint.summary(root), checkpoint.summary(root))
    pipeline.opengrep.run_scan = real
    checkpoint._dir(root).mkdir(parents=True, exist_ok=True)
    (checkpoint._dir(root) / "sast.json").write_text("{broken", encoding="utf-8")
    check("a damaged checkpoint costs a rescan, not an error", checkpoint.Checkpoint(root, "sast", 1).resumed == 0 and checkpoint.summary(root) == {})


def indirect(tmp) -> None:
    root = put(tmp / "app", {"pom.xml": "<project/>"})
    row = lambda n, direct: {"vendor": "g", "name": n, "version": "1.0", "language": "Java", "direct": direct, "paths": []}
    asked, resolved = [], []
    keep = nvd.lookup, sca.components, epss.scores, osv.query
    nvd.lookup = lambda k, v=None, group="": (asked.append(k), {"ok": True, "cached": False, "affected": []})[-1]
    sca.components = lambda r: (resolved.append(1), {"ok": True, "source": "opensca", "components": [row("near", True), row("far", False)]})[-1]
    p = projects.add(root)["project"]

    def names(**k):
        asked.clear()
        checkpoint.clear(root)
        return [c["name"] for c in sca.enrich(root, **k)["components"]]
    check("indirect dependencies are scanned unless turned off", names() == ["near", "far"])
    os.environ["SCA_INDIRECT"] = "0"
    check("turned off for all", names() == ["near"] and "far" not in asked, asked)
    r = sca.enrich(root)
    check("and said so, not as a gap", r["indirect"] is False and r["indirect_skipped"] == 1, r)
    projects.edit(p["id"], {"indirect": "1"})
    check("the project's choice goes before", names() == ["near", "far"])
    check("and this run's before that", names(indirect=False) == ["near"])
    os.environ.pop("SCA_INDIRECT")
    projects.edit(p["id"], {"indirect": "0"})
    check("off for one project", names() == ["near"] and names(indirect=True) == ["near", "far"])
    t = sca_triage.triage({"ok": True, "components": [], "indirect_skipped": 3})
    check("the result says how many were left out", "'indirect_skipped': 3" in str(t), t)
    source = "".join(f.read_text(encoding="utf-8") for f in [*(ROOT / "web" / "static").glob("*.js"), ROOT / "README.md", ROOT / "SKILL.md"])
    check("they are called by one name everywhere", "传递依赖" not in source)

    checkpoint.clear(root)
    resolved.clear()

    def halt(*a, **k):
        raise proc.Cancelled()
    nvd.lookup = halt
    try:
        sca.enrich(root, indirect=True)
        stopped = False
    except proc.Cancelled:
        stopped = True
    nvd.lookup = lambda k, v=None, group="": {"ok": True, "cached": False, "affected": []}
    sca.enrich(root, indirect=True)
    check("a stopped dependency scan does not resolve the tree again", stopped and len(resolved) == 1, (stopped, resolved))
    sca.enrich(root, indirect=True)
    check("a finished one does", len(resolved) == 2, resolved)
    nvd.lookup, sca.components, epss.scores, osv.query = keep


def sessions(tmp) -> None:
    root = put(tmp / "app", {"a.py": "x = 1\n"})
    runs, play = [], []
    real_run, real_cmd, real_label = proc.run, agents.command, agents.providers.label
    agents.command = lambda patch, session="": ["dsh", session]
    agents.providers.label = lambda: "m1"
    out = lambda text=json.dumps({"type": "final", "reason": {"kind": "completed"}}): type("R", (), {"stdout": text, "stderr": "", "returncode": 0})()

    def run(cmd, **k):
        runs.append({"session": cmd[1], "cwd": k["cwd"], "prompt": k["input"], "resumed": json.loads(pathlib.Path(k["env"]["SD_SPEC"]).read_text(encoding="utf-8"))["resumed"]})
        what = play.pop(0)
        if what == "cancel":
            pathlib.Path(k["env"]["SD_SESSION"]).write_text(json.dumps({"session": "S-1", "sig": k["env"]["SD_SESSION_SIG"]}), encoding="utf-8")
            raise proc.Cancelled()
        if what == "lost":
            return out("")
        pathlib.Path(k["env"]["SD_RESULT"]).write_text('{"a": 1}', encoding="utf-8")
        return out()
    proc.run = run
    task = agents.Task("t", "SYS", "P", {}, lambda v: (v, ""))
    spec = {"type": "audit", "root": root, "unit": {"id": "u1resume", "kind": "sink"}}

    def go(*what):
        runs.clear()
        play[:] = what
        try:
            return agents._dsh(task, spec)
        except proc.Cancelled:
            return None
    f = checkpoint.session_file(root, "u1resume")
    check("stopping a unit keeps its session and workspace", go("cancel") is None and f.exists() and pathlib.Path(runs[0]["cwd"]).is_dir(), f)
    first = runs[0]["cwd"]
    r = go("ok")
    check("next time it goes on in it, with a word instead of the task", r["ok"] and r["resumed"] and runs[0]["session"] == "S-1" and runs[0]["cwd"] == first and "SYS" not in runs[0]["prompt"] and runs[0]["resumed"], runs)
    check("a finished unit keeps neither", not f.exists() and not pathlib.Path(first).exists())
    go("cancel")
    agents.providers.label = lambda: "m2"
    r = go("ok")
    check("another model starts over", not r["resumed"] and runs[0]["session"] == "" and "SYS" in runs[0]["prompt"], runs)
    agents.providers.label = lambda: "m1"
    go("cancel")
    os.utime(f, (1, 1))
    check("so does an old session", go("ok")["resumed"] is False, runs)
    go("cancel")
    r = go("lost", "ok")
    check("a session that cannot be taken up is begun again", r["ok"] and not r["resumed"] and [x["session"] for x in runs] == ["S-1", ""] and "SYS" in runs[1]["prompt"], runs)
    check("and then its first answer must come from reading again", runs[1]["resumed"] is False, runs)
    proc.run, agents.command, agents.providers.label = real_run, real_cmd, real_label


def state(tmp) -> None:
    tasks.FILE = tmp / "tasks.json"
    root = put(tmp / "app", {"a.py": "x = 1\n"})
    p = projects.add(root)["project"]
    given, real = [], dict(tasks._RUN)
    tasks._RUN["sast"] = lambda project, params: (given.append(params), {"ok": False, "error": "x"})[-1]
    row = lambda i, kind, state, at, **k: {"id": i, "project_id": p["id"], "project": "app", "kind": kind, "label": kind, "params": k, "state": state, "stage": "", "created": "", "created_ts": at}
    rows = [row("1", "sast", "running", 1, lang="python", fresh=True), row("2", "secrets", "done", 2), row("3", "triage", "cancelled", 3), row("4", "triage", "done", 4), row("5", "graph", "cancelled", 5)]
    tasks.FILE.write_text(json.dumps({r["id"]: r for r in rows}), encoding="utf-8")
    c = checkpoint.Checkpoint(root, "sast", 1)
    c.total = 4
    c.put("a", 1)
    m = tasks.Manager()
    m.load()
    by = {t["id"]: t for t in m.list()}

    def wait(until):
        end = time.time() + 10
        while not until() and time.time() < end:
            time.sleep(0.05)
    idle = lambda: not any(t["state"] in tasks.LIVE for t in m.list())
    check("a task the console's restart cut off is known as such", by["1"]["state"] == "interrupted" and by["1"]["resumable"] and by["1"]["saved"]["done"] == 1, by["1"])
    check("finished work, and what was redone since, cannot be taken up", not by["2"]["resumable"] and not by["3"]["resumable"] and by["5"]["resumable"])
    r = m.resume()
    check("all that was interrupted goes on, nothing that a person cancelled", r["ok"] and [t["kind"] for t in r["tasks"]] == ["sast"], r)
    wait(lambda: given and idle())
    check("with its parameters, but not from the beginning", given and given[0].get("lang") == "python" and "fresh" not in given[0] and checkpoint.summary(root)["sast"]["done"] == 1, given)
    given.clear()
    m.submit(p, "sast", {"fresh": True})
    wait(lambda: given and idle())
    check("starting over forgets the checkpoint", given and checkpoint.summary(root) == {}, checkpoint.summary(root))
    check("nothing to take up is said so", not m.resume(["nope"])["ok"])
    tasks._RUN.update(real)


def main() -> int:
    saved = dict(os.environ)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        for fn in (parts, indirect, sessions, state):
            print(f"-- {fn.__name__}")
            mine = pathlib.Path(d) / fn.__name__
            mine.mkdir()
            projects.STORE, pipeline.SCANS_DIR, rulegen.OUT_DIR = mine / "store", mine / "scans", mine / "rules"
            review.FILE, decisions.FILE = mine / "r.json", mine / "d.json"
            os.environ["SCA_OSV"] = "0"
            os.environ.pop("SCA_INDIRECT", None)
            fn(mine)
    os.environ.clear()
    os.environ.update(saved)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
