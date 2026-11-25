"""Bugs that were found once and must not come back. Offline."""

import json
import pathlib
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
__import__("os").environ["SCA_OSV"] = "0"  # offline

import _env  # noqa: F401
from core import (config, decisions, endpoints, fact_status, jobs, kb, logging, nvd, pipeline, proc, profile,
                  projects, rulegen, sarif, sca, sca_triage, store, tasks, toolset)

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        FAILED.append(name)


def put(d: pathlib.Path, files: dict[str, str]) -> str:
    for name, body in files.items():
        (d / name).parent.mkdir(parents=True, exist_ok=True)
        (d / name).write_text(body, encoding="utf-8")
    return str(d)


def versions(tmp) -> None:
    for a, op, b in [("4.3.4.RELEASE", "==", "4.3.4"), ("9.4.48.v20220622", "==", "9.4.48"), ("2.0-rc1", "<", "2.0"),
                     ("2.0-SNAPSHOT", "<", "2.0"), ("1.2.0", "==", "1.2"), ("1.9rc2", "<", "1.10"), ("v1.2", ">", "1.0"),
                     ("1.10", ">", "1.9a"), ("9.10rc1", ">", "9.9"), ("1.0.2k", ">", "1.0.2"), ("1.0.2k", "<", "1.0.2u"),
                     ("2.0-beta9", "<", "2.0-rc1"), ("42.2.5.jre7", "==", "42.2.5"), ("32.1.2-jre", "==", "32.1.2"),
                     ("2.0.0-M5", "<", "2.0.0-RC1"), ("1.0.post1", ">", "1.0"), ("5.3.0", ">", "5.2.99")]:
        r = nvd._cmp(a, b)
        check(f"{a} {op} {b}", {"==": r == 0, "<": r < 0, ">": r > 0}[op], r)
    for v, ok in [("1.0", True), ("v1.0", True), ("${x}", False), ("[1,2)", False), ("", False), ("latest", False)]:
        check(f"comparable({v!r})", nvd.comparable(v) is ok)
    exact = {"criteria": "cpe:2.3:a:a:b:2.0:beta9:*:*:*:*:*:*"}
    check("2.0:beta9 does not match 2.0", not nvd._version_in_range("2.0", exact))
    check("2.0:beta9 matches 2.0-beta9", nvd._version_in_range("2.0-beta9", exact))


def state(tmp) -> None:
    f = tmp / "s" / "x.json"

    def bump(i):
        with store.update(f, {}) as d:
            d[str(i)] = i
    ts = [threading.Thread(target=bump, args=(i,)) for i in range(40)]
    [t.start() for t in ts]
    [t.join() for t in ts]
    check("concurrent updates all survive", len(store.read(f, {})) == 40, len(store.read(f, {})))
    f.write_text("{broken", encoding="utf-8")
    check("a corrupt file is kept aside, not overwritten",
          store.read(f, {}) == {} and list(f.parent.glob("x.json.corrupt-*")))
    f.write_bytes(b"\xef\xbb\xbf" + json.dumps({"a": 1}).encode())
    check("a BOM is accepted", store.read(f, {}) == {"a": 1})

    projects.STORE = tmp / "store"
    dirs = [put(tmp / f"p{i}", {"a.py": "x=1"}) for i in range(20)]
    ts = [threading.Thread(target=projects.add, args=(d,)) for d in dirs]
    [t.start() for t in ts]
    [t.join() for t in ts]
    check("concurrent project adds all survive", len(projects.list_all()["projects"]) == 20)
    ts = [threading.Thread(target=projects.save_artifact, args=(dirs[0], k, {"ok": True})) for k in projects.KINDS * 5]
    [t.start() for t in ts]
    [t.join() for t in ts]
    check("concurrent artifacts all survive", set(projects.latest(dirs[0])) == set(projects.KINDS)
          and len(projects.history(dirs[0])) == 5 * len(projects.KINDS), len(projects.history(dirs[0])))
    check("an empty path is not the current directory", projects.add("")["ok"] is False)
    pid = projects.project_id(dirs[0])
    check("removing a project leaves its source", projects.remove(pid)["ok"] and pathlib.Path(dirs[0], "a.py").exists()
          and not (projects.STORE / pid).exists())
    for run in ("../projects.json", "sast-x/../../projects.json", "..\\projects.json"):
        check(f"run {run!r} is refused", projects.load_artifact(dirs[1], "sast", run) is None)
    put(tmp / "ff", {"a.py": "one\x0cstill one\ntwo\n"})
    check("form feed does not shift lines", projects.read_source(str(tmp / "ff"), "a.py")["lines"][:2] == ["one\x0cstill one", "two"])

    pipeline.SCANS_DIR = tmp / "scans"
    check("scan directories are unique", len({pipeline.new_scan_dir() for _ in range(50)}) == 50)
    one = sarif.to_sarif([{"rule_id": "a", "file": "D:\\x\\中 文.java", "line": 1}])["runs"][0]
    two = sarif.to_sarif([{"rule_id": "b", "file": "中 文.java", "line": 1}])["runs"][0]
    uri = one["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    check("SARIF rules do not leak between runs", [r["id"] for r in two["tool"]["driver"]["rules"]] == ["b"])
    check("SARIF URIs are encoded", uri.startswith("file:///D:/x/%E4%B8%AD%20"), uri)


def settings(tmp) -> None:
    import os
    config.CONFIG_DIR, config.CONFIG_FILE = tmp / "cfg", tmp / "cfg" / "config.json"
    key = next(k for k in config.SECRET_KEYS if k not in config._EXPORTED)
    for v in ("first-value-aaaaaaaa", "second-value-bbbbbbb"):
        config.save({key: v})
        check(f"saving {v[:6]} takes effect at once", os.environ.get(key) == v)
    check("source is the file", config.view()["keys"][key]["source"] == "file")
    check("a secret is never returned whole", config.view()["keys"][key]["value"] not in ("", v))
    config.save({key: ""})
    check("clearing takes effect at once", key not in os.environ)
    config.CONFIG_FILE.write_text('{"%s": 5}' % key, encoding="utf-8")
    config.apply()
    check("a non-string value does not crash", os.environ.get(key) == "5")
    config.save({key: ""})


def log(tmp) -> None:
    logging.LOG_DIR, logging.LOG_FILE = tmp, tmp / "x.log"
    logging.info("t", "m", level="x", path=tmp, bad={1, 2}, text="a\n2026-01-01 00:00:00 ERROR forged")
    lines = logging.LOG_FILE.read_text(encoding="utf-8").splitlines()
    check("odd fields are logged and cannot forge a line", len(lines) == 1, lines)


def knowledge(tmp) -> None:
    import sqlite3
    kb.DB_PATH = tmp / "kb.db"
    old = sqlite3.connect(kb.DB_PATH)  # the first schema, whose index could not delete
    old.executescript("CREATE TABLE docs(id TEXT PRIMARY KEY, title TEXT, path TEXT, added_at TEXT);"
                      "CREATE TABLE chunks(id INTEGER PRIMARY KEY, doc_id TEXT, ord INTEGER, text TEXT);"
                      "CREATE VIRTUAL TABLE chunks_fts USING fts5(tokens, content='');"
                      "INSERT INTO docs VALUES('d','old','old.md','');INSERT INTO chunks VALUES(1,'d',0,'zebra crossing');")
    old.commit()
    old.close()
    check("an old index is rebuilt from its chunks", kb.search("zebra"))
    check("a document in it can be removed", kb.remove("d")["ok"] and not kb.search("zebra"))
    docs = str(ROOT / "demo" / "kb-docs")
    check("a document can be ingested twice", kb.ingest_dir(docs)["docs"] == kb.ingest_dir(docs)["docs"] > 0)
    check("twice is not double", len(kb.list_docs()) == len({d["path"] for d in kb.list_docs()}))
    for q in ("SQL 注入怎么判断", "怎么审计反序列化漏洞", "反序列化", "链", "SQL注入 union"):
        check(f"question finds something: {q}", kb.search(q))
    check("best match first", "deserial" in kb.search("反序列化 readObject")[0]["path"], kb.search("反序列化 readObject")[0]["path"])
    for q in ('"', "a OR", "NEAR(", "*", "''", "col:x"):
        kb.search(q)
    check("query syntax is inert", True)
    check("an empty folder name is refused", kb.ingest_dir("")["ok"] is False)
    doc = kb.list_docs()[0]
    check("a document can be removed", kb.remove(doc["id"])["ok"] and not any(h["path"] == doc["path"] for h in kb.search("注入 反序列化", 50)))


def routes(tmp) -> None:
    src = put(tmp / "ep", {
        "A.java": '/* @GetMapping("/no") */\n@RequestMapping(path = "/api")\nclass A {\n @GetMapping X l() {}\n'
                  ' @GetMapping({"/a","/b"}) X ab() {}\n @RequestMapping(method = RequestMethod.POST, value = "/c") X c() {}\n'
                  ' @PostMapping(\n  path = "/d") X d() {}\n}\nclass B { @DeleteMapping("/p/{id}") X p() {} }\n',
        "R.java": '@Path("/r")\nclass R {\n @GET @Path("/one") X o() {}\n @POST X t() {}\n}\n',
        "a.py": 'bp = Blueprint("x", __name__, url_prefix="/adm")\n@bp.route("/x", methods=["POST"])\ndef f(): pass\n'
                '# @app.get("/no")\n@app.get(path="/me")\nasync def g(): pass\n',
        "m.go": 'import "github.com/gin-gonic/gin"\nfunc r() { v := r.Group("/v1"); v.GET("/x", h); m.Get("key") }\n'})
    got = {(e["method"], e["path"]) for e in endpoints.extract(src)}
    want = {("GET", "/api"), ("GET", "/api/a"), ("GET", "/api/b"), ("POST", "/api/c"), ("POST", "/api/d"),
            ("DELETE", "/p/{id}"), ("GET", "/r/one"), ("POST", "/r"), ("POST", "/adm/x"), ("GET", "/me"), ("GET", "/v1/x")}
    check("endpoints", got == want, got ^ want)
    for deps, fam in ((["github.com/gin-gonic/gin v1.9.0", "gorm.io/gorm v1.25.0"], {"gin", "gorm"}),):
        p = profile.profile(put(tmp / "go", {"go.mod": "module x\n\nrequire (\n\t" + "\n\t".join(deps) + "\n)\n", "a.go": "package a"}))
        check("go.mod frameworks", fam <= set(p["frameworks"]), p["frameworks"])
    pom = "<project><dependencies>%s</dependencies></project>" % "".join(
        f"<dependency><artifactId>{a}</artifactId></dependency>" for a in
        ("spring-boot-starter-data-jpa", "mybatis-spring-boot-starter", "spring-boot-starter-jdbc"))
    p = profile.profile(put(tmp / "mv", {"mod/pom.xml": pom, "A.java": "class A {}"}))
    check("pom frameworks, nested module", {"jpa", "mybatis", "jdbc"} <= set(p["frameworks"]), p["frameworks"])
    p = profile.profile(put(tmp / "py", {"requirements.txt": "flask[async]>=2\nDjango ; python_version>'3'\n", "a.py": ""}))
    check("requirements with extras and markers", {"flask", "django"} <= set(p["frameworks"]), p["frameworks"])


def rules_per_project(tmp) -> None:
    rulegen.OUT_DIR = tmp / "gen"
    a = put(tmp / "ra", {"requirements.txt": "django\n", "a.py": "def f(request):\n    U.objects.raw('a' + request.GET.get('q'))\n"})
    b = put(tmp / "rb", {"requirements.txt": "flask\n", "a.py": "x = 1\n"})
    ra, rb = toolset._prepare_rules(a), toolset._prepare_rules(b)
    check("each project has only its own rules", len(ra["files"]) == 1 and "django" in ra["files"][0]
          and len(rb["files"]) == 1 and "flask" in rb["files"][0], (ra["files"], rb["files"]))
    real, rulegen.CATALOG["flask"] = rulegen.CATALOG["flask"], {**rulegen.CATALOG["flask"], "sinks": ["qqqq($Q)"]}
    check("one project's rules survive another's scan", pathlib.Path(ra["files"][0]).exists())
    rulegen._PROVED.clear()
    r = toolset.auto_scan(b)
    rulegen.CATALOG["flask"] = real
    check("a rule that proves nothing is dropped, the scan still runs",
          r["ok"] and r["complete"] is False and r["rules_failed"], r.get("incomplete_reasons"))


def triage(tmp) -> None:
    sca_triage.VERDICT_FILE = tmp / "v"
    sca_triage.epss.scores = lambda ids: {}
    app = put(tmp / "app", {"A.java": "import com.google.common.collect.Lists;\nclass A {}\n",
                            "m.go": 'package m\nimport (\n\t"github.com/gin-gonic/gin"\n)\n', "a.py": "import yaml\n"})
    used = lambda **c: sca_triage._source_usage(app, sca_triage._tokens(c))["used"]
    check("guava is recognised", used(name="guava", vendor="com.google.guava"))
    check("a go import block is recognised", used(name="github.com/gin-gonic/gin", vendor=""))
    check("PyYAML is recognised", used(name="PyYAML", vendor="", language="Python"))
    comp = lambda **k: {"ok": True, "components": [{"name": "zlib", "version": "1", "vendor": "", "direct": True, **k,
                        "cves": [{"id": "CVE-1", "score": 5.0, "matched_version": True}]}]}
    check("an unknown package name is not 'unused'", len(sca_triage.triage(comp(), app_root=app)["kept"]) == 1)
    check("a transitive dependency is not 'unused'",
          len(sca_triage.triage(comp(vendor="com.example", direct=False), app_root=app)["kept"]) == 1)

    many = {"kept": [{"cve": f"CVE-{i}", "dependency": "d", "version": "1", "cvss": i, "epss": None, "percentile": None,
                      "cwes": [], "family": None, "sinks": [], "reason": "", "group": "g.h",
                      "decision": "kept" if i > 25 else "pending"} for i in range(30)]}
    c = sca_triage.candidates(many, app)
    check("candidates are pending, worst first, with a remainder",
          c["candidates"][0]["cve"] == "CVE-25" and c["remaining"] == 6 and c["count"] == 20, (c["count"], c["remaining"]))
    (tmp / "v.txt").write_text("outside\n", encoding="utf-8")
    rec = lambda **k: sca_triage.record_verdicts(app, [{"cve": "CVE-1", "dependency": "a", "version": "1", "verdict": "ignore", **k}])
    for name, ev in (("no evidence", []), ("a made-up check", [{"check": "x"}]), ("a missing file", [{"file": "no.java", "line": 1}]),
                     ("a line past the end", [{"file": "A.java", "line": 99}]), ("a path outside", [{"file": "../v.txt", "line": 1}]),
                     ("a string", "trust me"), ("junk items", [1, None, "x"])):
        check(f"ignore with {name} is refused", rec(evidence=ev)["recorded"] == 0)
    check("junk verdicts are refused one by one", sca_triage.record_verdicts(app, ["x", None])["recorded"] == 0)
    check("ignore with a real line is accepted", rec(evidence=[{"file": "A.java", "line": 1}])["recorded"] == 1)
    rows = {"kept": [{"cve": "CVE-1", "dependency": d, "version": v, "reason": ""} for d, v in (("a", "1"), ("b", "9"), ("a", "2"))]}
    t = sca_triage.apply_verdicts(rows, sca_triage.load_verdicts(app))
    check("a verdict covers one dependency and version", len(t["ignored"]) == 1 and len(t["kept"]) == 2)
    pom = put(tmp / "mm", {"pom.xml": "<project><parent><groupId>g</groupId><artifactId>par</artifactId></parent>"
                                      "<artifactId>me</artifactId><dependencies><dependency><groupId>x</groupId>"
                                      "<artifactId>dep</artifactId></dependency></dependencies></project>"})
    check("a module is the project, its dependencies are not", sca._own_modules(pom) == {("g", "me")}, sca._own_modules(pom))
    check("a rejection overrides a guess", fact_status.promote("INFERRED", "REJECTED") == "REJECTED")
    check("a rejection does not override an observation", fact_status.promote("OBSERVED", "REJECTED") == "OBSERVED")


def background(tmp) -> None:
    tasks.FILE = tmp / "tasks.json"
    projects.STORE = tmp / "tstore"
    a = projects.add(put(tmp / "ta", {"a.py": "x=1"}))["project"]
    b = projects.add(put(tmp / "tb", {"a.py": "x=1"}))["project"]
    m = tasks.Manager()
    gate = threading.Event()

    def fake(p, opt):
        proc.stage("working")
        while not gate.is_set():
            proc.check()
            time.sleep(0.01)
        return {"ok": True, "complete": True, "root": p["path"]}

    def until(tid, *states, limit=30):
        end = time.time() + limit
        while time.time() < end:
            t = m.get(tid)
            if t["state"] in states:
                return t
            time.sleep(0.02)
        return m.get(tid)
    tasks._RUN["sast"] = fake
    t1, t2 = m.submit(a, "sast")["task"]["id"], m.submit(b, "sast")["task"]["id"]
    check("the same task is not queued twice", m.submit(a, "sast").get("duplicate"))
    check("a task reports its stage", until(t1, "running") and any(m.get(t1)["stage"] == "working" or time.sleep(0.05) for _ in range(40)))
    m.cancel(t2)
    check("a running task can be cancelled", until(t2, "cancelled")["state"] == "cancelled")
    gate.set()
    check("a task finishes", until(t1, "done")["state"] == "done")
    check("its result is filed under its own project", projects.load_artifact(a["path"], "sast")["root"] == a["path"]
          and projects.load_artifact(b["path"], "sast") is None)
    tasks._RUN["sast"] = lambda p, o: {"ok": False, "error": "nope"}
    t = until(m.submit(a, "sast")["task"]["id"], "failed")
    check("a failed run keeps the last good result", t["error"] == "nope" and projects.load_artifact(a["path"], "sast"))
    tasks._RUN["sast"] = lambda p, o: 1 / 0
    check("a crash is a failed task", "ZeroDivision" in until(m.submit(a, "sast")["task"]["id"], "failed")["error"])
    check("a jar task without a jar is refused", m.submit(a, "tabby")["ok"] is False)

    def child(p, opt):
        proc.run([sys.executable, "-c", "import time; time.sleep(60)"], timeout=60)
    tasks._RUN["sast"] = child
    tid = m.submit(a, "sast")["task"]["id"]
    until(tid, "running")
    time.sleep(0.5)
    began = time.time()
    m.cancel(tid)
    check("cancelling kills the engine process", until(tid, "cancelled", "failed")["state"] == "cancelled" and time.time() - began < 10,
          m.get(tid))
    m._items["x"] = {**m._items[tid], "id": "x", "state": "running"}
    m._save()
    n = tasks.Manager()
    n.load()
    check("a task cut off by a restart is marked interrupted", n.get("x")["state"] == "interrupted")

    saved, jobs.JOBS_DIR = jobs.JOBS_DIR, tmp / "jobs"
    jobs.JOBS_DIR.mkdir()
    jid = jobs.submit([sys.executable, "-c", "import time; time.sleep(60)"])["job_id"]
    time.sleep(1)
    pid = int((jobs.JOBS_DIR / jid / "pid").read_text())
    jobs.kill_tree(pid)
    time.sleep(0.5)
    check("a killed job is lost, not running forever", jobs.status(jid)["state"] == "lost", jobs.status(jid))
    jid = jobs.submit([sys.executable, "-c", "import time; time.sleep(60)"])["job_id"]
    time.sleep(0.5)
    check("a job can be cancelled", jobs.cancel(jid)["ok"] and jobs.status(jid)["state"] == "cancelled")
    jobs.JOBS_DIR = saved
    decisions.FILE = tmp / "d.json"
    check("an unpinned finding cannot be decided on", decisions.put("", "false_positive")["ok"] is False)
    recs = [{"suppress_key": "k", "status": "confirmed", "reason": "engine"}]
    decisions.put("k", "accepted_risk", "ok")
    decisions.apply(recs)
    decisions.put("k", "")
    was = recs[0]["status"]
    decisions.apply(recs)
    check("clearing a decision restores the engine's verdict",
          was == "rejected" and recs[0]["status"] == "confirmed" and recs[0]["reason"] == "engine", recs)


def main() -> int:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        for fn in (versions, state, settings, log, knowledge, routes, rules_per_project, triage, background):
            print(f"-- {fn.__name__}")
            (tmp / fn.__name__).mkdir()
            fn(tmp / fn.__name__)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
