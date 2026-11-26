"""Test code is left out by default, counted, and nothing that ships is left out with it."""

import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import _env  # noqa: F401
from core import agents, airules, audit, codeintel, decisions, endpoints, hardcoded, ledger, pipeline, projects, review, rulegen, sca_triage, testcode

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))
    if not ok:
        FAILED.append(name)


def names(tmp) -> None:
    for rel in ("src/test/java/a/ATest.java", "core/src/test/resources/application.yml", "tests/test_x.py", "test/x.js", "src/androidTest/java/A.kt", "src/integrationTest/java/A.java", "integration-tests/src/main/java/A.java",
                "web/__tests__/a.ts", "web/src/a.spec.ts", "web/src/a.test.tsx", "web/src/a.stories.tsx", "pkg/a_test.go", "app/test_views.py", "app/views_test.py", "conftest.py", "e2e/a.ts", "a\\src\\test\\A.java", "testdata/x.go"):
        check(f"test code: {rel}", testcode.is_test(rel))
    for rel in ("src/main/java/com/corp/test/TestController.java", "src/main/java/a/LoginTest.java", "core/src/main/java/tests/A.java", "src/main/webapp/test/x.js", "src/a/Contest.java", "latest/a.py", "app/testing_utils.py", "src/attest/A.java",
                "pkg/test.go", "a/protest/x.js", "Test.java", "spec/openapi.ts", "web/src/test.ts", "greatest.py"):
        check(f"ships: {rel}", not testcode.is_test(rel))


JAVA = 'import javax.servlet.http.*;import java.sql.*;\nclass {n} {{ Object f(HttpServletRequest r, Statement st) throws Exception {{\n  return st.executeQuery("s" + r.getParameter("n"));\n}} }}\n'
CTRL = '@RestController class {n} {{\n @GetMapping("/{n}") X x() {{}}\n}}\n'


def app(d: pathlib.Path) -> str:
    files = {"src/main/java/a/A.java": JAVA.format(n="A"), "src/main/java/a/test/B.java": JAVA.format(n="B"), "src/test/java/a/C.java": JAVA.format(n="C"),
             "src/main/java/a/Ctl.java": CTRL.format(n="Ctl"), "src/test/java/a/FakeCtl.java": CTRL.format(n="FakeCtl"),
             "src/main/resources/application.yml": "db:\n  password: Zx9!qwLm27pa\n", "src/test/resources/application.yml": "db:\n  password: Kq8!rtYu31vb\n",
             "src/test/java/a/UsesLib.java": "import org.onlytest.Thing;\nclass UsesLib {}\n"}
    for k, v in files.items():
        (d / k).parent.mkdir(parents=True, exist_ok=True)
        (d / k).write_text(v, encoding="utf-8")
    fresh()
    return str(d.resolve())


def fresh():
    codeintel._CACHE.clear()
    endpoints._CACHE.clear()


def engines(tmp) -> None:
    root = app(tmp / "app")
    r = pipeline.scan(root)
    files = sorted(x["file"].rsplit("/", 1)[-1] for x in pipeline.last_findings(root))
    check("the engine is kept out of it, and only of it", files == ["A.java", "B.java"], files)
    check("how much was left out is told, and is no gap", r["coverage"]["tests"] == 3 and r["complete"], (r["coverage"], r["incomplete_reasons"]))
    s = hardcoded.scan(root)
    recs = projects.store.read(pathlib.Path(s["artifacts"]["findings_json"]), [])
    check("so are secrets, with the number of those left out", s["tests_skipped"] >= 1 and recs and not [x for x in recs if "src/test" in x["file"]], s)
    check("and endpoints", [e["file"].rsplit("/", 1)[-1] for e in endpoints.extract(root)] == ["Ctl.java"], endpoints.extract(root))
    check("and the places agents trace from, production packages called test included", sorted({x["file"].rsplit("/", 1)[-1] for x in codeintel.sink_sites(root)}) == ["A.java", "B.java"], codeintel.sink_sites(root))
    check("what only tests import is not used", not sca_triage._source_usage(root, ["org.onlytest"])["used"])
    rule = {"id": "x", "languages": ["java"], "severity": "WARNING", "message": "m", "pattern": "$S.executeQuery(...)"}
    check("rules agents run stay out of it too", sorted(pathlib.Path(f["file"]).name for f in airules.run_sast([rule], root)["findings"]) == ["A.java", "B.java"])
    f = {"title": "t", "cwe": "CWE-89", "severity": "high", "auth": "anonymous", "impact": "i",
         "chain": [{"role": "sink", "file": "src/test/java/a/C.java", "line": 3, "quote": 'return st.executeQuery("s" + r.getParameter("n"));'}]}
    good, why = audit._findings([f], root)
    check("an agent's finding in it goes back", not good and "测试代码" in why, why)
    check("in what ships, it does not", audit._findings([{**f, "chain": [{**f["chain"][0], "file": "src/main/java/a/test/B.java"}]}], root)[0])
    check("agents are told", "src/test" in agents.TESTS_NOTE)
    check("an engine given too many excludes is corrected", pipeline._ends({"file": str(pathlib.Path(root) / "src/test/java/a/C.java"), "trace": []}, root) == ["src/test/java/a/C.java"])

    p = projects.add(root)["project"]
    projects.edit(p["id"], {"tests": "1"})
    fresh()
    r = pipeline.scan(root)
    check("a project can have it audited", sorted(x["file"].rsplit("/", 1)[-1] for x in pipeline.last_findings(root)) == ["A.java", "B.java", "C.java"] and r["coverage"]["tests"] == 0)
    check("everywhere", len(endpoints.extract(root)) == 2 and "C.java" in {x["file"].rsplit("/", 1)[-1] for x in codeintel.sink_sites(root)} and hardcoded.scan(root)["tests_skipped"] == 0 and audit._findings([f], root)[0]
          and sca_triage._source_usage(root, ["org.onlytest"])["used"])
    projects.edit(p["id"], {"tests": ""})
    os.environ["SCAN_TESTS"] = "1"
    check("or all of them", not testcode.skipping(root))
    projects.edit(p["id"], {"tests": "0"})
    check("the project's choice goes before", testcode.skipping(root))
    os.environ.pop("SCAN_TESTS")

    only = tmp / "only" / "src" / "test"
    only.mkdir(parents=True)
    (only / "C.java").write_text(JAVA.format(n="C"), encoding="utf-8")
    r = pipeline.scan(str(tmp / "only"))
    check("nothing but test code is said so, not called clean", not r["ok"] and "测试代码" in r["error"], r)
    check("a file asked for by name is scanned", ledger.source_files(str(only / "C.java"), "java") and pipeline.scan(str(only / "C.java"))["raw_hits"] == 1)
    check("a project that lives under a test directory is a project", ledger.source_files(str(only), "java") != [])
    old = pipeline.checkpoint.Checkpoint(root, "sast", testcode.skipping(root)).key
    projects.edit(p["id"], {"tests": "1"})
    check("a stopped scan does not go on under another choice", pipeline.checkpoint.Checkpoint(root, "sast", testcode.skipping(root)).key != old)
    check("what is left out is found from the top", testcode.paths(str(tmp / "only")) == ["src/test"], testcode.paths(str(tmp / "only")))
    import web.server as server
    from fastapi.testclient import TestClient
    web = TestClient(server.app, base_url="http://127.0.0.1:8770", headers={"X-SD-Token": server.TOKEN})
    check("the console can set it", web.patch(f"/api/projects/{p['id']}", json={"tests": "0"}).json()["project"]["tests"] == "0" and server.config.allowed("SCAN_TESTS"), json.dumps(p))


def main() -> int:
    saved = dict(os.environ)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        for fn in (names, engines):
            print(f"-- {fn.__name__}")
            mine = pathlib.Path(d) / fn.__name__
            mine.mkdir()
            projects.STORE, pipeline.SCANS_DIR, rulegen.OUT_DIR = mine / "store", mine / "scans", mine / "rules"
            review.FILE, decisions.FILE = mine / "r.json", mine / "d.json"
            os.environ.pop("SCAN_TESTS", None)
            fn(mine)
    os.environ.clear()
    os.environ.update(saved)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
