"""A failed, partial or suppressed audit must never look like a clean one.

Offline: NVD and EPSS are stubbed. Opengrep and Kùzu are real; a missing engine
fails this suite instead of skipping it.
"""

import csv
import json
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
__import__("os").environ["SCA_OSV"] = "0"  # offline

import _env  # noqa: F401
from core import decisions, epss, graph, nvd, pipeline, review, sca, sca_triage, toolset
from core.engines import opengrep, tabby

FAILED: list[str] = []
REAL_RUN = opengrep.run_scan


def check(name: str, ok: bool, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        FAILED.append(name)


JAVA = """import java.sql.*;import javax.servlet.http.*;
class C {
  void a(HttpServletRequest r, Statement st) throws Exception {
    String q = "s" + r.getParameter("x");
    st.executeQuery(q);%s
  }
  void b(HttpServletRequest r, Statement st) throws Exception {
    String q = "t" + r.getParameter("y");
    st.executeQuery(q);
  }
}
"""


def put(d: pathlib.Path, files: dict[str, str]) -> str:
    for name, body in files.items():
        p = d / name
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(body, encoding="utf-8")
    return str(d)


def stub_engine(**over):
    base = {"engine": "opengrep", "ok": True, "error": None, "findings": [], "total": 0,
            "errors": [], "error_items": [], "scanned": [], "unsupported_flags": []}
    opengrep.run_scan = lambda *a, **k: {**base, **over}


def engine_failures(tmp: pathlib.Path) -> None:
    src = put(tmp / "eng", {"C.java": JAVA % ""})
    stub_engine(ok=False, error="opengrep 执行失败（exit=2）", errors=["OOM"])
    r = pipeline.scan(src)
    check("engine failure without findings is ok=False", r["ok"] is False, r)

    hit = {"rule_id": "java-sqli-jdbc-statement", "message": "m", "line": 5, "trace": [],
           "file": src + "/C.java", "trace_complete": False}
    stub_engine(ok=False, error="exit=2", findings=[hit], total=1, scanned=[src + "/C.java"])
    r = pipeline.scan(src)
    check("engine failure with findings keeps them, marked incomplete",
          r["ok"] and r["reportable"] == 1 and r["complete"] is False, r)
    md = pathlib.Path(r["artifacts"]["markdown"]).read_text(encoding="utf-8")
    sarif = json.loads(pathlib.Path(r["artifacts"]["sarif"]).read_text(encoding="utf-8"))
    check("markdown says the scan is incomplete", "不完整" in md, md[:200])
    check("SARIF invocation is not successful",
          sarif["runs"][0]["invocations"][0]["executionSuccessful"] is False)
    opengrep.run_scan = REAL_RUN

    bad = tmp / "bad.yaml"
    bad.write_text("rules:\n - id: x\n   languages: [javva]\n   severity: ERROR\n"
                   "   message: m\n   pattern: foo\n", encoding="utf-8")
    r = opengrep.run_scan(src, rules=str(bad))
    check("real engine: a broken rule is a failed run", r["ok"] is False and r["error"], r)
    r = opengrep.run_scan(src, rules=pipeline.rules_for("java"), timeout_s=0.001)
    check("real engine: timeout is a failed run", r["ok"] is False and "超时" in r["error"], r)


def coverage(tmp: pathlib.Path) -> None:
    src = put(tmp / "cov", {"C.java": JAVA % "", "Broken.java": "class B { void a( { {{{",
                            "K.kt": "class K", "vendor/V.java": JAVA % ""})
    r = pipeline.scan(src, "java")
    doc = json.loads(pathlib.Path(r["artifacts"]["ledger_json"]).read_text(encoding="utf-8"))
    st = {}
    for u in doc["units"]:
        st.setdefault(u["surface"], set()).add(u["status"])
    check("parse failure is blocked", st["Broken.java"] == {"blocked"}, st)
    check("file no rule covers is skipped", st["K.kt"] == {"skipped"}, st)
    check("vendor code is scanned", "candidate" in st["vendor/V.java"], st)
    check("gaps make the scan incomplete", r["complete"] is False and len(r["incomplete_reasons"]) == 2,
          r["incomplete_reasons"])
    clean = pipeline.scan(put(tmp / "clean", {"A.java": "class A {}"}), "java")
    check("a fully scanned tree is complete", clean["complete"] is True, clean["incomplete_reasons"])
    one = pipeline.scan(str(pathlib.Path(src) / "C.java"))
    check("single file target is audited by name",
          one["ok"] and one["coverage"]["files"] == 1 and one["top"][0]["file"] == "C.java", one)


def self_silencing(tmp: pathlib.Path) -> None:
    r = pipeline.scan(put(tmp / "nosem", {"C.java": JAVA % " // nosem"}), "java")
    check("nosem comment does not hide a finding", r["raw_hits"] == 2, r["raw_hits"])
    r = pipeline.scan(put(tmp / "ign", {"C.java": JAVA % "", ".semgrepignore": "*.java\n",
                                        ".gitignore": "*.java\n"}), "java")
    check(".semgrepignore / .gitignore do not hide files", r["raw_hits"] == 2, r["raw_hits"])


def suppression(tmp: pathlib.Path) -> None:
    p1, p2 = (put(tmp / n, {"C.java": JAVA % ""}) for n in ("p1", "p2"))
    base = pipeline.scan(p1, "java")
    prints = {f["fingerprint"] for f in base["top"]}
    check("two sinks in one file have distinct fingerprints", len(prints) == 2, prints)

    real, ready = review.one, review.ready
    review.ready = lambda: (True, "")
    review.one = lambda rec, root: {"verdict": "refute", "reason": "r", "evidence": [], "backend": "x", "model": "x"}
    r = pipeline.scan(p1, "java", verify=True)
    check("a refute lowers a finding, it never removes it",
          r["reportable"] == 2 and r["status_counts"]["needs_review"] == 2, r["status_counts"])
    review.FILE.unlink()
    check("and only as long as the review stands", pipeline.scan(p1, "java")["status_counts"]["confirmed"] == 2)

    decisions.put(base["top"][0]["suppress_key"], "false_positive", "checked")
    again = pipeline.scan(p1, "java")
    check("only the rejected finding is suppressed",
          again["reportable"] == 1 and again["previously_rejected"] == 1, again["reportable"])
    recs = json.loads(pathlib.Path(again["artifacts"]["findings_json"]).read_text(encoding="utf-8"))
    check("suppressed finding stays on disk as rejected",
          sorted(x["status"] for x in recs) == ["confirmed", "rejected"], recs)
    check("suppression is counted", again["status_counts"]["rejected"] == 1, again["status_counts"])
    check("another project is untouched", pipeline.scan(p2, "java")["reportable"] == 2)
    put(tmp / "p1", {"C.java": JAVA % "" + "// edited below every trace line\n"})
    check("editing the file lifts the suppression", pipeline.scan(p1, "java")["reportable"] == 2)
    review.one = lambda rec, root: {"verdict": "unavailable", "reason": "no key"}
    r = pipeline.scan(p2, "java", verify=True)
    check("a review that did not happen changes nothing and is a gap",
          r["status_counts"]["confirmed"] == 2 and r["complete"] is False, r["incomplete_reasons"])
    review.ready = lambda: (False, "没有配置模型")
    r = pipeline.scan(p2, "java", verify=True)
    check("no reviewer is a gap, not a pass", r["verification"]["unavailable"] == 2 and r["complete"] is False, r["verification"])
    review.one, review.ready = real, ready


def languages(tmp: pathlib.Path) -> None:
    r = pipeline.scan(str(ROOT / "demo" / "python"))
    check("auto picks python", r["language"] == "python" and r["raw_hits"] > 0, r)
    r = pipeline.scan(str(ROOT / "demo" / "python"), "java")
    check("no source in the chosen language is an error", r["ok"] is False and "python" in r["error"], r)
    r = pipeline.scan(put(tmp / "mix", {"a.py": "x=1", "b.py": "y=1", "C.java": JAVA % ""}))
    check("auto covers every language present",
          r["language"] == "python+java" and r["raw_hits"] == 2 and r["coverage"]["files"] == 3
          and r["complete"], r)
    r = toolset.auto_scan(str(ROOT / "demo" / "go"))
    check("auto_scan defaults to the project's language", r.get("language") == "go" and r["raw_hits"] > 0, r)


def call_graph(tmp: pathlib.Path) -> None:
    out = tmp / "tw" / "output" / "dev"
    out.mkdir(parents=True)

    def w(key, cols, rows):
        with (out / f"GRAPHDB_PUBLIC_{key}.csv").open("w", newline="", encoding="utf-8") as fh:
            cw = csv.writer(fh)
            cw.writerow(cols)
            cw.writerows(rows)
    m = lambda i, cls, name, sink="FALSE", vul="": [i, name, cls, "", vul, sink, "FALSE"]
    cols = ["ID", "NAME", "CLASSNAME", "SIGNATURE", "VUL", "IS_SINK", "IS_SERIALIZABLE"]
    w("METHODS", cols, [m("e", "app.E", "readObject"), m("i", "app.Iface", "run"),
                        m("x", "app.Impl", "run"), m("s", "java.lang.Runtime", "exec", "TRUE", "EXEC"),
                        m("s2", "java.lang.reflect.Method", "invoke", "TRUE", "CODE"),
                        m("j", "java.util.X", "readObject")])
    w("CLASSES", ["ID", "NAME", "IS_SERIALIZABLE", "SUPER_CLASS"], [["c", "app.E", "TRUE", ""]])
    w("CALL", ["SOURCE", "TARGET", "LINE_NUM"], [["e", "i", "1"], ["x", "s", "2"], ["x", "s2", "3"], ["j", "s", "9"]])
    w("ALIAS", ["ID", "SOURCE", "TARGET"], [["a", "i", "x"]])
    g = tabby.load_graph(str(out), str(tmp / "g.db"))
    found = tabby.find_gadget_chains(g["conn"], limit=30)
    check("chain through an interface is found", found["total"] == 3, found)
    check("trace shows the override", any("app.Impl.run" in s["text"] for s in found["chains"][0]["trace"]))
    cut = tabby.find_gadget_chains(g["conn"], limit=1)
    check("truncation is reported", cut["truncated"] and cut["total"] == 3 and len(cut["chains"]) == 1, cut)
    check("depth in code matches the template",
          f"1..{tabby.MAX_DEPTH}]" in (tabby.TEMPLATES / "gadget-chain.cypher").read_text(encoding="utf-8"))
    graph.close(g["conn"])

    # whole path, with the build stubbed out
    fake = tmp / "app.jar"
    fake.write_bytes(b"PK")
    saved = tabby.available, tabby.prepare_workspace, tabby.submit_build
    from core import jobs
    saved_wait = jobs.wait
    tabby.available = lambda: True
    tabby.prepare_workspace = lambda *a, **k: None
    tabby.submit_build = lambda *a, **k: {"job_id": "x"}
    # first case: leftover CSVs are usable, so only the job state gives it away
    import shutil
    csvs = tmp / "csvs"
    shutil.copytree(out, csvs)
    builds = []

    def build(work, heap=""):
        builds.append(work)
        shutil.copytree(csvs if "empty" not in work else tmp / "blank", pathlib.Path(work) / "output" / "dev")
        return {"job_id": "0" * 8}
    (tmp / "blank").mkdir()
    for f in csvs.iterdir():
        (tmp / "blank" / f.name).write_text(f.read_text(encoding="utf-8").splitlines()[0] + "\n", encoding="utf-8")
    tabby.submit_build = build
    run = lambda work, **k: pipeline.tabby_audit(str(fake), workdir=str(tmp / work), **k)
    for label, state, work in (
            ("lost build job is a failure", {"state": "lost", "exit": None}, "w1"),
            ("empty graph is a failure", {"state": "done", "exit": "0"}, "empty")):
        jobs.wait = lambda *a, _s=state, **k: _s
        r = run(work)
        check(label, r["ok"] is False, r)

    jobs.wait = lambda *a, **k: {"state": "running", "exit": None}
    builds.clear()
    check("a slow build is pending", run("w2").get("pending") and run("w2").get("pending"))
    check("a pending build is joined, not started twice", len(builds) == 1, builds)
    jobs.wait = lambda *a, **k: {"state": "done", "exit": "1", "tail": ["boom"]}
    r = run("w2")
    check("a build that failed after the wait is reported", r["ok"] is False and r["tail"] == ["boom"], r)
    jobs.wait = lambda *a, **k: {"state": "done", "exit": "0"}
    r = run("w2")
    check("then it is built again", r["ok"] and len(builds) == 2 and r["chains_total"] == 3, r)
    check("a finished build is reused", run("w2")["ok"] and len(builds) == 2)
    check("project chains come before library chains", r["top"][0]["severity"] == "high", r["top"][0])

    a, b = tmp / "a" / "x.jar", tmp / "b" / "x.jar"
    for f, data in ((a, b"one"), (b, b"two")):
        f.parent.mkdir()
        f.write_bytes(data)
    check("same name, other content: other build", tabby.content_key(str(a)) != tabby.content_key(str(b)))
    tabby.available, tabby.prepare_workspace, tabby.submit_build = saved
    rules = tmp / "rules"
    rules.mkdir()
    (rules / "sinks.json").write_text("{}")
    (rules / "ignores.json").write_text('["md5"]')
    tabby.prepare_workspace(str(tmp / "ws"), str(fake), rules_dir=str(rules))
    text = (tmp / "ws" / "config" / "settings.properties").read_text(encoding="utf-8")
    check("a build never sees which jars were analysed before",
          (tmp / "ws" / "rules" / "sinks.json").exists() and not (tmp / "ws" / "rules" / "ignores.json").exists()
          and "ws/rules" in text and "isNeedToCreateIgnoreList      = false" in text, text)
    jobs.wait = saved_wait


def cve(n, product="lib", **cm):
    return {"cve": {"id": f"CVE-2020-{n:05d}", "metrics": {}, "configurations": [{"nodes": [{"cpeMatch": [
        {"vulnerable": True, "criteria": f"cpe:2.3:a:acme:{product}:*:*:*:*:*:*:*:*", **cm}]}]}]}}


def dependencies(tmp: pathlib.Path) -> None:
    nvd.CACHE_DIR = tmp / "nvd"
    nvd.CACHE_DIR.mkdir()
    epss.CACHE = tmp / "epss"
    real_get, real_req = nvd._get, epss.net.request_json
    vendors = ["acme"]
    products = {"lib", "jackson-databind"}
    total, fail, asked = 4500, set(), []

    def fake_get(params, attempts=3, base=None):
        if base == nvd.CPE_BASE:
            prod = params["cpeMatchString"].split(":")[4]
            asked.append(prod)
            hits = vendors if prod in products else []
            return {"totalResults": len(hits),
                    "products": [{"cpe": {"cpeName": f"cpe:2.3:a:{v}:{prod}:1.0"}} for v in hits]}
        vendor, prod = params["virtualMatchString"].split(":")[3:5]
        if vendor in fail:
            raise RuntimeError("429")
        s = params["startIndex"]
        return {"totalResults": total, "vulnerabilities":
                [cve(i, prod, versionEndExcluding="2.0") for i in range(s, min(s + params["resultsPerPage"], total))]}
    nvd._get = fake_get

    r = nvd.lookup("lib", "1.0")
    check("every NVD page is read", len(r["affected"]) == 4500, len(r["affected"]))
    check("second lookup is served from cache", nvd.lookup("lib", "1.0").get("cached"))
    total = 3
    check("hyphenated CPE products are found", len(nvd.lookup("jackson-databind", "1.0")["affected"]) == 3)
    nvd.lookup("log4j-core", "2.14.1")
    check("log4j-core is asked as log4j", "log4j" in asked, asked)
    check("a Go module is asked by its name", nvd._cpe_products("github.com/gin-gonic/gin/v2") == ["gin"])

    vendors[:], fail = ["acme", "down"], {"down"}
    nvd.lookup("lib", "1.1")
    r = nvd.lookup("lib", "1.1")
    check("a partial answer says so and is not cached", r["ok"] and r.get("error") and not r.get("cached"), r)
    vendors[:] = [f"v{i}" for i in range(6)] + ["acme"]
    fail = set()
    r = nvd.lookup("lib", "1.2", group="org.acme.lib")
    check("the group's vendor is queried first, dropped vendors are reported",
          len(r["affected"]) == 3 and "vendor" in r["error"], r)
    check("long keys do not share a cache file",
          nvd._cache_path("v4:" + "x" * 90 + "@1") != nvd._cache_path("v4:" + "x" * 90 + "@2"))
    check("CVSS v4-only CVE has a score", nvd._score(
        {"metrics": {"cvssMetricV40": [{"cvssData": {"baseScore": 9.3}}]}}) == 9.3)

    vendors[:] = ["acme"]
    comps = lambda items: lambda root: {"ok": True, "source": "opensca", "components": [
        {"vendor": g, "name": n, "version": v} for g, n, v in items]}
    real_comps = sca.components
    sca.components = comps([("", "nosuch", "1.0"), ("", "lib", ""), ("", "lib", "${v}"), ("a", "lib", "1.0")])
    e = sca.enrich(str(tmp))
    check("unknown product and missing version are unresolved",
          len(e["unresolved"]) == 3 and e["complete"] is False, e["unresolved"])
    epss.net.request_json = lambda *a, **k: (_ for _ in ()).throw(OSError("down"))
    t = sca_triage.triage(e, app_root=str(tmp))
    check("triage carries the gaps", t["complete"] is False and t["stats"]["unresolved"] == 3, t["stats"])
    check("failed EPSS is not cached", not list(epss.CACHE.glob("*.json")))

    (tmp / "App.java").write_text("import java.util.List;\nclass App {}\n", encoding="utf-8")
    row = lambda score: {"ok": True, "components": [{"name": "some-lib", "version": "1", "vendor": "com.example",
                         "cves": [{"id": "CVE-X", "score": score, "matched_version": True}]}]}
    epss.net.request_json = lambda *a, **k: {"data": []}
    check("unknown CVSS is kept", len(sca_triage.triage(row(None), app_root=str(tmp))["kept"]) == 1)
    check("known low CVSS is still ignored", len(sca_triage.triage(row(5.0), app_root=str(tmp))["ignored"]) == 1)

    sca.components = comps([("", "lib", f"1.{i}") for i in range(5)])
    first = sca.enrich(str(tmp), max_lookups=2)
    sca.enrich(str(tmp), max_lookups=2)
    third = sca.enrich(str(tmp), max_lookups=2)
    check("lookup cap is a gap and reruns make progress",
          first["complete"] is False and third["complete"] is True, (first["skipped"], third["skipped"]))
    sca.components = real_comps

    root_only = {"ok": True, "components": [{"name": "app", "version": "1", "vendor": "", "root": True}]}
    real_osca, sca.run_opensca = sca.run_opensca, lambda *a, **k: root_only
    c = sca.components(str(ROOT / "demo" / "spring-proj"))
    check("project-only OpenSCA result falls back to the build file",
          c["source"] in ("builtin", "maven") and len(c["components"]) >= 2, c)
    sca.run_opensca = real_osca
    nvd._get, epss.net.request_json = real_get, real_req


def main() -> int:
    if not opengrep.capabilities().get("available"):
        print("FAIL: opengrep 不可用，本套件不允许跳过")
        return 1
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        pipeline.SCANS_DIR = tmp / "scans"
        decisions.FILE, review.FILE = tmp / "decisions.json", tmp / "reviews.json"
        toolset.rulegen.OUT_DIR = tmp / "rules"
        for fn in (engine_failures, coverage, self_silencing, suppression, languages,
                   call_graph, dependencies):
            print(f"-- {fn.__name__}")
            fn(tmp)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
