"""What the engines could not do is done by something else: another source, or an agent.

Offline: OSV, NVD and OpenSCA are stand-ins; agents' answers are given to the checkers.
"""

import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import _env  # noqa: F401
from core import agent_tool, airules, audit, codeintel, config, decisions, endpoints, epss, gaps, net, nvd, osv, pipeline, projects, review, rulegen, sca, toolset

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:500]}"))
    if not ok:
        FAILED.append(name)


def put(d: pathlib.Path, files: dict) -> str:
    for k, v in files.items():
        (d / k).parent.mkdir(parents=True, exist_ok=True)
        (d / k).write_text(v, encoding="utf-8")
    codeintel._CACHE.clear()
    endpoints._CACHE.clear()
    return str(d.resolve())


def comp(name, version, vendor="g", language="Java", **k):
    return {"vendor": vendor, "name": name, "version": version, "language": language, "direct": True, "paths": [], **k}


VULNS = {"GHSA-1": {"id": "GHSA-1", "aliases": ["CVE-2020-0001"], "summary": "bad", "severity": [{"type": "CVSS_V3", "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
                    "database_specific": {"cwe_ids": ["CWE-502"]}, "affected": [{"package": {"name": "g:lib"}, "ranges": [{"events": [{"introduced": "0"}, {"fixed": "2.0"}]}]}]},
         "GHSA-2": {"id": "GHSA-2", "aliases": [], "summary": "no alias", "database_specific": {"severity": "HIGH"}, "affected": []},
         "GHSA-3": {"id": "GHSA-3", "aliases": ["CVE-2020-0003"], "withdrawn": "2021", "affected": []}}


def databases(tmp) -> None:
    for vector, want in (("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8), ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L", 5.3), ("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1),
                         ("CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:N/I:N/A:N", 0.0), ("CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H", 9.9)):
        check(f"base score {want}", osv.base_score(vector) == want, osv.base_score(vector))
    check("a broken vector has no score", osv.base_score("CVSS:3.1/AV:X") is None)
    co = lambda *a, **k: (osv.coordinate(comp(*a, **k)) or {}).get("package", {}).get("name")
    check("coordinates per ecosystem", co("lib", "1") == "g:lib" and co("My_Pkg.x", "1", "", "Python") == "my-pkg-x" and co("@a/b", "1", "", "JavaScript") == "@a/b"
          and co("github.com/x/y", "v1.2", "", "Go") == "github.com/x/y" and osv.coordinate(comp("github.com/x/y", "v1.2", "", "Go"))["version"] == "1.2")
    check("no guessing without a group or a known ecosystem", co("lib", "1", "") is None and co("lib", "1", "g", "") is None)

    osv.CACHE = tmp / "osv"
    real = net.post_json, net.request_json
    sent = []

    def post(url, payload, **k):
        sent.append(payload)
        if "querybatch" in url:
            return {"results": [{"vulns": [{"id": i} for i in {"g:lib": ["GHSA-1", "GHSA-2", "GHSA-3"], "g:paged": ["GHSA-1"], "g:gone": ["GHSA-404"]}.get(q["package"]["name"], [])],
                                 **({"next_page_token": "t"} if q["package"]["name"] == "g:paged" else {})} for q in payload["queries"]]}
        return {"vulns": [{"id": "GHSA-2"}]}

    def get(url, **k):
        return VULNS[url.rsplit("/", 1)[1]]
    net.post_json, net.request_json = post, get
    got, err = osv.query([comp("lib", "1.0"), comp("clean", "1.0"), comp("paged", "1.0"), comp("gone", "1.0"), comp("x", "1.0", "", "Java")])
    ids = {k[1]: [r["id"] for r in v] for k, v in got.items()}
    check("answers by coordinate, CVE names first", sorted(ids["lib"]) == ["CVE-2020-0001", "GHSA-2"], ids)
    check("withdrawn entries are not vulnerabilities", "CVE-2020-0003" not in ids["lib"])
    check("nothing known is an answer, not a gap", ids["clean"] == [])
    check("every page is read", "GHSA-2" in ids["paged"])
    check("a vulnerability that cannot be described is not an answer", "gone" not in ids and "详情" in err, (ids, err))
    row = next(r for r in got[("g", "lib", "1.0")] if r["id"] == "CVE-2020-0001")
    check("score, weakness and range come along", row["score"] == 9.8 and row["cwes"] == ["CWE-502"] and row["cpes"][0]["end"] == "2.0", row)
    check("a label stands in for a missing vector", next(r for r in got[("g", "lib", "1.0")] if r["id"] == "GHSA-2")["score"] == 7.0)
    check("only names and versions are sent", {k for p in sent for q in p.get("queries", []) for k in q} == {"package", "version"}, sent[:1])
    check("details are kept for the agent", "bad" in osv.known("CVE-2020-0001") and "GHSA-1" in agent_tool.sd_advisory(str(tmp), "CVE-2020-0001").replace("\n", " "))

    asked = []
    keep = nvd.lookup, sca.run_opensca, epss.scores
    nvd.lookup = lambda k, v=None, group="": (asked.append(k), {"ok": False, "error": f"CPE 字典中找不到产品: {k}"})[-1]
    sca.run_opensca = lambda root, timeout_s=0: {"ok": True, "components": [comp("lib", "1.0"), comp("clean", "1.0"), comp("noversion", "${x}"), comp("nolang", "1.0", "", ""), comp("late", "1.0", "", "")]}
    epss.scores = lambda ids: {}
    root = put(tmp / "app", {"pom.xml": "<project></project>"})
    config_off, os.environ["SCA_OSV"] = os.environ.get("SCA_OSV"), "1"
    r = sca.enrich(root, max_lookups=1)
    un = {u["name"]: u["reason"] for u in r["unresolved"]}
    check("what OSV answered is settled, even when NVD knows no such name or the cap is reached", not {"lib", "clean"} & set(un) and r["osv"]["answered"] == 2, un)
    check("what neither answered is not", set(un) == {"noversion", "nolang", "late"}, un)
    check("the CVEs are there", {c["id"] for x in r["components"] if x["name"] == "lib" for c in x["cves"]} == {"CVE-2020-0001", "GHSA-2"})
    nvd.lookup = lambda k, v=None, group="": (asked.append(k), {"ok": True, "cached": True, "affected": [{"id": "CVE-2020-0001", "score": 5.0}, {"id": "CVE-2020-0009", "score": 5.0}]})[-1]
    asked.clear()
    sca.enrich(root, max_lookups=9)
    check("NVD, slow, is asked only what OSV did not answer", "lib" not in asked and "nolang" in asked, asked)
    known, nvd.cached = nvd.cached, lambda *a: True
    r = sca.enrich(root, max_lookups=9)
    nvd.cached = known
    check("both databases are used, one row per CVE", sorted(c["id"] for x in r["components"] if x["name"] == "lib" for c in x["cves"]) == ["CVE-2020-0001", "CVE-2020-0009", "GHSA-2"])

    def down(*a, **k):
        raise OSError("down")
    net.post_json = down
    nvd.lookup = lambda k, v=None, group="": {"ok": False, "error": "x"}
    r = sca.enrich(root, max_lookups=9)
    check("OSV down is a gap with its reason", "lib" in {u["name"] for u in r["unresolved"]} and any("OSV" in g for g in r["incomplete_reasons"]), r["incomplete_reasons"])
    os.environ["SCA_OSV"] = "0"
    sent.clear()
    net.post_json = post
    sca.enrich(root, max_lookups=1)
    check("it can be turned off", not sent)
    os.environ["SCA_OSV"] = config_off or "0"
    net.post_json, net.request_json = real
    nvd.lookup, sca.run_opensca, epss.scores = keep


EV = lambda f, n, q: [{"file": f, "line": n, "quote": q}]
FIND = {"title": "SQL 注入", "cwe": "CWE-89", "severity": "high", "auth": "anonymous", "impact": "读库", "conditions": "", "fix": "",
        "chain": [{"role": "entry", "file": "a/C.java", "line": 2, "quote": "void f(@RequestParam String q)"}, {"role": "sink", "file": "a/C.java", "line": 3, "quote": "jdbcTemplate.query(q);"}]}


def agents_fill_in(tmp) -> None:
    root = put(tmp / "app", {"a/C.java": "class C {\n  void f(@RequestParam String q) {\n    jdbcTemplate.query(q);\n  }\n}\n", "a/Broken.java": "class B { void g() { x( } }\n",
                             "pom.xml": "<project>\n<properties><lib.version>1.2.3</lib.version></properties>\n<dependency><artifactId>t</artifactId><scope>test</scope></dependency>\n</project>\n", "lib/versions.txt": "core-1.4.jar\n"})
    led = tmp / "ledger.json"
    led.write_text(json.dumps({"files_unscanned": ["a/Broken.java"], "files_failed": {}}), encoding="utf-8")
    old = "引擎告警：SemgrepWarning:\n rule x.java-xxe: the interfile search stopped at depth 3 with calls beyond it"
    projects.save_artifact(root, "sast", {"ok": True, "complete": False, "artifacts": {"ledger_json": str(led)},
                                          "incomplete_reasons": [old, old.replace("xxe", "ssrf"), "1 个源文件引擎未扫描，如 a/Broken.java", "引擎告警：something odd happened"]})
    deps = [{"vendor": "g", "name": n, "version": v, "reason": why} for n, v, why in (("lib", "${lib.version}", "版本未解析，无法判断是否受影响"), ("t", "1.0", "NVD 查询失败：CPE 字典中找不到产品"),
                                                                                      ("odd", "2.0", "NVD 查询失败：CPE 字典中找不到产品"), ("gone", "3.0", "NVD 查询失败：CPE 字典中找不到产品"))]
    projects.save_artifact(root, "triage", {"ok": True, "complete": False, "unresolved": deps, "kept": [], "ignored": [], "incomplete_reasons": ["4 个依赖没有查到结论（不等于没有漏洞），如 lib", "间接依赖未解析，只读了构建文件：OpenSCA 超时"]})
    kinds = [(g["engine"], g["type"], len(g["texts"])) for g in gaps.found(root)]
    check("every reason is something to cover", kinds == [("sast", "depth", 2), ("sast", "files", 1), ("sast", "alert", 1), ("triage", "deps", 1), ("triage", "alert", 1)], kinds)
    todo = [u for u in audit.plan(root) if u["kind"] == "gap"]
    check("and has work for it", sorted(u["gap"]["type"] for u in todo) == ["alert", "alert", "deps", "files"], [u["title"] for u in todo])
    audit.refresh(root)
    st = {(g["kind"], g["type"]): g for g in audit.load(root)["engine_gaps"]}
    check("nothing is closed before it is done", not any(g["closed"] for g in st.values()), st)
    check("the depth limit is covered by tracing from sinks", st[("sast", "depth")]["total"] == sum(u["kind"] in ("sink", "chain") for u in audit.plan(root)) > 0 and st[("sast", "depth")]["more"] == 1)

    unit = lambda t, e="": next(u for u in todo if u["gap"]["type"] == t and (not e or u["gap"]["engine"] == e))
    ask = lambda u, ans: audit.task(audit.spec(u, root, audit.load(root))).validate(ans)
    d = unit("deps")
    ids = {x["name"]: f"D{i}" for i, x in enumerate(d["gap"]["items"], 1)}
    item = lambda n, v, **k: {"id": ids[n], "verdict": v, "reason": "查了 pom", **k}
    good = [item("lib", "version", version="1.2.3", evidence=EV("pom.xml", 2, "<lib.version>1.2.3</lib.version>")), item("t", "not_shipped", evidence=EV("pom.xml", 3, "<scope>test</scope>")),
            item("odd", "alias", product="Real_Product"), item("gone", "unknown")]
    say = lambda *rows: ask(d, {"items": list(rows)})[1]
    check("every dependency needs an answer", "还没有结论" in say(*good[:3]))
    check("a version must be written where it is cited", "那一行" in say({**good[0], "version": "9.9"}, *good[1:]) and "具体版本" in say({**good[0], "version": "${x}"}, *good[1:]))
    check("not shipped needs evidence, an alias a product", "evidence" in say(good[0], {**good[1], "evidence": []}, *good[2:]) and "product" in say(*good[:2], {**good[2], "product": ""}, good[3]))
    value, why = ask(d, {"items": good})
    check("a full answer is accepted", value and not why, why)
    note = audit.take(d, value, root, audit.load(root))["note"]
    check("it is filed", "查到版本 1" in note and "不进制品 1" in note, note)

    keep = nvd.lookup, sca.run_opensca, epss.scores
    asked = []
    nvd.lookup = lambda k, v=None, group="": (asked.append((k, v)), {"ok": True, "cached": True, "affected": [{"id": "CVE-2021-1", "score": 9.0, "cwes": [], "summary": "", "cpes": [], "matched_version": True}]}
                                              if k in ("lib", "real_product") else {"ok": False, "error": "CPE 字典中找不到产品"})[-1]
    sca.run_opensca = lambda root, timeout_s=0: {"ok": True, "components": [comp(x["name"], x["version"]) for x in deps]}
    epss.scores = lambda ids: {}
    f = unit("files")
    full = {"files": [{"file": "a/Broken.java", "verdict": "covered", "note": "只有一个没有输入的方法"}], "findings": []}
    check("every unread file needs an answer that says something", "还没有结论" in ask(f, {"files": [], "findings": []})[1] and "note" in ask(f, {"files": [{**full["files"][0], "note": "ok"}], "findings": []})[1])
    check("a finding in one has to be one", "对不上" in ask(f, {"files": [{**full["files"][0], "verdict": "finding"}], "findings": []})[1])
    a, b = unit("alert", "sast"), unit("alert", "triage")
    check("an alert needs what was checked, and where", "checked" in ask(a, {"verdict": "covered", "checked": "ok", "findings": []})[1] and "paths" in ask(a, {"verdict": "covered", "checked": "x" * 30, "paths": ["nope"], "findings": []})[1])
    check("components need a cited version", "components[0]" in ask(b, {"verdict": "covered", "checked": "x" * 30, "paths": ["lib"], "findings": [], "components": [{"name": "core", "version": "9.9", "evidence": EV("lib/versions.txt", 1, "core-1.4.jar")}]})[1])
    answers = {f["id"]: full, a["id"]: {"verdict": "covered", "checked": "逐个核对了告警涉及的规则与文件，没有遗漏", "paths": ["a"], "findings": [FIND]},
               b["id"]: {"verdict": "covered", "checked": "读了 lib 目录里的全部 jar 清单，补出组件", "paths": ["lib"], "findings": [], "components": [{"group": "g", "name": "core", "version": "1.4", "evidence": EV("lib/versions.txt", 1, "core-1.4.jar")}]}}
    one, review.one = review.one, lambda *x, **k: {"verdict": "uphold", "reason": "r", "evidence": [], "usage": {"in": 0, "out": 0}}
    for u in (f, a, b):
        v, why = ask(u, answers[u["id"]])
        check(f"{u['gap']['engine']} {u['gap']['type']} accepted", v and not why, why)
        audit.take(u, v, root, audit.load(root))
    review.one = one
    for u in todo:
        audit._update(root, lambda x: x["units"].update({u["id"]: {"id": u["id"], "kind": "gap", "title": u["title"], "items": u["items"], "state": "done", "usage": {}}}))
    check("what a gap hid is a finding like any other", [x["rule_id"] for x in audit.findings(root)] == ["agent-gap"] and audit.findings(root)[0]["status"] == "confirmed", audit.findings(root))
    audit._apply_gaps({"title": "x", "fresh": [u for u in audit.load(root)["units"].values() if u["kind"] == "gap"]}, root)
    tri = projects.load_artifact(root, "triage")
    un = {u["name"]: u for u in tri["unresolved"]}
    check("the version an agent found is looked up", ("lib", "1.2.3") in asked and any(k["dependency"] == "lib" and k["version"] == "1.2.3" for k in tri["kept"]), (asked, tri["kept"]))
    check("so is the product name, and the component from lib/", ("real_product", "2.0") in asked and ("core", "1.4") in asked, asked)
    check("what does not ship is settled, with the reason", "t" not in un and any(x["name"] == "t" and "不进运行制品" in x["reason"] for x in tri["sca"]["explained"]), tri["sca"])
    check("what nobody knows stays open, and is not asked again", un["gone"]["asked"] and "agent 也没有查清" in un["gone"]["reason"] and all(x["name"] != "gone" for u in audit.plan(root) if u["kind"] == "gap" and u["gap"]["type"] == "deps" for x in u["gap"]["items"]), un)
    audit.refresh(root)
    st = {(g["kind"], g["type"]): g for g in audit.load(root)["engine_gaps"]}
    check("gaps that were filled are closed", st[("sast", "files")]["closed"] and st[("sast", "alert")]["closed"], st)
    check("one that is still open says so", not st[("triage", "deps")]["closed"] and st[("triage", "deps")]["left"] >= 1, st[("triage", "deps")])
    check("the depth limit stays open until its tracing is done", not st[("sast", "depth")]["closed"])
    for u in audit.plan(root):
        if u["kind"] in ("sink", "chain"):
            audit._update(root, lambda x: x["units"].update({u["id"]: {"id": u["id"], "kind": u["kind"], "title": u["title"], "items": [], "state": "done", "usage": {}}}))
    audit.refresh(root)
    check("and closes with it", all(g["closed"] for g in audit.load(root)["engine_gaps"] if g["kind"] == "sast"))
    art = projects.load_artifact(root, "sast")
    check("a closed gap is no reason any more", audit.uncovered(root, "sast", art["incomplete_reasons"]) == [] and len(art["incomplete_reasons"]) == 4)
    projects.add(root)
    runs = projects.list_all()["projects"][0]["runs"]
    check("the project list follows", runs["sast"]["summary"]["complete"] is True and runs["sast"]["summary"]["by_agent"] == 3 and runs["triage"]["summary"]["complete"] is False, runs["sast"]["summary"])
    projects.save_artifact(root, "sast", {**art, "incomplete_reasons": ["引擎告警：a new one"]})
    audit.refresh(root)
    check("a new run has new gaps", projects.list_all()["projects"][0]["runs"]["sast"]["summary"].get("by_agent", 0) == 0 and not any(g["closed"] for g in audit.load(root)["engine_gaps"] if g["kind"] == "sast"))

    import web.server as server
    from fastapi.testclient import TestClient
    web = TestClient(server.app, base_url="http://127.0.0.1:8770", headers={"X-SD-Token": server.TOKEN})
    pid = projects.project_id(root)
    audit._update(root, lambda x: x.update(engine_gaps=[]))
    body = web.get(f"/api/projects/{pid}/artifact/sast").json()
    check("the page is told who covers what, for old runs too", [g["type"] for g in body["covered"]] == ["alert"] and body["covered"][0]["total"] == 1, body.get("covered"))
    nvd.lookup, sca.run_opensca, epss.scores = keep


def main() -> int:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        for fn in (databases, agents_fill_in):
            print(f"-- {fn.__name__}")
            mine = tmp / fn.__name__
            mine.mkdir()
            projects.STORE, pipeline.SCANS_DIR, rulegen.OUT_DIR = mine / "store", mine / "scans", mine / "rules"
            review.FILE, decisions.FILE = mine / "r.json", mine / "d.json"
            os.environ["SCA_OSV"] = "0"
            fn(mine)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
