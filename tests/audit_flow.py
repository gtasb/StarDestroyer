"""How the audit's work is ordered, kept and counted, with a stand-in for dsh."""

import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import _env  # noqa: F401
import agent_audit as T
from core import agents, audit, codeintel, decisions, hunt, pipeline, proc, projects, records, review, rulegen, verdict

FAILED: list[str] = []
ok = T.ok


def check(name: str, ok_, detail="") -> None:
    print(("PASS " if ok_ else "FAIL ") + name + ("" if ok_ else f"  -> {str(detail)[:700]}"))
    if not ok_:
        FAILED.append(name)


def kept(tmp, dsh) -> None:
    root = T.app(tmp / "app")
    dsh.play(brief=ok(T.BRIEF), sink=ok(T.SINK), review=ok(T.UP))
    real, calls = audit.take, []

    def broken(u, *a, **k):
        if u["kind"] == "sink":
            calls.append(u)
            raise proc.Cancelled()
        return real(u, *a, **k)
    audit.take = broken
    try:
        audit.run(root, ["sink"], concurrency=1)
    except proc.Cancelled:
        pass
    audit.take = real
    u = next(x for x in audit.load(root)["units"].values() if x["kind"] == "sink")
    check("an answer is kept before anything is done with it", calls and u["state"] == "answered" and u["answer"]["findings"] and u["usage"]["in"] == 15, u)
    spent = audit.load(root)["usage"]["in"]
    check("what it cost is counted", spent >= 30, audit.load(root)["usage"])
    check("it does not count as done", audit.progress(root)["by"]["sink"]["done"] == 0)
    dsh.play(review=ok(T.UP))
    r = audit.run(root, ["sink"])
    kinds = [x["kind"] for x in dsh.log()[0]]
    check("next time it is filed without another session", r["worked"] == 1 and "sink" not in kinds and audit.findings(root)[0]["status"] == "confirmed", (r["worked"], kinds))
    u = next(x for x in audit.load(root)["units"].values() if x["kind"] == "sink")
    check("and is an ordinary finished unit", u["state"] == "done" and "answer" not in u and u["steps"], u)

    root = T.app(tmp / "reviews")
    dsh.play(brief=ok(T.BRIEF), sink=ok(T.SINK), review={"die": "no network"})
    r = audit.run(root, ["sink"])
    check("a finding nobody could review is open, and that is a gap", any("还没有独立复核" in g for g in r["incomplete_reasons"]) and not r["complete"] and audit.findings(root)[0]["status"] == "needs_review", r["incomplete_reasons"])
    audit.refresh(root)
    check("the project list knows", not audit.summary(root)["complete"])
    dsh.play(review=ok(T.UP))
    r = audit.run(root, ["sink"])
    check("it is reviewed next time, with nothing else to do", r["complete"] and r["worked"] == 0 and [x["kind"] for x in dsh.log()[0]] == ["review"] and audit.findings(root)[0]["status"] == "confirmed", r)


def replies(tmp, dsh) -> None:
    agents.RETRY_WAIT_S = 0
    root = T.app(tmp / "app")
    spec = {"type": "review", "root": root, "rec": {"message": "m"}, "context": ""}
    lost = {"kind": "error", "error": {"message": "DeepSeek Messages stream: tool input is invalid JSON", "code": "MALFORMED_RESPONSE"}}
    dsh.play(review={"answers": [T.UP], "late": True, "reason": lost})
    r = agents.run(spec)
    runs = dsh.log()[0]
    check("a reply that was garbled is asked for again, in the same session", r["ok"] and [x["resumed"] for x in runs] == [False, True] and "已经读过" in runs[1]["task"], r)
    dsh.play(review={"answers": [], "reason": lost})
    r = agents.run(spec)
    check("a few times, not for ever", not r["ok"] and len(dsh.log()[0]) == 3 and "MALFORMED" in r["error"], len(dsh.log()[0]))
    for reason in ({"kind": "error", "message": "Insufficient balance"}, {"kind": "error", "error": {"code": "401", "message": "invalid api key"}}, {"kind": "error", "message": "maximum context length exceeded"}):
        dsh.play(review={"answers": [], "reason": reason})
        agents.run(spec)
        check(f"not when it would be the same again: {json.dumps(reason)[17:60]}", len(dsh.log()[0]) == 1)
    check("what is worth another try", all(agents.transient({"error": {"message": m}}) for m in ("HTTP 503", "429 rate limit", "socket hang up", "ECONNRESET", "Overloaded")) and not agents.transient({"kind": "max_steps"}))


def order(tmp, dsh) -> None:
    root = T.app(tmp / "app")
    kept_ = [{"cve": "CVE-2020-0001", "dependency": "lib", "group": "g", "version": "1", "cvss": 9.8, "percentile": .9, "cwes": [], "family": "", "summary": "s", "usage": "used", "usage_evidence": [], "via": "a > lib"}]
    projects.save_artifact(root, "triage", {"ok": True, "kept": kept_ + [{**kept_[0], "cve": "CVE-2020-0002", "dependency": "lib2"}] + [{**kept_[0], "dependency": "lib2"}], "ignored": []})
    plan = audit.plan(root)
    kinds = [u["kind"] for u in plan]
    check("what is reachable from outside comes before what is inherited", kinds.index("endpoint") < kinds.index("dependency") and kinds.index("sink") < kinds.index("dependency"), kinds)
    dep = [u for u in plan if u["kind"] == "dependency"]
    check("a CVE two modules share is judged once, with how it got in", len(dep) == 1 and sorted(dep[0]["items"]) == ["CVE-2020-0001", "CVE-2020-0002"] and dep[0]["dependency"]["via"] == ["a > lib"], dep)
    (pathlib.Path(root) / "pom.xml").write_text("<project/>", encoding="utf-8")

    root = T.app(tmp / "overlap")
    everything = {"brief": ok(T.BRIEF), "endpoint": ok(T.ENDP), "review": ok(T.UP), "rules": ok({"sast": [], "secrets": [], "sca": [], "reason": "r"}), "map": ok({"areas": [T.ONE], "excluded": [*T.REST, {"class": "Business logic", "reason": "x"}]}),
                  "hunt": ok({"findings": [], "coverage": T.COV("Injection", "Wildcard")}), "critic": ok({"areas": [], "reason": "都查了"})}
    dsh.play(**everything, sink={**ok(T.SINK), "sleep": 6})
    r = audit.run(root, concurrency=3)
    logs = sorted(pathlib.Path(str(dsh.plan) + ".log").glob("*"))
    at = {}
    for f in logs:
        row = json.loads(f.read_text(encoding="utf-8").split("\n")[0])
        at.setdefault(row["kind"], int(f.name.split("-")[0]) / 1e9)
    check("a slow unit does not hold up the next stage", at["rules"] - at["sink"] < 5, at)
    check("but the hunters wait for the map, the critic for them, and the last rules for all", at["brief"] < at["sink"] and at["map"] < at["hunt"] < at["critic"], at)
    rules = [int(f.name.split("-")[0]) / 1e9 for f in logs if json.loads(f.read_text(encoding="utf-8").split("\n")[0])["kind"] == "rules"]
    check("variants are written once everything is settled", len(rules) == 2 and rules[1] > at["critic"], rules)
    check("and it is complete", r["complete"], r["incomplete_reasons"])
    check("sessions that ran at once are still one finding", len(audit.findings(root)) == 1)

    root = T.app(tmp / "broken")
    dsh.play(**{**everything, "sink": ok(T.SINK), "map": {}})
    r = audit.run(root)
    check("without a map the rest is not tried, and the leads still are", r["progress"]["by"]["sink"]["done"] == 1 and not r["complete"] and not {"hunt", "critic"} & {x["kind"] for x in dsh.log()[0]}, r["incomplete_reasons"])


def together(tmp, dsh) -> None:
    root = T.app(tmp / "app")
    base = {"message": "AI 规则命中", "status": "needs_review", "reason": "r", "severity": "high", "cwe": "CWE-639", "source_tool": "opengrep", "evidence_level": "none"}
    recs = []
    for n in range(1, 8):
        rec = {**base, "rule_id": "ai-tenant", "file": T.C, "line": n, "trace": [{"kind": "source", "file": T.C, "line": n, "text": "x"}]}
        recs.append({**rec, "suppress_key": audit._key(rec, root)})
    real, projects.findings = projects.findings, lambda p, k, run="": (decisions.apply(r := [dict(x) for x in recs]) and r or r) if k == "sast" else []
    units = [u for u in audit.plan(root, ["chain"]) if u["kind"] == "chain"]
    check("hits of one rule are read together, a few at a time", [len(u["items"]) for u in units] == [5, 2], [len(u["items"]) for u in units])
    said = lambda n: {"items": [{"id": f"H{i}", "verdict": "completed", "reason": "r", "chain": T.CHAIN} if i == 1 else {"id": f"H{i}", "verdict": "dead", "reason": "有归属校验", "evidence": T.EV} for i in range(1, n + 1)]}
    dsh.play(brief=ok(T.BRIEF), chain=ok(said(1), said(2), said(5)), review=ok(T.UP, {"items": [{"id": "R1", **T.UP}]}, {"items": [{"id": "R1", **T.UP}, {"id": "R2", **T.UP, "verdict": "refute"}]}))
    r = audit.run(root, ["chain"], concurrency=1)
    out = projects.findings(root, "sast")
    check("each has its own answer", any("还没有结论" in x for x in dsh.log()[1]) and sorted((x.get("review") or {}).get("verdict", "?") for x in out).count("refute") >= 5, [(x["line"], (x.get("review") or {}).get("verdict")) for x in out])
    n = [x["kind"] for x in dsh.log()[0]].count("review")
    check("and what held up is reviewed together, one by one", n == 1 and {"uphold", "refute"} <= {(x.get("review") or {}).get("verdict") for x in out} and [x for x in out if (x.get("review") or {}).get("chain")], (n, r["incomplete_reasons"]))
    check("nothing is left waiting", not audit.load(root)["chains"] and r["complete"], audit.load(root)["chains"])
    projects.findings = real

    src = tmp / "src"
    src.mkdir()
    (src / "A.java").write_text("class A {\n  void one() {\n    f(1);\n    f(2);\n    f(3);\n  }\n  void two() {\n    f(4);\n  }\n}\n", encoding="utf-8")
    codeintel._CACHE.clear()
    mk = lambda n, rule="ai-x": {"rule_id": rule, "file": "A.java", "line": n, "trace": [{"kind": "sink", "file": "A.java", "line": n, "text": "f"}]}
    got = pipeline._merge_in_method([mk(3), mk(4), mk(5), mk(8), mk(4, "java-sqli"), mk(5, "java-sqli")], str(src))
    check("lines of one method are one place, for rules an agent wrote only", [(r["rule_id"], r["line"], r.get("lines")) for r in got] == [("ai-x", 3, [4, 5]), ("ai-x", 8, None), ("java-sqli", 4, None), ("java-sqli", 5, None)], got)


def standing(tmp, dsh) -> None:
    root = T.app(tmp / "app")
    f = {**T.FIND, "title": "越权", "cwe": "CWE-639", "auth": "login", "auth_default": "anonymous", "cause": "报表 接口没有归属校验", "chain": [T.CHAIN[0], {"role": "sink", "file": T.I, "line": 4, "quote": "reportMapper.listSorted(sort.trim())"}]}
    same = {**f, "auth_default": "login", "title": "另一处", "chain": T.CHAIN}
    good, why = audit._findings([f, same], root)
    check("what it takes in production and by default are kept apart", not why and good[0]["auth"] == "login" and good[0]["auth_default"] == "anonymous" and "auth_default" not in good[1], (good, why))
    check("severity is asked for by production", "生产配置" in audit._AUDITOR and "生产配置" in json.dumps(audit._FINDING, ensure_ascii=False))
    dsh.play(brief=ok({**T.BRIEF, "environments": "prod 走网关"}), endpoint=ok({**T.ENDP, "endpoints": [{**T.ENDP["endpoints"][0], "auth": "login", "auth_default": "anonymous"}, T.ENDP["endpoints"][1]], "findings": [f]}), review=ok({**T.UP, "verdict": "refute"}), sink=ok(T.SINK))
    audit.run(root, ["endpoint", "sink"], concurrency=1)
    d = audit.load(root)
    check("endpoints too", d["endpoints"][f"{T.C}|GET /open/report/list"]["auth_default"] == "anonymous")
    check("later agents know the environments, and the causes found so far", "prod 走网关" in audit._context(d) and "报表 接口没有归属校验" in audit._context(d))
    s = audit.summary(root)
    check("what a review refuted is not open risk, and still listed", s["refuted"] == len(audit.findings(root)) >= 1 and s["severity"] == {} and s["needs_review"] >= 1, s)
    decisions.put(audit.findings(root)[0]["suppress_key"], "confirmed", "x")
    check("until a person says otherwise", audit.summary(root)["severity"] == {"high": 1}, audit.summary(root))
    check("causes", records.cause({"cwe": "CWE-862"}) == records.cause({"cwe": "CWE-639"}) == "缺少授权或归属校验" and records.cause({"cwe": "CWE-639", "cause": "c"}) == "c" and records.cause({"rule_id": "agent-dependency", "cwe": "CWE-502"}) == "有漏洞的依赖" and records.cause({"cwe": "CWE-9"}) == "CWE-9" and records.cause({}) == "其它")
    import web.server as server
    from fastapi.testclient import TestClient
    pid = projects.add(root)["project"]["id"]
    web = TestClient(server.app, base_url="http://127.0.0.1:8770", headers={"X-SD-Token": server.TOKEN})
    get = lambda **k: web.get("/api/findings", params={"project_id": pid, "kind": "agent", **k}).json()
    g = get(group="1")["groups"]
    check("findings can be put together by cause", sum(x["count"] for x in g) == get()["total"] and any(x["cause"] == "报表 接口没有归属校验" for x in g), g)
    check("and opened again", {x["cause"] for x in get(cause="报表 接口没有归属校验")["items"]} == {"报表 接口没有归属校验"})
    check("refuted ones are a status of their own", get(status="refuted")["total"] == get()["facets"]["status"].get("refuted", 0) and all(x["shown"] == "refuted" for x in get(status="refuted")["items"]))
    audit._update(root, lambda x: x.update(engine_gaps=[{"kind": "sast", "type": "depth", "text": "跨文件分析到达深度上限（3 条规则）", "closed": True}]))
    t = server._closed([{"state": "done", "complete": False, "kind": "sast", "project_id": pid, "gaps": ["跨文件分析到达深度上限（2 条规则），更深的链要靠 agent 续追"]}, {"state": "done", "complete": False, "kind": "sast", "project_id": pid, "gaps": ["3 个源文件解析失败"]}])
    check("a task whose gaps were closed since is complete", t[0]["complete"] and t[0]["by_agent"] and not t[1]["complete"], t)
    check("tests leave the real log alone", "sd-test-logs" in str(__import__("core.logging", fromlist=["x"]).LOG_FILE))


def main() -> int:
    saved = dict(os.environ)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        dsh = T.Dsh(tmp)
        for fn in (kept, replies, order, together, standing):
            print(f"-- {fn.__name__}")
            mine = tmp / fn.__name__
            mine.mkdir()
            os.environ["SCA_OSV"] = "0"
            projects.STORE, pipeline.SCANS_DIR, rulegen.OUT_DIR = mine / "store", mine / "scans", mine / "rules"
            review.FILE, decisions.FILE = mine / "r.json", mine / "d.json"
            fn(mine, dsh)
        dsh.close()
    os.environ.clear()
    os.environ.update(saved)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
