"""The audit agent: runs on dsh, reads only the audited tree, and every citation is
checked. Offline: a script plays dsh and calls the real submit tool.
"""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
__import__("os").environ["SCA_OSV"] = "0"  # offline

import _env  # noqa: F401
from core import (agent_tool, agents, airules, audit, codeintel, config, decisions, endpoints, hunt, pipeline, projects, providers, review,
                  rulegen, sca_triage, store, tasks, toolset)

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))
    if not ok:
        FAILED.append(name)


APP = {
    "src/a/ReportController.java": '''package a;
@RestController
@RequestMapping("/open/report")
public class ReportController {
  @Autowired private ReportService reportService;
  @GetMapping("/list")
  public List<Map> list(@RequestParam String sort) { return reportService.list(sort); }
  @GetMapping("/safe")
  public List<Map> safe(@RequestParam String sort) { return reportService.safe(sort); }
}
''',
    "src/a/ReportService.java": "package a;\npublic interface ReportService {\n  List<Map> list(String sort);\n  List<Map> safe(String sort);\n}\n",
    "src/a/ReportServiceImpl.java": '''package a;
public class ReportServiceImpl extends ServiceImpl<ReportMapper, Report> implements ReportService {
  // reportMapper.listSorted("in a comment");
  public List<Map> list(String sort) { return reportMapper.listSorted(sort.trim()); }
  public List<Map> safe(String sort) { return reportMapper.safeSorted(COLS.contains(sort) ? sort : "id"); }
  String multiLikeval = "eval(x)"; boolean b = name.startsWith("list");
}
''',
    "src/a/ReportMapper.java": "package a;\npublic interface ReportMapper {\n  List<Map> listSorted(@Param(\"sort\") String sort);\n  List<Map> safeSorted(@Param(\"sort\") String sort);\n}\n",
    "src/m/ReportMapper.xml": '''<?xml version="1.0"?>
<mapper namespace="a.ReportMapper">
  <!-- <select id="old">${x}</select> -->
  <select id="listSorted" resultType="map">
    select * from report order by ${sort}
  </select>
  <select id="safeSorted" resultType="map">
    select * from report order by ${sort} limit #{n}
  </select>
</mapper>
''',
    "src/test/a/T.java": "class T { void t() { Runtime.getRuntime().exec(x); } }\n",
}
C, I, X = "src/a/ReportController.java", "src/a/ReportServiceImpl.java", "src/m/ReportMapper.xml"
CHAIN = [{"role": "entry", "file": C, "line": 7, "quote": "public List<Map> list(@RequestParam String sort)"},
         {"role": "step", "file": I, "line": 4, "quote": "reportMapper.listSorted(sort.trim())"},
         {"role": "sink", "file": X, "line": 5, "quote": "select * from report order by ${sort}"}]
FIND = {"title": "SQL 注入", "cwe": "CWE-89: SQLi", "severity": "high", "auth": "anonymous", "chain": CHAIN, "impact": "读库"}
EV = [{"file": X, "line": 5, "quote": "order by ${sort}"}]
UP = {"verdict": "uphold", "reason": "r", "evidence": EV}
BRIEF = {"summary": "s", "auth": "拦截器", "anonymous": ["/open/**"], "evidence": [EV[0], {"file": C, "line": 7, "quote": "@RequestParam String sort"}]}
SINK = {"sinks": [{"line": 5, "verdict": "exploitable", "note": "n"}, {"line": 8, "verdict": "safe", "note": "白名单"}], "findings": [FIND]}
ENDP = {"endpoints": [{"endpoint": "GET /open/report/list", "auth": "anonymous", "verdict": "vulnerable", "note": "n"},
                      {"endpoint": "GET /open/report/safe", "auth": "anonymous", "verdict": "ok", "note": "n"}], "findings": [FIND]}


def app(d: pathlib.Path) -> str:
    for k, v in APP.items():
        (d / k).parent.mkdir(parents=True, exist_ok=True)
        (d / k).write_text(v, encoding="utf-8")
    codeintel._CACHE.clear()
    endpoints._CACHE.clear()
    return str(d.resolve())


# ---- a stand-in for dsh ------------------------------------------------------
FAKE = '''import json, os, pathlib, subprocess, sys
a = sys.argv[1:]
task = sys.stdin.buffer.read().decode("utf-8")
spec = json.load(open(os.environ["SD_SPEC"], encoding="utf-8")) if "SD_SPEC" in os.environ else {}
kind = spec.get("unit", {}).get("kind") or spec.get("type") or "test"
plan = json.load(open(os.environ["FAKE_PLAN"], encoding="utf-8"))
log = pathlib.Path(os.environ["FAKE_PLAN"] + ".log")
log.mkdir(exist_ok=True)
log /= f"{__import__('time').time_ns()}-{os.getpid()}"
patch = pathlib.Path(a[a.index("--patch") + 1]).read_text(encoding="utf-8")
with log.open("a", encoding="utf-8") as fh:
    fh.write(json.dumps({"kind": kind, "argv": a, "cwd": os.getcwd(), "task": task, "patch": json.loads(patch),
                         "root": os.environ.get("SD_AUDIT_ROOT"), "key": os.environ.get("SD_LLM_KEY"), "resumed": "--session-id" in a}, ensure_ascii=False) + "\\n")
sys.stdout.reconfigure(encoding="utf-8")
say = lambda **e: print(json.dumps(e, ensure_ascii=False), flush=True)
p = plan.get(kind, plan.get("*", {}))
if p.get("sleep"): __import__("time").sleep(p["sleep"])
if p.get("die"): sys.stderr.write(p["die"]); sys.exit(1)
say(type="session", sessionId="s1")
say(type="tool_call", tool="read", input={"file_path": "x"})
say(type="status", usage={"inputTokens": 10, "cacheReadTokens": 5, "outputTokens": 2})
answers = p.get("answers", [])
if p.get("late") and "--session-id" not in a: answers = []
for ans in answers:
    r = subprocess.run([sys.executable, "-X", "utf8", os.environ["FAKE_TOOL"], "sd_submit"], input=json.dumps(ans).encode(), capture_output=True)
    say(type="tool_call", tool="sd_submit", input={})
    with log.open("a", encoding="utf-8") as fh: fh.write(json.dumps({"reply": r.stdout.decode("utf-8")}, ensure_ascii=False) + "\\n")
if "forge" in p: pathlib.Path(os.environ["SD_RESULT"]).write_text(json.dumps(p["forge"]))
say(type="final", text=p.get("text", "OK"), reason=p.get("reason", {"kind": "completed"}))
'''


class Dsh:
    def __init__(self, tmp: pathlib.Path):
        self.plan, self.script = tmp / "plan.json", tmp / "fake_dsh.py"
        self.script.write_text(FAKE, encoding="utf-8")
        os.environ.update(FAKE_PLAN=str(self.plan), FAKE_TOOL=str(ROOT / "core" / "agent_tool.py"), DSH_BIN=str(self.script), DEEPSEEK_API_KEY="k")
        self.real, agents.command = agents.command, lambda patch, session="": [sys.executable, str(self.script)] + self.real(patch, session)[-(9 + 2 * bool(session)):]

    def play(self, **kinds):
        self.plan.write_text(json.dumps(kinds), encoding="utf-8")
        shutil.rmtree(str(self.plan) + ".log", ignore_errors=True)

    def log(self):
        f = pathlib.Path(str(self.plan) + ".log")
        rows = [json.loads(x) for one in sorted(f.glob("*")) for x in one.read_text(encoding="utf-8").split("\n") if x]
        return [r for r in rows if "kind" in r], [r["reply"] for r in rows if "reply" in r]

    def close(self):
        agents.command = self.real


def ok(*answers):
    return {"answers": list(answers)}


# ---- tests -------------------------------------------------------------------
def navigation(tmp) -> None:
    root = app(tmp / "app")
    idx = codeintel.index(root)
    s = idx.symbol("ReportMapper.listSorted")
    check("a mapper method and its XML statement are both found", len(s["methods"]) == 1 and s["statements"][0]["file"] == X, s)
    check("commented statements are not statements", "old" not in idx.statements)
    check("an interface leads to its implementation", [t["name"] for t in idx.implementations("ReportService")] == ["ReportServiceImpl"])
    callers = idx.callers("list", "ReportService")
    check("callers through an interface field", [(c["file"], c["line"], c["in"]) for c in callers] == [(C, 7, "ReportController.list")], callers)
    check("comments are not call sites", [c["line"] for c in idx.callers("listSorted", "ReportMapper")] == [4], idx.callers("listSorted", "ReportMapper"))
    check("a method is returned whole, annotations included", '@GetMapping("/list")' in idx.method_source(C, 7)["source"])
    sites = {(x["file"], x["line"], x["class"]) for x in codeintel.sink_sites(root)}
    check("every mapper ${} is a lead, #{} is not", {(X, 5, "sqli"), (X, 8, "sqli")} <= sites and len([x for x in sites if x[0] == X]) == 2, sites)
    check("multiLikeval and startsWith are not sinks", not [x for x in sites if x[0] == I], sites)
    check("test code is not a lead", not [x for x in sites if "test" in x[0]], sites)
    tri = {"kept": [{"cve": "CVE-1", "family": "command"}, {"cve": "CVE-2", "family": "expression"}]}
    check("SCA leads are real calls", all(not f["hints"] for f in sca_triage.sink_report(tri, root)["families"]))


def tools(tmp) -> None:
    root = app(tmp / "app")
    (tmp / "secret.txt").write_text("TOP", encoding="utf-8")

    def tool(tool_name, /, **args):
        r = subprocess.run([sys.executable, "-X", "utf8", str(ROOT / "core" / "agent_tool.py"), tool_name], input=json.dumps(args).encode(),
                           capture_output=True, env={**os.environ, "SD_AUDIT_ROOT": root})
        return r.stdout.decode("utf-8") or r.stderr.decode("utf-8", "replace")
    check("symbol", f"{X}:4-6 含 1 处 ${{}}" in tool("sd_symbol", name="listSorted"), tool("sd_symbol", name="listSorted"))
    check("callers", "ReportController.list" in tool("sd_callers", method="list", owner="ReportService"))
    check("implementations", "ReportServiceImpl" in tool("sd_implementations", name="ReportService"))
    check("method", "reportMapper.listSorted" in tool("sd_method", file=I, line=4))
    check("endpoints", f"GET /open/report/list {C}:" in tool("sd_endpoints", filter="list"))
    check("sinks", f"{X}:5" in tool("sd_sinks", **{"class": "sqli"}))
    for bad in ("../secret.txt", str(tmp / "secret.txt"), "//127.0.0.1/x/y"):
        check(f"method refuses {bad[-14:]}", tool("sd_method", file=bad, line=1).startswith("错误"), tool("sd_method", file=bad, line=1))
    check("a root argument from the model is refused", tool("sd_symbol", name="x", root="C:/").startswith("错误"))
    check("advisory takes a CVE number and nothing else", tool("sd_advisory", cve="my source code").startswith("错误"))
    check("unknown tools and bad input are errors", tool("rm").startswith("错误") and tool("sd_symbol", nope=1).startswith("错误"))


def guard(tmp) -> None:
    node = shutil.which("node")
    if not node:
        return check("node is available", False)
    root = app(tmp / "app")
    (tmp / "app" / ".env").write_text("K=1", encoding="utf-8")
    (tmp / "app" / "a.key").write_text("K", encoding="utf-8")
    (tmp / "spec.json").write_text(json.dumps({"schema": {"type": "object", "properties": {}}}), encoding="utf-8")
    inside, outside = str(pathlib.Path(root) / C), str(tmp / "spec.json")
    cases = [
        ["read", {"file_path": inside}, True], ["read", {"file_path": C}, False], ["grep", {"pattern": "x", "path": root}, True],
        ["glob", {"pattern": "**/*.xml", "path": root}, True], ["sd_symbol", {}, True], ["sd_submit", {}, True],
        ["read", {"file_path": outside}, False], ["read", {"file_path": root + "/../spec.json"}, False], ["read", {}, False],
        ["read", {"file_path": "\\\\127.0.0.1\\share\\x"}, False], ["read", {"file_path": root + "/.env"}, False], ["read", {"file_path": root + "/a.key"}, False],
        ["read", {"file_path": root + "-evil/x"}, False], ["grep", {"pattern": "x"}, False], ["grep", {"pattern": "x", "path": str(tmp)}, False],
        ["grep", {"pattern": "x", "path": root, "include": "*.env"}, False], ["glob", {"pattern": "../*", "path": root}, False], ["glob", {"pattern": "C:/**", "path": root}, False],
        ["bash", {"command": "id"}, False], ["pwsh", {"command": "id"}, False], ["write", {"file_path": inside}, False], ["edit", {"file_path": inside}, False],
        ["sd_web_search", {"query": "x"}, False], ["sd_review_verdict", {}, False], ["sd_audit_submit", {}, False], ["sd_scan", {"path": "/"}, False],
        ["sd_opengrep", {}, False], ["wait_agent", {}, False], ["send_message", {}, False],
        ["web_fetch", {"url": "x"}, False], ["subagent", {}, False], ["apply_patch", {}, False],
    ]
    js = tmp / "t.mjs"
    js.write_text("const m = await import(process.argv[2]); let g; const tools = {};\n"
                  "m.apply({ tools: { guard: f => { g = f }, register: t => { tools[t.name] = t } } });\n"
                  "const submitEarly = await tools.sd_submit.execute({}, {});\n"
                  "console.log(JSON.stringify({ early: submitEarly, names: Object.keys(tools), r: JSON.parse(process.argv[3]).map(([n, a]) => g({ name: n, arguments: a }) === undefined) }))\n", encoding="utf-8")
    r = subprocess.run([node, str(js), agents.PLUGIN.as_uri(), json.dumps(cases)], capture_output=True, text=True, encoding="utf-8",
                       env={**os.environ, "SD_AUDIT_ROOT": root, "SD_SPEC": str(tmp / "spec.json")})
    try:
        out = json.loads(r.stdout)
    except ValueError:
        return check("the plugin loads", False, r.stderr)
    for (n, a, want), got in zip(cases, out["r"]):
        check(f"guard {'allows' if want else 'refuses'} {n} {str(list(a.values())[:2])[-50:]}", got is want)
    (tmp / "spec.json").write_text(json.dumps({"schema": {"type": "object", "properties": {}}, "subagents": 2, "engines": True}), encoding="utf-8")
    cases = [["subagent", {"prompt": "x"}, True], ["subagent", {"prompt": "x", "cwd": "C:/"}, False], ["subagent", {"prompt": "x", "model": "m"}, False],
             ["subagent", {"prompt": "y"}, True], ["subagent", {"prompt": "z"}, False], ["wait_agent", {}, True], ["sd_opengrep", {}, True], ["sd_findings", {}, True],
             ["sd_scan", {}, False], ["bash", {"command": "id"}, False], ["read", {"file_path": outside}, False], ["sd_submit", {}, True]]
    r2 = subprocess.run([node, str(js), agents.PLUGIN.as_uri(), json.dumps(cases)], capture_output=True, text=True, encoding="utf-8",
                        env={**os.environ, "SD_AUDIT_ROOT": root, "SD_SPEC": str(tmp / "spec.json")})
    got = json.loads(r2.stdout or '{"r": []}')["r"]
    check("a hunter may delegate, within limits, and run the engines", got == [c[2] for c in cases], (list(zip(cases, got)), r2.stderr[-300:]))
    kid = [[n, a, w] for n, a, w in (["read", {"file_path": inside}, True], ["read", {"file_path": outside}, False], ["subagent", {"prompt": "x"}, False], ["sd_submit", {}, False], ["sd_callers", {}, True])]
    js.write_text(js.read_text(encoding="utf-8").replace("g({ name: n, arguments: a })", "g({ name: n, arguments: a, agent: { options: { subagentDepth: 1 } } })"), encoding="utf-8")
    r3 = subprocess.run([node, str(js), agents.PLUGIN.as_uri(), json.dumps(kid)], capture_output=True, text=True, encoding="utf-8",
                        env={**os.environ, "SD_AUDIT_ROOT": root, "SD_SPEC": str(tmp / "spec.json")})
    got = json.loads(r3.stdout or '{"r": []}')["r"]
    check("its children are confined, and only it submits", got == [c[2] for c in kid], (got, r3.stderr[-300:]))
    off = {p["id"] for p in agents.overlay({"subagents": 4}) if p.get("disabled")}
    check("only a hunter's session has the delegation tool", "tool-subagent" not in off and {"tool-web", "tool-subagent-fork", "tool-workflow", "stardestroyer"} <= off
          and "tool-subagent" in {p["id"] for p in agents.overlay({}) if p.get("disabled")})
    js.write_text(js.read_text(encoding="utf-8").replace(", agent: { options: { subagentDepth: 1 } }", ""), encoding="utf-8")

    def under(mode, rows):
        r = subprocess.run([node, str(js), agents.PLUGIN.as_uri(), json.dumps(rows)], capture_output=True, text=True, encoding="utf-8",
                           env={**os.environ, "SD_AUDIT_ROOT": root, "SD_SPEC": str(tmp / "spec.json"), "SD_ACCESS": mode})
        return json.loads(r.stdout or '{"r": []}')["r"]
    rows = [["pwsh", {"command": "x"}], ["bash", {"command": "x"}], ["job_output", {}], ["pwsh", {"command": "x", "sandbox_permissions": "danger-full-access"}], ["write", {"file_path": inside}],
            ["web_fetch", {"url": "x"}], ["read", {"file_path": outside}], ["sd_web_search", {}], ["sd_review_verdict", {}]]
    check("with a shell: commands, no wider sandbox, nothing else new", under("shell", rows) == [True, True, True, False, False, False, False, False, False], under("shell", rows))
    check("read-only: none of it", not any(under("readonly", rows)))
    check("unguarded: all but answering for the audit", under("open", rows) == [True] * 7 + [False, False], under("open", rows))
    check("anything else is read-only", not any(under("", rows)))
    check("a submission before reading is refused", "have not read" in out["early"], out["early"])
    check("the plugin registers its tools", {"sd_symbol", "sd_callers", "sd_implementations", "sd_method", "sd_sinks", "sd_submit"} <= set(out["names"]))


def citations(tmp) -> None:
    root = app(tmp / "app")
    good, bad = agents.verify(CHAIN, root)
    check("real quotes hold", len(good) == 3 and not bad, bad)
    check("one line off is tolerated", agents.verify([{**CHAIN[2], "line": 6}], root)[0][0]["line"] == 5)
    for name, e in (("an invented quote", {"quote": "if (admin) return;"}), ("a wrong line", {"line": 1}), ("a missing file", {"file": "no.java"}),
                    ("a path outside", {"file": "../x"}), ("a trivial quote", {"quote": "s"})):
        check(f"{name} does not hold", agents.verify([{**CHAIN[2], **e}], root)[1])
    check("the agent is told what the line really is", "select * from report" in agents.verify([{**CHAIN[2], "quote": "nope nope"}], root)[1][0])
    for junk in (None, "x", [1, None, {}]):
        check(f"junk {junk!r} is harmless", not agents.verify(junk, root)[0])


def sessions(tmp, dsh) -> None:
    root = app(tmp / "app")
    spec = {"type": "review", "root": root, "rec": {"message": "m"}, "context": ""}
    dsh.play(review=ok(UP))
    r = agents.run(spec)
    runs, _ = dsh.log()
    check("an accepted answer comes back with what was read and spent", r["ok"] and r["value"]["verdict"] == "uphold" and r["reads"] and r["usage"] == {"in": 15, "out": 2, "cached": 5}, r)
    a = runs[0]
    check("by default: commands in dsh's sandbox, and it never asks", a["argv"][-5:] == ["--permission-mode", "workspace-write", "--approval-policy", "never", "-"], a["argv"])
    off = {p["id"] for p in a["patch"] if p.get("disabled")}
    check("a shell, but no network tool, helpers or project instructions", not off & {"tool-bash", "tool-pwsh"} and {"tool-web", "tool-subagent", "agent-instructions", "skill-filesystem", "stardestroyer"} <= off, off)
    check("the agent knows the command line tools and the limits", "opengrep:" in a["task"] and "不要运行被审项目自己的代码" in a["task"])
    check("its workspace is gone afterwards, and apart from the task and the answer", not pathlib.Path(a["cwd"]).exists() and "sd-agent-" not in a["cwd"], a["cwd"])
    os.environ["AUDIT_ACCESS"] = "readonly"
    dsh.play(review=ok(UP))
    agents.run(spec)
    a = dsh.log()[0][0]
    check("read-only on request", a["argv"][-5:] == ["--permission-mode", "read-only", "--approval-policy", "never", "-"] and "你有 shell" not in a["task"], a["argv"])
    off = {p["id"] for p in a["patch"] if p.get("disabled")}
    check("then no shell either", {"tool-bash", "tool-pwsh", "tool-web", "tool-subagent", "agent-instructions", "skill-filesystem", "stardestroyer"} <= off, off)
    check("the audit plugin is loaded", a["patch"][-1]["insert"][0]["name"] == agents.PLUGIN.as_posix())
    check("the audited project is never the working directory (dsh reads .env there)", not pathlib.Path(a["cwd"]).resolve().is_relative_to(root), a["cwd"])
    check("the root comes from the environment", pathlib.Path(a["root"]) == pathlib.Path(root) and root in a["task"])
    os.environ["AUDIT_ACCESS"] = "open"
    off = {p["id"] for p in agents.overlay({}) if p.get("disabled")}
    check("unguarded on request, still without project instructions", not off & {"tool-bash", "tool-web", "tool-subagent"} and {"agent-instructions", "skill-filesystem", "stardestroyer"} <= off, off)
    os.environ["AUDIT_ACCESS"] = "opne"
    check("a typo does not open anything", agents.access() == "readonly")
    os.environ.pop("AUDIT_ACCESS")
    dsh.play(review={"answers": [], "forge": {"verdict": "uphold", "reason": "r", "evidence": [{**EV[0], "quote": "return safe;"}]}})
    r = agents.run(spec)
    check("an answer that did not come through the tool is checked all the same", not r["ok"] and "复查不通过" in r["error"], r)
    dsh.play(review=ok({**UP, "evidence": [{**EV[0], "quote": "return safe;"}]}, {"verdict": "maybe"}, UP))
    r = agents.run(spec)
    replies = dsh.log()[1]
    check("a bad answer goes back with the reason until it holds", r["ok"] and "未通过核对" in replies[0] and "原文不符" in replies[0] and "已接受" in replies[2], replies)
    dsh.play(review={"answers": [UP], "late": True})
    r = agents.run(spec)
    check("a session that forgot to submit is resumed once", r["ok"] and [x["resumed"] for x in dsh.log()[0]] == [False, True], r)
    dsh.play(review={})
    r = agents.run(spec)
    check("no accepted answer is a failure", not r["ok"] and len(dsh.log()[0]) == 2, r)
    dsh.play(review={"answers": [], "reason": {"kind": "error", "message": "quota"}})
    check("a session that broke off is a failure, with the reason", "quota" in agents.run(spec)["error"])
    dsh.play(review={"die": "bad key"})
    check("a dead dsh is a failure, with its last words", "bad key" in agents.run(spec)["error"])
    dsh.play(review={"sleep": 5})
    agents.TIMEOUT_S, saved = 1, agents.TIMEOUT_S
    check("a stuck session is stopped", "超时" in agents.run(spec)["error"])
    agents.TIMEOUT_S = saved
    dsh.play(test={"text": "OK"})
    check("the connection test is a session", agents.test()["ok"], agents.test())
    src = "".join((ROOT / "core" / f).read_text(encoding="utf-8") for f in os.listdir(ROOT / "core") if f.endswith(".py"))
    check("there is no model client or agent loop of our own", "chat/completions" not in src and "messages.create" not in src and not (ROOT / "core" / "llm.py").exists())


def models(tmp) -> None:
    for k in ("LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL"):
        os.environ.pop(k, None)
    check("dsh's own route is the default", providers.overlay() == [{"id": "agent-default-model", "config": {"provider": "deepseek-official", "model": "deepseek-flash"}}])
    providers.catalog, real = lambda: [{"id": "anthropic", "name": "A", "env": [], "base": "", "models": [{"id": "m1", "name": "", "context": 0}]}], providers.catalog
    os.environ.update(LLM_PROVIDER="anthropic", LLM_MODEL="m1", LLM_KEY_ANTHROPIC="kk")
    route, pi = providers.overlay()
    check("a catalog provider is routed through pi-ai", route["config"] == {"provider": "anthropic", "model": "m1"} and pi["config"]["providers"]["anthropic"] == {"apiKeyEnv": "SD_LLM_KEY"}, pi)
    check("the key travels in the environment, never in the patch", providers.env() == {"SD_LLM_KEY": "kk"} and "kk" not in json.dumps(agents.overlay()))
    os.environ["LLM_MODEL"] = "brand-new"
    check("a model newer than the catalog can be used", providers.overlay()[1]["config"]["providers"]["anthropic"]["models"] == [{"id": "brand-new"}])
    os.environ.pop("LLM_KEY_ANTHROPIC")
    check("a missing key is said so", "API key" in providers.why_not(), providers.why_not())
    os.environ.update(LLM_PROVIDER="custom", LLM_MODEL="m", LLM_BASE_URL="http://example.com/v1")
    check("a key is never sent over plain http", "https" in providers.why_not())
    os.environ["LLM_BASE_URL"] = "http://127.0.0.1:9/v1"
    p = providers.overlay()[1]["config"]["providers"]["custom"]
    check("an OpenAI-compatible address is enough", not providers.why_not() and p["api"] == "openai-completions" and p["models"] == [{"id": "m"}], p)
    providers.catalog = real
    ids = [p["id"] for p in providers.listing()]
    check("providers have unique ids", len(ids) == len(set(ids)) and "custom" in ids and "ollama" in ids, ids)
    check("each provider's key can be saved", all(config.allowed(p["key_name"]) for p in providers.listing()))
    check("nothing else can be", not config.allowed("PATH") and not config.allowed("LLM_KEY_x") and not config.allowed("NODE_OPTIONS"))
    for k in ("LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL"):
        os.environ.pop(k, None)
    if agents.dsh_home():
        check("the catalog comes from the installed dsh", len(providers.catalog()) > 20, len(providers.catalog()))


def listed_models(tmp) -> None:
    import http.server
    import threading
    seen, routes = [], {}

    class H(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append((self.path.split("?")[0], {k.lower(): v for k, v in self.headers.items()}))
            code, body, *more = routes.get(self.path.split("?")[0], (404, {}))
            self.send_response(code)
            for k, v in more[0].items() if more else ():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(json.dumps(body).encode())

        def log_message(self, *a):
            pass
    srv = [http.server.ThreadingHTTPServer(("127.0.0.1", 0), H) for _ in range(2)]
    for s in srv:
        threading.Thread(target=s.serve_forever, daemon=True).start()
    at, other = (f"http://127.0.0.1:{s.server_port}" for s in srv)
    saved = {k: os.environ.pop(k, None) for k in ("LLM_PROVIDER", "LLM_MODEL", "LLM_BASE_URL", "LLM_KEY_CUSTOM", "LLM_KEY_OPENAI", "OPENAI_API_KEY")}
    os.environ["DEEPSEEK_API_KEY"] = "ds-key"
    real, providers.catalog = providers.catalog, lambda: [{"id": i, "name": i, "env": [e], "base": b, "models": [{"id": "known-1", "name": "Known One", "context": 128000}]} for i, e, b in (
        ("openai", "OPENAI_API_KEY", f"{at}/v1"), ("anthropic", "ANTHROPIC_TEST_KEY", at), ("google", "GEMINI_TEST_KEY", f"{at}/v1beta"), ("odd", "ODD_KEY", f"{at}/anthropic"))]
    ids = lambda r: [m["id"] for m in r.get("models", [])]
    routes["/v1/models"] = (200, {"data": [{"id": "zeta"}, {"id": "known-1"}, {"id": "text-embedding-3"}, {"id": "zeta"}]})
    r = providers.models("openai", key="k1")
    check("the service's own list, sorted, without duplicates or what cannot chat", r["ok"] and ids(r) == ["known-1", "zeta"] and r["hidden"] == 1, r)
    check("what dsh knows about a model is added", r["models"][0]["context"] == 128000 and r["models"][0]["name"] == "Known One")
    check("the key goes in a header, never in the address", seen[-1][1].get("authorization") == "Bearer k1" and "k1" not in seen[-1][0] + r["url"])
    r = providers.models("custom", base=at)
    check("an address without a version is tried with one; a local service needs no key", ids(r) == ["known-1", "zeta"] and seen[-1][0] == "/v1/models" and "authorization" not in seen[-1][1], r)
    routes["/v3/models"], routes["/plain/models"] = (200, {"models": [{"name": "models/gem", "supportedGenerationMethods": ["generateContent"]}, {"name": "models/emb", "supportedGenerationMethods": ["embedContent"]}]}), (200, ["a", "b"])
    check("other versions, shapes and paths", ids(providers.models("custom", base=f"{at}/v3")) == ["gem"] and ids(providers.models("custom", base=f"{at}/plain")) == ["a", "b"])
    r = providers.models("odd", key="k2")
    check("a list that sits beside the address is found", ids(r) == ["known-1", "zeta"] and [p for p, _ in seen[-3:]] == ["/anthropic/v1/models", "/anthropic/models", "/v1/models"], [p for p, _ in seen[-4:]])
    providers.models("anthropic", key="k3")
    check("Anthropic's header", seen[-1][1].get("x-api-key") == "k3" and "authorization" not in seen[-1][1], seen[-1])
    routes["/v1beta/models"] = (200, {"models": [{"name": "models/gemini-x", "supportedGenerationMethods": ["generateContent"]}]})
    check("Google's", ids(providers.models("google", key="k4")) == ["gemini-x"] and seen[-1][1].get("x-goog-api-key") == "k4")

    os.environ["LLM_KEY_OPENAI"] = "stored-key"
    check("a stored key is used for its own address", providers.models("openai")["ok"] and seen[-1][1]["authorization"] == "Bearer stored-key")
    n = len(seen)
    r = providers.models("openai", base=f"{other}/v1")
    check("and is not sent to another one", not r["ok"] and len(seen) == n and "先保存" in r["error"], r)
    os.environ.update(LLM_PROVIDER="openai", LLM_BASE_URL=f"{other}/v1")
    providers.models("openai", base=f"{other}/v1")
    check("unless that address was saved", len(seen) > n and seen[-1][1].get("authorization") == "Bearer stored-key", seen[-1])
    os.environ.pop("LLM_PROVIDER"), os.environ.pop("LLM_BASE_URL")
    routes["/v1/models"] = (302, {}, {"Location": f"{other}/elsewhere"})
    routes["/elsewhere"] = (200, {"data": [{"id": "x"}]})
    providers.models("openai", key="k5")
    check("nor along a redirect to another host", seen[-1][0] == "/elsewhere" and "authorization" not in seen[-1][1], seen[-1])
    routes["/v1/models"] = (401, {})
    n = len(seen)
    r = providers.models("openai", key="bad-key")
    check("a refused key is said so, once, and not repeated back", "401" in r["error"] and len(seen) == n + 1 and "bad-key" not in json.dumps(r, ensure_ascii=False), r)
    routes["/v1/models"] = (200, {"oops": 1})
    check("not a list is said so", "不是模型列表" in providers.models("openai", key="k")["error"])
    routes.pop("/v1/models")
    check("no such endpoint is said so", "404" in providers.models("openai", key="k")["error"])
    check("no key, no address, no plain http, no unknown provider", "先填 API key" in providers.models("anthropic")["error"] and "接口地址" in providers.models("custom")["error"]
          and "https" in providers.models("custom", base="http://example.com/v1")["error"] and "https" in providers.models("custom", base="file:///etc/passwd")["error"] and not providers.models("nope")["ok"])
    check("a key with a line break does not become a header", "换行" in providers.models("openai", key="a\nX: y")["error"])
    import web.server as server
    from fastapi.testclient import TestClient
    web = TestClient(server.app, base_url="http://127.0.0.1:8770")
    check("the endpoint needs the console's token", web.post("/api/llm/models", json={"provider": "custom", "base": at}).status_code == 403)
    routes["/v1/models"] = (200, {"data": [{"id": "m"}]})
    check("and answers with it", web.post("/api/llm/models", json={"provider": "custom", "base": at}, headers={"X-SD-Token": server.TOKEN, "Origin": "http://127.0.0.1:8770"}).json()["models"][0]["id"] == "m")
    providers.catalog = real
    for s in srv:
        s.shutdown()
    os.environ.pop("LLM_KEY_OPENAI")
    os.environ.update({k: v for k, v in saved.items() if v is not None}, DEEPSEEK_API_KEY="k")


def workflow(tmp, dsh) -> None:
    root = app(tmp / "app")
    kinds = [(u["kind"], len(u["items"])) for u in audit.plan(root)]
    check("the plan covers architecture, mapper sinks and every endpoint", kinds[0][0] == "brief" and ("sink", 2) in kinds and ("endpoint", 2) in kinds, kinds)
    dsh.play(brief=ok(BRIEF), sink=ok(SINK), endpoint=ok(ENDP), review=ok(UP))
    r = audit.run(root)
    check("a finished audit is complete", r["ok"] and r["complete"] and r["progress"]["done"] == r["progress"]["total"] == 3, r)
    f = audit.findings(root)
    check("the same sink from two units is one finding", len(f) == 1, [(x["file"], x["line"], x["cwe"]) for x in f])
    check("a finding that survives review is confirmed, with its chain", f[0]["status"] == "confirmed" and f[0]["cwe"] == "CWE-89" and [s["file"] for s in f[0]["trace"]] == [C, I, X], f[0])
    ctx = [x["task"] for x in dsh.log()[0] if x["kind"] == "sink"][0]
    check("later agents start from the brief", "/open/**" in ctx)
    d = audit.load(root)
    check("each endpoint has a verdict", d["endpoints"][f"{C}|GET /open/report/safe"]["verdict"] == "ok" and len(d["endpoints"]) == 2)
    dsh.play()
    check("a finished audit is not repeated", audit.run(root)["worked"] == 0 and not dsh.log()[0])
    s = audit.summary(root)
    check("the project list can tell", s["complete"] and s["confirmed"] == 1, s)
    (pathlib.Path(root) / X).write_text(APP[X].replace("limit", "LIMIT"), encoding="utf-8")
    codeintel._CACHE.clear()
    check("changed code is audited again", audit.progress(root)["left"] == 1, audit.progress(root)["by"]["sink"])
    check("a finding on changed code is not shown as current", audit.findings(root) == [])

    part = app(tmp / "part")
    dsh.play(brief=ok(BRIEF), sink=ok(SINK), review=ok(UP))
    r = audit.run(part, ["sink"])
    check("auditing a part is not auditing the whole", r["complete"] and not audit.summary(part)["complete"] and "1 个单元" in audit.gaps(part)[0], audit.summary(part))
    check("no audit at all is a gap", "没有做 agent 审计" in audit.gaps(str(tmp / "nowhere"))[0])
    import web.server as server
    from fastapi.testclient import TestClient
    pid = projects.add(part)["project"]["id"]
    web = TestClient(server.app, base_url="http://127.0.0.1:8770", headers={"X-SD-Token": server.TOKEN})
    get = lambda fmt, kind="sast": web.get(f"/api/projects/{pid}/export/{kind}/{fmt}")
    md, sa, js = get("md").text, get("sarif").json(), get("json").json()
    check("the report has the agent's findings, chain and gaps", all(x in md for x in ("SQL 注入", f"{X}:5", "agent 复核：uphold", "1 个单元没有完成", "没有做引擎扫描")), md)
    check("so do SARIF and JSON", sa["runs"][0]["results"][0]["ruleId"] == "agent-sink" and not sa["runs"][0]["invocations"][0]["executionSuccessful"]
          and js["complete"] is False and js["findings"][0]["source_tool"] == "agent", js)
    decisions.put(js["findings"][0]["suppress_key"], "false_positive", "x")
    check("a finding a person rejected is not in the report", "SQL 注入" not in get("md").text and get("json").json()["findings"][0]["status"] == "rejected")
    decisions.put(js["findings"][0]["suppress_key"], "")
    check("nothing to export is said so", get("md", "tabby").status_code == 404)

    root = app(tmp / "app2")
    dsh.play(brief=ok(BRIEF), sink=ok(SINK), endpoint=ok({**ENDP, "endpoints": ENDP["endpoints"][:1]}, ENDP), review=ok({**UP, "verdict": "refute"}))
    audit.run(root)
    check("an endpoint left out is sent back", any("这些接口还没有结论" in x for x in dsh.log()[1]), dsh.log()[1])
    f = audit.findings(root)
    check("a refuted finding is kept for a person, not confirmed", len(f) == 1 and f[0]["status"] == "needs_review" and f[0]["review"]["verdict"] == "refute")

    root = app(tmp / "app3")
    bad = {**SINK, "findings": []}
    dsh.play(brief=ok(BRIEF), sink=ok(bad), endpoint=ok(ENDP), review=ok(UP))
    r = audit.run(root)
    check("exploitable without a chain is not accepted", any("没有包含这一行的链" in x for x in dsh.log()[1]), dsh.log()[1])
    noted = {**FIND, "title": "非漏洞，仅记录", "chain": [CHAIN[0], {"role": "sink", "file": X, "line": 8, "quote": "select * from report order by ${sort} limit #{n}"}]}
    quiet = {"endpoints": [{**e, "verdict": "ok"} for e in ENDP["endpoints"]], "findings": [FIND]}
    other = app(tmp / "app5")
    dsh.play(brief=ok(BRIEF), sink=ok({**SINK, "findings": [FIND, noted]}, SINK), endpoint=ok(quiet, {**quiet, "findings": []}), review=ok(UP))
    audit.run(other)
    replies = dsh.log()[1]
    check("a place judged safe cannot also be a finding", any("第 8 行判为 safe" in x for x in replies) and len(audit.findings(other)) == 1, replies)
    check("findings need an endpoint that is not ok", any("所有接口都判为 ok" in x for x in replies), replies)
    codeintel._CACHE.clear()
    check("a unit without an answer is a gap", r["complete"] is False and any("sink" in g for g in r["incomplete_reasons"]), r["incomplete_reasons"])
    dsh.play(brief=ok(BRIEF), sink=ok(SINK), endpoint=ok(ENDP), review=ok(UP))
    check("and is tried again next time", audit.run(root)["worked"] == 1)

    root = app(tmp / "app4")
    for i in range(8):
        (pathlib.Path(root) / f"src/a/C{i}.java").write_text(f'@RestController class C{i} {{\n @GetMapping("/c{i}") X x() {{}}\n}}\n', encoding="utf-8")
    endpoints._CACHE.clear()
    dsh.play(**{"*": {"die": "no quota"}})
    r = audit.run(root, concurrency=1)
    check("a broken setup stops early and says why", r["worked"] <= 5 and "no quota" in r["incomplete_reasons"][0], r)
    dsh.play(brief=ok(BRIEF), **{"*": {}})
    r = audit.run(root, max_units=2, concurrency=1)
    check("the unit limit holds", r["worked"] == 2, r["worked"])
    check("what is left is said so", r["complete"] is False)


def chains_and_cves(tmp, dsh) -> None:
    root = app(tmp / "app")
    rec = {"rule_id": "java-sqli", "message": "断链", "file": C, "line": 7, "status": "needs_review", "reason": "trace 不完整", "severity": "high", "cwe": "CWE-89",
           "trace": [{"kind": "source", "file": C, "line": 7, "text": "sort"}], "source_tool": "opengrep", "evidence_level": "none"}
    rec["suppress_key"] = audit._key(rec, root)
    real, projects.findings = projects.findings, lambda p, k, run="": (decisions.apply(r := [dict(rec)]) and r or r) if k == "sast" else []
    check("a broken trace is a unit", [u["kind"] for u in audit.plan(root, ["chain"])] == ["brief", "chain"])
    dsh.play(brief=ok(BRIEF), chain=ok({"verdict": "completed", "reason": "接到 XML", "chain": CHAIN[:1]}, {"verdict": "completed", "reason": "接到 XML", "chain": CHAIN}), review=ok(UP))
    audit.run(root, ["chain"])
    got = projects.findings(root, "sast")[0]
    check("a one-step chain is not complete", any("至少 2 跳" in x for x in dsh.log()[1]))
    check("a completed and reviewed chain is confirmed, with the full trace", got["status"] == "confirmed" and len(got["trace"]) == 3 and got["trace"][-1]["file"] == X, got)
    review.FILE.unlink()
    dsh.play(chain=ok({"verdict": "dead", "reason": "白名单", "evidence": EV}))
    audit._update(root, lambda d: d["units"].clear())
    audit._update(root, lambda d: d.update(brief=BRIEF))
    audit.run(root, ["chain"])
    check("a dead end lowers it, with evidence", projects.findings(root, "sast")[0]["review"]["verdict"] == "refute")
    projects.findings = real

    kept = [{"cve": c, "dependency": "lib", "group": "g", "version": "1", "cvss": 9.8, "percentile": .9, "cwes": ["CWE-502"], "family": "deserialization",
             "summary": "s", "usage": "used", "usage_evidence": []} for c in ("CVE-2020-0001", "CVE-2020-0002")]
    projects.save_artifact(root, "triage", {"ok": True, "kept": kept, "ignored": []})
    one = {"cve": "CVE-2020-0001", "verdict": "reachable", "reason": "r", "vulnerable_api": "readObject", "chain": CHAIN}
    two = {"cve": "CVE-2020-0002", "verdict": "not_reachable", "reason": "没有用到", "evidence": []}
    dsh.play(brief=ok(BRIEF), dependency=ok({"cves": [one]}, {"cves": [{**one, "chain": []}, two]}, {"cves": [one, two]}), review=ok(UP))
    audit.run(root, ["dependency"])
    replies = dsh.log()[1]
    check("every CVE needs an answer, reachable needs a chain", any("CVE-2020-0002" in x and "还没有结论" in x for x in replies) and any("链核对不上" in x for x in replies), replies)
    reach = audit.load(root)["reach"]
    check("each CVE gets its own reachability", reach["CVE-2020-0001|g|1"]["verdict"] == "reachable" and reach["CVE-2020-0002|g|1"]["verdict"] == "not_reachable", reach)
    check("a reachable CVE is a finding with its chain", any(f["rule_id"] == "agent-dependency" and f["trace"] for f in audit.findings(root)))
    projects.save_artifact(root, "triage", {"ok": True, "kept": [{**k, "version": "2"} for k in kept], "ignored": []})
    check("until the project turns out to use another version", not any(f["rule_id"] == "agent-dependency" for f in audit.findings(root)))


def reviews(tmp, dsh) -> None:
    src = tmp / "app"
    src.mkdir()
    (src / "A.java").write_text('import javax.servlet.http.*;import java.sql.*;\nclass A { Object f(HttpServletRequest r, Statement st) throws Exception {\n'
                                '  String q = "s" + r.getParameter("n");\n  return st.executeQuery(q);\n} }\n', encoding="utf-8")
    ev = [{"file": "A.java", "line": 4, "quote": "return st.executeQuery(q);"}]
    pipeline.scan(str(src))
    recs = pipeline.last_findings(str(src))
    dsh.play(review=ok({"verdict": "refute", "reason": "r", "evidence": ev}))
    out = review.run(recs, str(src))
    check("a refute lowers, never removes", out["refuted"] == 1 and recs[0]["status"] == "needs_review", out)
    check("a review survives a rescan", pipeline.scan(str(src))["status_counts"]["needs_review"] == 1)
    check("it is not reviewed twice", not review.pending(pipeline.last_findings(str(src))))
    recs = pipeline.last_findings(str(src))
    decisions.put(recs[0]["suppress_key"], "confirmed", "seen")
    decisions.apply(recs)
    check("a person outranks the reviewer", recs[0]["status"] == "confirmed")
    decisions.put(recs[0]["suppress_key"], "")
    decisions.apply(recs)
    check("clearing the decision brings the review back", recs[0]["status"] == "needs_review")
    review.FILE.unlink()
    decisions.apply(recs)
    check("without a review the engine's verdict returns", recs[0]["status"] == "confirmed" and "review" not in recs[0])
    (src / "A.java").write_text((src / "A.java").read_text(encoding="utf-8") + "// x\n", encoding="utf-8")
    for i in range(6):
        (src / f"B{i}.java").write_text((src / "A.java").read_text(encoding="utf-8").replace("class A", f"class B{i}"), encoding="utf-8")
    pipeline.scan(str(src))
    recs = pipeline.last_findings(str(src))
    dsh.play(review={"die": "no"})
    out = review.run(recs, str(src))
    check("after three failures the rest is not tried", len(dsh.log()[0]) == 3 and out["unavailable"] == 7, out)
    check("failed reviews change nothing", all(r["status"] == "confirmed" for r in recs))
    os.environ["REVIEW_MAX"] = "2"
    dsh.play(review=ok({"verdict": "uphold", "reason": "r", "evidence": ev}))
    r = pipeline.scan(str(src), verify=True)
    check("the cap is a gap", r["verification"]["skipped"] == 5 and any("未复核" in g for g in r["incomplete_reasons"]), r["incomplete_reasons"])
    os.environ.pop("REVIEW_MAX")

    c = toolset.review_candidates(str(src))
    key = c["candidates"][0]["key"]
    rec = lambda **k: toolset.review_record(str(src), [{"key": key, "verdict": "refute", "reason": "r", "evidence": ev, **k}])
    check("a host agent gets keys and instructions", c["total"] == 5 and "推翻" in c["instructions"], c["total"])
    check("unknown keys and junk are refused", not rec(key="x")["ok"] and not toolset.review_record(str(src), ["x", None])["ok"])
    check("an invented quote is stored as uncertain", rec(evidence=[{**ev[0], "quote": "safe();"}])["recorded"][0]["verdict"] == "uncertain")

    root = app(tmp / "host")
    n = toolset.audit_next(root, 5)
    unit = next(u for u in n["units"] if u["kind"] == "sink")
    check("a host agent can take units", unit["answer_schema"] and "order by" in unit["task"], n["remaining"])
    check("its answers meet the same checks", not toolset.audit_submit(root, unit["id"], {**SINK, "findings": []})["ok"]
          and not toolset.audit_submit(root, "nope", SINK)["ok"] and not toolset.audit_submit(root, unit["id"], "x")["ok"])
    dsh.play(review=ok(UP))
    check("and are filed and reviewed", toolset.audit_submit(root, unit["id"], SINK)["findings"] == 1 and audit.findings(root)[0]["status"] == "confirmed")
    check("a filed unit is gone from the queue", unit["id"] not in [u["id"] for u in toolset.audit_next(root, 9)["units"]])


ALL = list(audit.ORDER)
ONE = {"title": "报表", "boundary": "匿名不能注入", "paths": ["src/a", X], "classes": ["Injection", "Wildcard"], "companions": ["CLIENT-SIDE"], "why": "二阶"}
TWO = {"title": "服务", "boundary": "b", "paths": [I], "classes": ["Business logic"], "why": "w"}
REST = [{"class": c, "reason": "不适用"} for c in hunt.classes() if c not in ("Injection", "Wildcard", "Business logic")]
COV = lambda *cs, **st: [{"class": c, "status": st.get(c.split()[0], "covered"), "paths": ["src/a"], "checked": "查了参数到 ORDER BY 的每一跳"} for c in cs]


def open_round(tmp, dsh) -> None:
    check("attack classes come from the skill, with its licence", len(hunt.classes()) == 9 and "Business logic" in hunt.classes() and (hunt.REF / "LICENSE").read_text(encoding="utf-8").startswith("MIT"))
    root = app(tmp / "app")
    everything = {"brief": ok(BRIEF), "sink": ok(SINK), "endpoint": ok(ENDP), "review": ok(UP), "rules": ok({"sast": [], "secrets": [], "sca": [], "reason": "没有自己的封装"})}
    bad_map = {"areas": [{**ONE, "paths": ["no/such"]}], "excluded": REST}
    hole = {"areas": [ONE], "excluded": REST}
    other = {**FIND, "title": "越权", "cwe": "CWE-639", "chain": [CHAIN[0], {"role": "sink", "file": I, "line": 4, "quote": "reportMapper.listSorted(sort.trim())"}]}
    dsh.play(**everything, map=ok(bad_map, hole, {"areas": [ONE, TWO], "excluded": REST}),
             hunt=ok({"findings": [], "coverage": COV("Injection")}, {"findings": [], "coverage": COV("Injection", "Wildcard", "Business logic", Injection="finding")},
                     {"findings": [other], "coverage": COV("Injection", "Wildcard", "Business logic")},
                     {"findings": [other], "coverage": COV("Injection", "Wildcard", "Business logic", Injection="finding", Business="finding"), "uncovered": [{"title": "定时任务", "why": "y"}]}),
             critic=ok({"areas": [], "reason": ""}, {"areas": [{**TWO, "title": "补充"}], "reason": "核对了入口"}))
    r = audit.run(root)
    runs, replies = dsh.log()
    order = [x["kind"] for x in runs if x["kind"] not in ("review", "rules")]
    full = [x["kind"] for x in runs]
    check("rules are written before the map, and again at the end", full.count("rules") == 2 and full.index("rules") < full.index("map") and full[-1] == "rules", full)
    check("the open round follows the leads, and the critic follows the hunters", r["ok"] and order.index("map") > max(order.index("sink"), order.index("endpoint"))
          and order.count("hunt") == 3 and order.index("critic") == len(order) - 2 and order[-1] == "hunt", order)
    check("a map needs real paths and every class placed or excluded", any("路径不存在" in x for x in replies) and any("既没有分配" in x for x in replies), replies)
    check("a hunter answers for every class it was given", any("还没有覆盖记录" in x for x in replies) and any("findings 是空的" in x for x in replies) and any("没有攻击类写 finding" in x for x in replies), replies)
    check("a critic says what it checked", any("缺少 reason" in x for x in replies))
    check("the whole audit is complete", r["complete"] and audit.summary(root)["complete"], r["incomplete_reasons"])
    f = [x for x in audit.findings(root) if x["rule_id"] == "agent-hunt"]
    check("what it finds is reviewed like everything else", len(f) == 1 and f[0]["status"] == "confirmed" and f[0]["cwe"] == "CWE-639", f)
    p = audit.progress(root)
    check("the coverage map is kept", [(a["title"], a["wave"], len(a.get("rows") or [])) for a in p["areas"]] == [("报表", 1, 2), ("服务", 1, 1), ("补充", 2, 1)] and p["excluded"], p["areas"])
    hunts = [x for x in runs if x["kind"] == "hunt"]
    check("a hunter gets its blocks, the brief, and what is already known", all(s in hunts[0]["task"] + hunts[1]["task"] for s in ("/open/**", "sd_opengrep", "Core discipline", "Read code that looks boring")))
    check("and may delegate; the others may not", all("tool-subagent" not in {q["id"] for q in h["patch"] if q.get("disabled")} for h in hunts)
          and all("tool-subagent" in {q["id"] for q in h["patch"] if q.get("disabled")} for h in runs if h["kind"] != "hunt"))
    again = {**audit._record({**FIND, "title": "换个说法", "cwe": "CWE-203", "conditions": "", "fix": ""}, "hunt", root)}
    n = len(audit.findings(root))
    check("the same flaw under another CWE is not a second finding", not audit._claim(root, again) and len(audit.findings(root)) == n and any(x.get("also") == ["换个说法"] for x in audit.findings(root)))
    check("who may call it is", audit._claim(root, {**again, "cwe": "CWE-862", "message": "未授权"}))
    audit._update(root, lambda d: d["findings"].pop())
    dsh.play()
    check("a finished round is not repeated", audit.run(root)["worked"] == 0)
    (pathlib.Path(root) / I).write_text(APP[I] + "// changed\n", encoding="utf-8")
    codeintel._CACHE.clear()
    endpoints._CACHE.clear()
    left = [u["kind"] for u in audit.plan(root) if audit.load(root)["units"].get(u["id"], {}).get("state") != "done"]
    check("changed code is hunted again, the map stays", left.count("hunt") == 3 and "map" not in left, left)
    put = pathlib.Path(root) / "src/a/New.java"
    put.write_text("class New {}", encoding="utf-8")
    codeintel._CACHE.clear()
    check("new files make a new map", "map" in [u["kind"] for u in audit.plan(root)] and not [u for u in audit.plan(root) if u["kind"] == "hunt"])

    root = app(tmp / "small")
    dsh.play(**everything, map=ok({"areas": [ONE, TWO], "excluded": REST}), hunt=ok({"findings": [], "coverage": COV("Injection", "Wildcard", "Business logic")}), critic=ok({"areas": [], "reason": "都查了"}))
    r = audit.run(root, max_units=5, concurrency=1)
    check("the unit limit covers the open round too", r["worked"] == 5 and r["complete"] is False and "critic" not in [x["kind"] for x in dsh.log()[0]], r["worked"])
    audit.run(root)
    check("and it goes on from there", audit.summary(root)["complete"], audit.progress(root)["by"])
    root = app(tmp / "off")
    dsh.play(**everything)
    audit.run(root, ["sink", "endpoint"])
    check("it can be left out", not {"rules", "map", "hunt", "critic"} & {x["kind"] for x in dsh.log()[0]})
    root = app(tmp / "nomap")
    dsh.play(**everything, map={})
    r = audit.run(root)
    check("without a map there is no hunt, and that is a gap", "hunt" not in [x["kind"] for x in dsh.log()[0]] and any("覆盖规划" in g for g in r["incomplete_reasons"]), r["incomplete_reasons"])

    rule = {"languages": ["java"], "pattern": "$X.safeSorted(...)"}
    out = agent_tool.sd_opengrep(root, rule)
    check("an agent can run a rule of its own", out.startswith("1 处") and f"{I}:5" in out, out)
    taint = {"languages": ["java"], "mode": "taint", "pattern-sources": [{"patterns": [{"pattern-inside": "$T $M(..., @RequestParam String $P, ...) { ... }"}, {"focus-metavariable": "$P"}]}], "pattern-sinks": [{"pattern": "reportService.list(...)"}]}
    check("taint rules too, inside one path", C in agent_tool.sd_opengrep(root, taint, "src/a"), agent_tool.sd_opengrep(root, taint, "src/a"))
    for name, r in (("a validator that could call out", {**rule, "validators": [{"http": {}}]}), ("a fix", {**rule, "fix": "x"}), ("not an object", "rules: []")):
        try:
            agent_tool.sd_opengrep(root, r)
            check(f"{name} is refused", False)
        except ValueError:
            check(f"{name} is refused", True)
    try:
        agent_tool.sd_opengrep(root, rule, "../..")
        check("a path outside is refused", False)
    except ValueError:
        check("a path outside is refused", True)
    check("a broken rule is said so", agent_tool.sd_opengrep(root, {"languages": ["java"], "pattern": "((("}).startswith("错误"))
    check("what is known can be listed", "agent-" in agent_tool.sd_findings(root, "agent"))
    check("no call graph is said so", "没有字节码调用图" in agent_tool.sd_callgraph(root, "a.b"))


SRC = {"patterns": [{"pattern-inside": "$RT $M(..., @RequestParam String $P, ...) { ... }"}, {"focus-metavariable": "$P"}]}
GOOD_RULE = {"id": "report-mapper-sort", "title": "排序参数进入 ReportMapper", "why": "模仿 java-sqli，项目自己的 Mapper", "cwe": "CWE-89", "severity": "high",
             "rule": {"languages": ["java"], "mode": "taint", "options": {"interfile": True}, "pattern-sources": [SRC], "pattern-sinks": [{"pattern": "reportMapper.$F(...)"}],
                      "pattern-sanitizers": [{"pattern": "COLS.contains(...)"}]},
             "samples": {"lang": "java", "bad": "class S { Object f(@RequestParam String s) { return reportMapper.listSorted(s); } }", "good": "class S { Object f(@RequestParam String s) { return reportMapper.listSorted(\"id\"); } }"}}
CORP = "corp_" + "a1b2c3d4e5f6"
GOOD_SECRET = {"id": "corp-token", "title": "内部系统令牌", "why": f"项目里的令牌都是 corp_ 开头，如 {CORP}", "cwe": "CWE-798", "severity": "high", "regex": "(corp_[a-z0-9]{12})", "group": 1,
               "samples": {"bad": ["x = corp_" + "zzzzzzzzzzzz"], "good": ["corp_home page"]}}
GOOD_SCA = {"id": "vendored-jquery", "title": "直接放进来的 jQuery", "why": "不在依赖树里", "type": "component", "product": "jquery", "path": "web/js/jquery-{version}.js"}


def written_rules(tmp, dsh) -> None:
    root = app(tmp / "app")
    for k, v in {"conf/x.txt": f"t = {CORP}\n", "web/js/jquery-1.11.0.js": "// jq\n", "web/js/jquery-ui.js": "x"}.items():
        (pathlib.Path(root) / k).parent.mkdir(parents=True, exist_ok=True)
        (pathlib.Path(root) / k).write_text(v, encoding="utf-8")
    ask = lambda **k: airules.check({"sast": [], "secrets": [], "sca": [], "reason": "r", **k}, root)
    value, why = ask(sast=[GOOD_RULE], secrets=[GOOD_SECRET], sca=[GOOD_SCA])
    check("rules of all three kinds are accepted", value and [(r["kind"], r["hits"]) for r in value["rules"]] == [("sast", 2), ("secrets", 1), ("sca", 1)], (why, value))
    check("samples are not kept, they may hold values", "samples" not in json.dumps(value))
    no = lambda want, **k: check(f"refused: {want}", ask(**k)[0] is None and want in ask(**k)[1], ask(**k)[1])
    no("没有命中 bad", sast=[{**GOOD_RULE, "samples": {**GOOD_RULE["samples"], "bad": "class S {}"}}])
    no("误报了 good", sast=[{**GOOD_RULE, "samples": {**GOOD_RULE["samples"], "good": GOOD_RULE["samples"]["bad"]}}])
    no("不支持这些键", sast=[{**GOOD_RULE, "rule": {**GOOD_RULE["rule"], "validators": []}}])
    no("只能用", sast=[{**GOOD_RULE, "rule": {**GOOD_RULE["rule"], "languages": ["generic"]}}])
    no("引擎加载或解析不了", sast=[{**GOOD_RULE, "rule": {"languages": ["java"], "pattern": "((("}}])
    no("缺少 why", sast=[{**GOOD_RULE, "why": ""}])
    no("CWE-数字", sast=[{**GOOD_RULE, "cwe": "SQLi"}])
    no("没有命中 bad", secrets=[{**GOOD_SECRET, "samples": {"bad": ["nothing"], "good": ["x"]}}])
    no("误报了 good", secrets=[{**GOOD_SECRET, "samples": {**GOOD_SECRET["samples"], "good": GOOD_SECRET["samples"]["bad"]}}])
    no("gitleaks 不接受", secrets=[{**GOOD_SECRET, "regex": "(?=corp_)corp_[a-z0-9]{12}"}])
    no("一个也没找到", sca=[{**GOOD_SCA, "path": "lib/nope-{version}.jar"}])
    no("{version}", sca=[{**GOOD_SCA, "path": "web/js/*.js"}])
    no("没有结论的依赖", sca=[{**GOOD_SCA, "type": "alias", "dependency": "nope"}])
    no("id 重复", secrets=[GOOD_SECRET], sast=[{**GOOD_RULE, "id": GOOD_SECRET["id"]}])
    check("a reason is due even for nothing", airules.check({"sast": []}, root)[0] is None and ask()[0] is not None)
    keep, airules.MAX_HITS = airules.MAX_HITS, 0
    no("太宽", sast=[GOOD_RULE])
    no("太宽", secrets=[GOOD_SECRET])
    airules.MAX_HITS = keep
    began = time.time()
    ask(secrets=[{**GOOD_SECRET, "regex": "(corp_([a-z]+)+[a-z0-9]{12}$)"}])
    (pathlib.Path(root) / "conf/evil.txt").write_text("corp_" + "a" * 60000 + "!\n", encoding="utf-8")
    ask(secrets=[{**GOOD_SECRET, "regex": "(corp_(?:[a-z0-9]+)+)"}], sca=[{**GOOD_SCA, "path": "**/**/**/*-{version}.js"}])
    check("a hostile file cannot hang them", time.time() - began < 60, time.time() - began)
    (pathlib.Path(root) / "conf/evil.txt").unlink()

    from core import hardcoded, nvd, sca
    real = nvd._resolve_vendors, nvd.lookup, sca.run_opensca, sca_triage.epss.scores
    asked = []
    nvd._resolve_vendors = lambda p, g="": ["v"] if p == "real_product" else []
    nvd.lookup = lambda k, v=None, group="": (asked.append(k), {"ok": True, "cached": True, "affected": [{"id": "CVE-2020-11022", "score": 6.1, "cwes": [], "summary": "", "cpes": [], "matched_version": True}] if k == "jquery" else [],
                                                                 **({"error": "查不到"} if k == "weird-lib" else {})})[-1]
    sca.run_opensca = lambda root, timeout_s=0: {"ok": True, "components": [{"vendor": "g", "name": "weird-lib", "version": "1.2", "language": "Java", "direct": True, "paths": []}]}
    sca_triage.epss.scores = lambda ids: {}
    projects.save_artifact(root, "triage", toolset.sca_triage_scan(root))
    no("CPE 字典里没有", sca=[{**GOOD_SCA, "type": "alias", "dependency": "weird-lib", "product": "made_up"}])
    alias = {**GOOD_SCA, "id": "weird-alias", "type": "alias", "dependency": "weird-lib", "product": "real_product"}
    check("an alias needs an unresolved dependency and a real product", ask(sca=[alias])[0], ask(sca=[alias]))

    dsh.play(brief=ok(BRIEF), rules=ok({"sast": [GOOD_RULE], "secrets": [GOOD_SECRET], "sca": [GOOD_SCA], "reason": "补空白"}),
             chain=ok({"items": [{"id": "H1", "verdict": "completed", "reason": "接到 XML", "chain": CHAIN}]},
                      {"items": [{"id": f"H{i}", "verdict": "completed", "reason": "接到 XML", "chain": CHAIN} for i in (1, 2)]}),
             review={"answers": [UP, {"items": [{"id": f"R{i}", **UP} for i in (1, 2)]}]}, map={},
             secret=ok({"items": [{"id": f"S{i}", "verdict": "real", "reason": "r", "what": "内部系统", "severity": "high", "evidence": [{"file": "conf/x.txt", "line": 1, "quote": "t = corp"}]} for i in range(1, 9)]}),
             dependency=ok({"cves": [{"cve": "CVE-2020-11022", "verdict": "not_reachable", "reason": "没有引用"}]}))
    asked.clear()
    r = audit.run(root, ["hunt"])
    kinds = [x["kind"] for x in dsh.log()[0]]
    check("the agent is shown what to imitate", any("languages: [java]" in x["task"] and "ReportController.list" in x["task"] or "规则样式" in x["task"] for x in dsh.log()[0] if x["kind"] == "rules"))
    note = next(u.get("note") or u["error"] for u in audit.load(root)["units"].values() if u["kind"] == "rules")
    check("the engines run again with them", "SAST 1 · 硬编码 1 · SCA 1" in note and "源码新规则命中 2" in note and "硬编码新规则命中 1" in note, note)
    sast = [x for x in projects.findings(root, "sast") if x["rule_id"] == "ai-report-mapper-sort"]
    check("a hit is a lead, then an agent and a reviewer", kinds.index("chain") > kinds.index("rules") and sast and sast[0]["status"] == "confirmed" and sast[0]["review"]["chain"], sast)
    check("never confirmed by the rule itself", sast[0]["base"]["status"] == "needs_review", sast[0]["base"])
    check("secrets too, masked", any(x["rule_id"] == "ai-corp-token" and x["engine"] == "ai" and x["status"] == "confirmed" for x in projects.findings(root, "secrets"))
          and CORP not in json.dumps(projects.findings(root, "secrets")) + json.dumps(airules.load(root)) + json.dumps(audit.load(root)), projects.findings(root, "secrets"))
    airules.save(root, ask(sca=[alias])[0]["rules"], 3)
    tri = toolset.sca_triage_scan(root)
    check("vendored components go to NVD, which decides", any(k["cve"] == "CVE-2020-11022" and k["dependency"] == "jquery" and k["version"] == "1.11.0" for k in tri["kept"]), tri["kept"])
    check("an alias is looked up, and finding nothing under it is not a clean bill", "real_product" in asked and any("real_product" in u["reason"] for u in tri["unresolved"]), (asked, tri["unresolved"]))
    check("and what they brought in is worked on, though only the open round was asked for", {"chain", "secret", "dependency"} <= set(kinds) and not {"sink", "endpoint"} & set(kinds), kinds)
    check("the rules stay for the next scan", toolset.auto_scan(root)["ok"] and any(x["rule_id"] == "ai-report-mapper-sort" for x in pipeline.last_findings(root)))
    check("they are listed", {x["id"] for x in audit.progress(root)["rules"]} == {"ai-report-mapper-sort", "ai-corp-token", "ai-vendored-jquery", "ai-weird-alias"})
    check("and can be taken out", airules.remove(root, "ai-report-mapper-sort")["ok"] and not airules.files(root) and not airules.remove(root, "nope")["ok"])
    other = app(tmp / "other")
    check("another project does not get them", not airules.load(other) and not airules.files(other) and not airules.components(other))
    dsh.play(brief=ok(BRIEF), rules=ok({"sast": [GOOD_RULE], "secrets": [], "sca": [], "reason": "r"}), map={})
    scan, toolset.auto_scan = toolset.auto_scan, lambda p, *a: {"ok": False, "error": "boom"}
    r = audit.run(other, ["hunt"], max_units=2)
    toolset.auto_scan = scan
    check("a round that failed is a gap", any("boom" in g for g in r["incomplete_reasons"]) and any("boom" in g for g in audit.gaps(other)), r["incomplete_reasons"])
    nvd._resolve_vendors, nvd.lookup, sca.run_opensca, sca_triage.epss.scores = real


def background(tmp, dsh) -> None:
    tasks.FILE = tmp / "tasks.json"
    root = app(tmp / "app")
    p = projects.add(root)["project"]
    m = tasks.Manager()
    order, real = [], dict(tasks._RUN)
    tasks._RUN["sast"] = lambda *a: (time.sleep(0.6), order.append("sast"), {"ok": True, "complete": True})[-1]
    tasks._RUN["audit"] = lambda *a: (order.append("audit"), {"ok": True, "complete": True, "incomplete_reasons": [], "worked": 0, "progress": {}, "status_counts": {}})[-1]

    def until(kind, limit=30):
        end = time.time() + limit
        while time.time() < end:
            t = next((t for t in m.list() if t["kind"] == kind), {})
            if t.get("state") not in (None, *tasks.LIVE):
                return t
            time.sleep(0.05)
        return t
    m.submit(p, "sast")
    m.submit(p, "audit")
    check("the audit waits for the engines", until("audit")["state"] == "done" and order == ["sast", "audit"], order)
    tasks._RUN["sast"] = lambda *a: (time.sleep(0.6), {"ok": False, "error": "x"})[-1]
    m.clear()
    order.clear()
    m.submit(p, "sast")
    m.submit(p, "audit")
    check("and still runs when an engine fails", until("audit")["state"] == "done")
    m.clear()
    m.submit(p, "sast")
    t = m.submit(p, "audit")["task"]["id"]
    m.cancel(t)
    until("sast")
    time.sleep(0.3)
    check("a waiting audit can be cancelled", m.get(t)["state"] == "cancelled" and order == ["audit"], (m.get(t), order))
    tasks._RUN.update(real)
    m.clear()
    dsh.play(**{"*": {"sleep": 60}})
    t = m.submit(p, "audit")["task"]["id"]
    time.sleep(2.5)
    began = time.time()
    m.cancel(t)
    check("cancelling an audit ends its sessions", until("audit", 20)["state"] == "cancelled" and time.time() - began < 15, m.get(t))
    check("a cancelled unit is not recorded as done", not [u for u in audit.load(root)["units"].values() if u["state"] == "done"])


def main() -> int:
    saved = dict(os.environ)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        dsh = Dsh(tmp)
        for fn in (navigation, tools, guard, citations, models, listed_models, sessions, workflow, chains_and_cves, reviews, background, open_round, written_rules):
            audit.ORDER[:] = ALL if fn in (open_round, written_rules) else [k for k in ALL if k not in hunt.KINDS]
            print(f"-- {fn.__name__}")
            mine = tmp / fn.__name__
            mine.mkdir()
            projects.STORE, pipeline.SCANS_DIR, rulegen.OUT_DIR = mine / "store", mine / "scans", mine / "rules"
            review.FILE, decisions.FILE = mine / "r.json", mine / "d.json"
            fn(mine, *([dsh] if fn.__code__.co_argcount == 2 else []))
        dsh.close()
        os.environ.clear()
        os.environ.update(saved)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
