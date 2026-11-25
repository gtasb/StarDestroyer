"""Conversations about a project, with a stand-in that speaks the agent protocol."""

import json
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import _env  # noqa: F401
from core import agents, chat, config, decisions, pipeline, projects, review, rulegen

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:600]}"))
    if not ok:
        FAILED.append(name)


# Answers depend on the question, so each test can say what it wants to happen.
FAKE = r'''import json, os, sys, threading, time, pathlib
sys.stdout.reconfigure(encoding="utf-8"); sys.stderr.reconfigure(encoding="utf-8"); sys.stdin.reconfigure(encoding="utf-8")
log = open(os.environ["FAKE_LOG"], "a", encoding="utf-8")
lock = threading.Lock()
def note(**k):
    with lock: log.write(json.dumps(k, ensure_ascii=False) + "\n"); log.flush()
def send(m):
    with lock: sys.stdout.write(json.dumps({"jsonrpc": "2.0", **m}, ensure_ascii=False) + "\n"); sys.stdout.flush()
def up(s, **u): send({"method": "session/update", "params": {"sessionId": s, "update": u}})
def say(s, k, d=""): sys.stderr.write("\x1eSD" + json.dumps({"s": s, "k": k, "d": d}) + "\n"); sys.stderr.flush(); time.sleep(.03)
cancelled = set()
OPTS = [{"id": "model", "name": "Model", "type": "select", "currentValue": "m1", "options": [{"group": "g", "options": [{"value": "m1", "name": "M1"}, {"value": "m2", "name": "M2"}]}]}, {"id": "flag", "type": "boolean"}]
note(start=True, argv=sys.argv[1:], cwd=os.getcwd(), mode=os.environ.get("DSH_PERMISSION_MODE"), root=os.environ.get("SD_AUDIT_ROOT"), access=os.environ.get("SD_ACCESS"), spec=json.load(open(os.environ["SD_SPEC"], encoding="utf-8")),
     patch=json.load(open(sys.argv[sys.argv.index("--patch") + 1], encoding="utf-8")))
if os.environ.get("FAKE_DEAD"): sys.stderr.write("no such provider\n"); sys.exit(1)
print("not json")
def prompt(i, p):
    s, text = p["sessionId"], "\n".join(x["text"] for x in p["prompt"])
    note(prompt=text, session=s, parts=len(p["prompt"]))
    q = text.split("\n")[-1]
    if q == "die": os._exit(3)
    if q == "limit": return send({"id": i, "result": {"stopReason": "max_tokens"}})
    if q == "fail": return send({"id": i, "error": {"code": -32000, "message": "quota exceeded"}})
    say(s, "start"); say(s, "think", "hm"); say(s, "text", "dra")
    if q == "retry": say(s, "start"); say(s, "think", "again")
    if q == "hang":
        while s not in cancelled: time.sleep(.02)
        return send({"id": i, "result": {"stopReason": "cancelled"}})
    if q == "deaf": time.sleep(60)
    say(s, "text", "ft")
    up(s, sessionUpdate="agent_thought_chunk", content={"type": "text", "text": "hm hm"})
    up(s, sessionUpdate="tool_call", toolCallId="t1", title="read", rawInput={"file_path": "a.py"}, status="pending")
    if q == "ask": send({"id": 900, "method": "session/request_permission", "params": {"sessionId": s}})
    up(s, sessionUpdate="tool_call_update", toolCallId="t1", status="completed", content=[{"type": "content", "content": {"type": "text", "text": "x = 1"}}])
    up("other", sessionUpdate="agent_message_chunk", content={"type": "text", "text": "LEAK"})
    up(s, sessionUpdate="agent_message_chunk", content={"type": "text", "text": "answer to " + q})
    up(s, sessionUpdate="usage_update", used=50, size=200)
    send({"id": i, "result": {"stopReason": "end_turn"}})
n = 0
for line in sys.stdin:
    m = json.loads(line); i, p, what = m.get("id"), m.get("params") or {}, m.get("method")
    if what != "session/prompt": note(call=what or "reply", params=p, result=m.get("result"))
    if what == "initialize": send({"id": i, "result": {}})
    elif what == "session/new":
        n += 1; send({"id": i, "result": {"sessionId": f"S{os.getpid()}-{n}", "configOptions": OPTS}})
    elif what == "session/resume":
        send({"id": i, "error": {"code": 1, "message": "gone"}} if os.environ.get("FAKE_GONE") else {"id": i, "result": {"configOptions": OPTS}})
    elif what == "session/set_config_option": send({"id": i, "result": {}})
    elif what == "session/cancel": cancelled.add(p["sessionId"])
    elif what == "session/prompt": threading.Thread(target=prompt, args=(i, p), daemon=True).start()
'''


class World:
    def __init__(self, tmp: pathlib.Path):
        self.log, script = tmp / "log", tmp / "fake.py"
        script.write_text(FAKE, encoding="utf-8")
        os.environ.update(FAKE_LOG=str(self.log), DSH_BIN=str(script), DEEPSEEK_API_KEY="k", LLM_PROVIDER="", LLM_MODEL="")
        agents.acp_command = lambda patch: [sys.executable, "-X", "utf8", "-u", str(script), "--profile", "acp", "--patch", patch]
        d = tmp / "app"
        d.mkdir()
        (d / "a.py").write_text("x = 1\n", encoding="utf-8")
        self.p = projects.add(str(d))["project"]
        self.pid = self.p["id"]

    def rows(self, key):
        return [r for r in (json.loads(x) for x in self.log.read_text(encoding="utf-8").splitlines()) if key in r]

    def calls(self, name):
        return [r for r in self.rows("call") if r["call"] == name]

    def ask(self, cid, text, refs=None):
        r = chat.send(self.p, cid, text, refs)
        if not r["ok"]:
            return r
        return self.end(cid)

    def end(self, cid, limit=20):
        end = time.time() + limit
        while (self.pid, cid) in chat._turns and time.time() < end:
            time.sleep(0.02)
        return chat.get(self.pid, cid)["messages"][-1]


def answers(tmp) -> None:
    w = World(tmp)
    cid = chat.create(w.pid)["id"]
    m = w.ask(cid, "first question")
    check("an answer with its thinking, tools and text, in order", [p["type"] for p in m["parts"]] == ["think", "text", "tool"] and m["state"] == "done", m)
    check("what was streamed is replaced by what was said in the end", m["parts"][0]["text"] == "hm hm" and m["parts"][1]["text"] == "answer to first question" and not any(p.get("live") for p in m["parts"]), m)
    check("a tool call keeps its input and output", m["parts"][2] == {"type": "tool", "id": "t1", "name": "read", "input": {"file_path": "a.py"}, "status": "completed", "output": "x = 1"}, m["parts"][2])
    check("another session's text does not end up here", "LEAK" not in json.dumps(m))
    c = chat.get(w.pid, cid)
    check("the conversation is named after the question", c["title"] == "first question" and c["context"] == {"used": 50, "size": 200}, c)
    check("the model can be chosen; what is not a choice is left out", [o["id"] for o in c["options"]] == ["model"] and [x["value"] for x in c["options"][0]["choices"]] == ["m1", "m2"], c["options"])
    s = w.rows("start")[0]
    check("the session cannot ask for more, and runs apart from the project", s["mode"] == "workspace-write" and pathlib.Path(s["cwd"]) != pathlib.Path(w.p["path"]) and pathlib.Path(s["root"]) == pathlib.Path(w.p["path"]), s)
    check("it gets the audit's tools and guard, and nothing to submit", s["spec"]["chat"] and s["spec"]["engines"] and s["patch"][-2]["insert"][0]["name"] == agents.PLUGIN.as_posix(), s["patch"][-2:])
    first = w.rows("prompt")[0]
    check("the first question comes with the project", "app" in first["prompt"] and "不可信数据" in first["prompt"] and first["prompt"].endswith("first question"), first)
    w.ask(cid, "second")
    second = w.rows("prompt")[1]
    check("later ones do not, in the same session and process", second["prompt"] == "second" and second["session"] == first["session"] and len(w.rows("start")) == 1, second)
    other = chat.create(w.pid)["id"]
    w.ask(other, "third")
    check("another conversation has its own session in that process", w.rows("prompt")[2]["session"] != first["session"] and len(w.rows("start")) == 1)
    w.ask(cid, "ask")
    check("a request for wider permissions is turned down", any(r["result"] == {"outcome": {"outcome": "cancelled"}} for r in w.calls("reply")), w.calls("reply"))
    m = w.ask(cid, "retry")
    check("a new attempt voids what the broken one wrote", "dra" not in json.dumps(m["parts"]) and len([p for p in m["parts"] if p["type"] == "think"]) == 1, m["parts"])
    check("an option that does not exist is refused", not chat.set_option(w.pid, cid, "model", "m9")["ok"] and not chat.set_option(w.pid, cid, "x", "m1")["ok"])
    chat.set_option(w.pid, cid, "model", "m2")
    w.ask(cid, "with m2")
    sets = [r["params"] for r in w.calls("session/set_config_option")]
    check("a chosen model is set before the next question", sets and sets[-1]["configId"] == "model" and sets[-1]["value"] == "m2", sets)
    n = len(sets)
    w.ask(cid, "once more")
    check("shown as chosen, and told once", chat.get(w.pid, cid)["options"][0]["value"] == "m2" and len(w.calls("session/set_config_option")) == n, (n, len(w.calls("session/set_config_option"))))
    check("empty and endless questions are refused", not chat.send(w.p, cid, "  ")["ok"] and not chat.send(w.p, cid, "x" * 30000)["ok"])
    key = os.environ.pop("DEEPSEEK_API_KEY")
    check("without a model it is said so", "key" in chat.send(w.p, cid, "x")["error"].lower(), chat.send(w.p, cid, "x"))
    os.environ["DEEPSEEK_API_KEY"] = key


def stream(tmp) -> None:
    w = World(tmp)
    cid = chat.create(w.pid)["id"]
    chat.send(w.p, cid, "hang")
    seq, parts, over, seen = 0, [], False, []

    def drain():
        nonlocal seq, over
        d = chat.events(w.pid, cid, seq, 2)
        for e in d["events"]:
            seen.append(e["op"])
            if e["op"] == "add":
                parts.append(dict(e["part"]))
            elif e["op"] == "append":
                parts[e["i"]]["text"] += e["d"]
            elif e["op"] == "set":
                parts[e["i"]] = e["part"]
            elif e["op"] == "cut":
                del parts[e["n"]:]
        seq, over = d["seq"], d["over"]
    end = time.time() + 20
    while not any(p.get("text") == "dra" for p in parts) and time.time() < end:
        drain()
    check("the text arrives while it is being written", [p.get("text") for p in parts] == ["hm", "dra"] and not over, parts)
    live = chat.get(w.pid, cid)["live"]
    check("who comes later sees the same", [p["text"] for p in live["parts"]] == ["hm", "dra"] and live["seq"] == seq, live)
    chat._turns[(w.pid, cid)]._kept = 0
    chat._turns[(w.pid, cid)].say("x")
    stored = chat._load(w.pid, cid)["messages"][-1]
    check("what is there so far survives a crash of the console, and is not shown twice", [p["text"] for p in stored["parts"]] == ["hm", "dra"] and stored["state"] == "running"
          and chat.get(w.pid, cid)["messages"][-1]["parts"] == [], stored)
    seq += 1
    check("one question at a time", "还在回答" in chat.send(w.p, cid, "x")["error"])
    check("the list shows it is busy", chat.listing(w.pid)[0]["running"])
    got = []
    t = threading.Thread(target=lambda: got.append((time.time(), chat.events(w.pid, cid, seq, 20))))
    t.start()
    time.sleep(0.3)
    began = time.time()
    chat.stop(w.pid, cid)
    t.join(10)
    check("a waiting reader hears at once", got and got[0][0] - began < 2, got)
    m = w.end(cid)
    check("stopping keeps what was written", m["state"] == "stopped" and [p["text"] for p in m["parts"]] == ["hm", "dra"], m)
    check("afterwards there is nothing to wait for", chat.events(w.pid, cid, 0, 5)["over"])
    m = w.ask(cid, "go on")
    check("and the conversation goes on in the same session", m["state"] == "done" and len({r["session"] for r in w.rows("prompt")}) == 1, m)
    chat.send(w.p, cid, "hang")
    end = time.time() + 10
    while not chat._turns[(w.pid, cid)].session and time.time() < end:
        time.sleep(0.01)
    time.sleep(0.2)
    chat.delete(w.pid, cid)
    end = time.time() + 10
    while (w.pid, cid) in chat._turns and time.time() < end:
        time.sleep(0.02)
    check("deleting one in the middle of an answer", chat.get(w.pid, cid) is None and not chat.listing(w.pid) and (w.pid, cid) not in chat._turns)


def trouble(tmp) -> None:
    w = World(tmp)
    cid = chat.create(w.pid)["id"]
    m = w.ask(cid, "fail")
    check("what the model's service says is passed on", m["state"] == "error" and "quota exceeded" in m["error"], m)
    check("a limit is named", "输出上限" in w.ask(cid, "limit")["error"])
    m = w.ask(cid, "die")
    check("a dsh that dies is an error", m["state"] == "error" and "dsh" in m["error"], m)
    m = w.ask(cid, "back")
    check("the next question starts it again and takes the session up", m["state"] == "done" and len(w.rows("start")) == 2 and len(w.calls("session/resume")) == 1 and w.rows("prompt")[-1]["prompt"] == "back", m)
    chat.shutdown()
    os.environ["FAKE_GONE"] = "1"
    m = w.ask(cid, "lost")
    check("a session that is gone is begun again, with what was said", m["state"] == "done" and m["parts"][0]["type"] == "note" and "之前的对话" in w.rows("prompt")[-1]["prompt"] and "answer to back" in w.rows("prompt")[-1]["prompt"], (m, w.rows("prompt")[-1]["prompt"][-400:]))
    check("the question itself is not in there twice", w.rows("prompt")[-1]["prompt"].count("lost") == 1, w.rows("prompt")[-1]["prompt"][-300:])
    os.environ.pop("FAKE_GONE")
    n = len(w.rows("start"))
    os.environ["DEEPSEEK_API_KEY"] = "k2"
    w.ask(cid, "new key")
    check("another key, model or access means another process", len(w.rows("start")) == n + 1)
    os.environ["AUDIT_ACCESS"] = "readonly"
    w.ask(cid, "read only")
    check("read-only is dsh's too", w.rows("start")[-1]["mode"] == "read-only" and w.rows("start")[-1]["access"] == "readonly")
    os.environ.pop("AUDIT_ACCESS")
    chat.shutdown()
    os.environ["FAKE_DEAD"] = "1"
    m = w.ask(cid, "x")
    check("a dsh that does not start says why", m["state"] == "error" and "no such provider" in m["error"], m)
    os.environ.pop("FAKE_DEAD")
    chat._change(w.pid, cid, lambda c: c["messages"].append({"role": "agent", "parts": [], "state": "running", "at": "", "seconds": 0}))
    check("an answer the console's restart cut off is shown as such", chat.get(w.pid, cid)["messages"][-1]["state"] == "interrupted")
    for bad in ("../../x", "0123456789a", "ABCDEF0123", "", "..\\..\\xx"):
        try:
            chat.get(w.pid, bad)
            check(f"no such conversation {bad!r}", False)
        except KeyError:
            check(f"no such conversation {bad!r}", True)
    w.ask(cid, "alive")
    d = chat._dshs[w.pid]
    d.used = 0
    chat._sweep()
    check("a process nobody talks to is closed", w.pid not in chat._dshs and d.proc.wait(10) is not None)
    w.ask(cid, "alive again")
    d = chat._dshs[w.pid]
    work = d.work
    chat.send(w.p, cid, "hang")
    time.sleep(0.6)
    projects.remove(w.pid)
    time.sleep(0.5)
    check("removing the project ends its process and its conversations", d.proc.wait(10) is not None and not work.exists() and not (projects.STORE / w.pid).exists(), list(projects.STORE.rglob("*")))


def about(tmp) -> None:
    w = World(tmp)
    cid = chat.create(w.pid)["id"]
    real = projects.findings
    rec = {"suppress_key": "k1", "rule_id": "r", "message": "SQL 注入", "severity": "high", "status": "confirmed", "file": "a.py", "line": 1, "trace": []}
    projects.findings = lambda root, kind, run="": [rec] if kind == "sast" else []
    w.ask(cid, "why", ["k1", "nope"])
    p = w.rows("prompt")[-1]["prompt"]
    check("a question about a finding carries it", "用户引用的发现" in p and "a.py" in p and p.endswith("why"), p[-500:])
    check("the conversation shows which", [r["key"] for r in chat.get(w.pid, cid)["messages"][0]["refs"]] == ["k1"])
    check("known findings are in the first message", "SQL 注入 a.py:1" in p)
    projects.findings = real


def plugin(tmp) -> None:
    node = shutil.which("node")
    if not node:
        return check("node is available", False)
    root = tmp / "app"
    root.mkdir()
    (root / "a.py").write_text("x", encoding="utf-8")
    (tmp / "spec.json").write_text(json.dumps({"type": "chat", "chat": True, "engines": True, "subagents": 2, "schema": {}}), encoding="utf-8")
    js = tmp / "t.mjs"
    js.write_text("""const m = await import(process.argv[2]); let g; const tools = {}, on = {};
m.apply({ tools: { guard: f => { g = f }, register: t => { tools[t.name] = t } }, on: (n, f) => { (on[n] ??= []).push(f) } });
const go = (name, args, agent = { id: 'A', options: {} }) => g({ name, arguments: args, agent }) === undefined;
const r = { names: Object.keys(tools), sub: [go('subagent', {}), go('subagent', {}), go('subagent', {}), go('subagent', {}, { id: 'B', options: {} })] };
for (const f of on['session/event'] ?? []) f({ id: 'A' }, { type: 'turn/start' });
r.again = go('subagent', {});
r.kid = go('subagent', {}, { id: 'K', options: { subagentDepth: 1 } });
r.read = [go('read', { file_path: process.argv[3] }), go('read', { file_path: process.argv[4] }), go('write', { file_path: process.argv[3] }), go('web_fetch', { url: 'x' }), go('sd_review_verdict', {}), go('sd_findings', {}), go('pwsh', { command: 'x' }), go('pwsh', { command: 'x', sandbox_permissions: 'danger-full-access' })];
const say = on['agent/assistant-stream'];
for (const f of say ?? []) {
  f({ agent: { id: 'A', options: {} }, frame: { type: 'start' } });
  f({ agent: { id: 'A', options: {} }, frame: { type: 'chunk', chunk: { type: 'text-delta', text: 'a\\nb' } } });
  f({ agent: { id: 'K', options: { subagentDepth: 1 } }, frame: { type: 'chunk', chunk: { type: 'text-delta', text: 'kid' } } });
  f({ agent: { id: 'A', options: {} }, frame: { type: 'chunk', chunk: { type: 'reasoning-delta', text: 'h' } } });
}
console.log(JSON.stringify(r));
""", encoding="utf-8")
    r = subprocess.run([node, str(js), agents.PLUGIN.as_uri(), str(root / "a.py"), str(tmp / "spec.json")], capture_output=True, text=True, encoding="utf-8",
                       env={**os.environ, "SD_AUDIT_ROOT": str(root), "SD_SPEC": str(tmp / "spec.json"), "SD_STREAM": "1", "SD_ACCESS": "shell"})
    try:
        out = json.loads(r.stdout)
    except ValueError:
        return check("the plugin loads for a conversation", False, r.stderr)
    check("a conversation has nothing to submit, and the engines", "sd_submit" not in out["names"] and {"sd_findings", "sd_opengrep", "sd_symbol"} <= set(out["names"]), out["names"])
    check("helpers are counted per conversation and question", out["sub"] == [True, True, False, True] and out["again"], out)
    check("helpers have none of their own", not out["kid"])
    check("it reads the project, runs commands in the sandbox, and nothing else", out["read"] == [True, False, False, False, False, True, True, False], out["read"])
    said = [json.loads(x[3:]) for x in r.stderr.split(chr(10)) if x.startswith(chat.MARK)]
    check("only its own words are streamed", said == [{"s": "A", "k": "start"}, {"s": "A", "k": "text", "d": "a\nb"}, {"s": "A", "k": "think", "d": "h"}], said)


def api(tmp) -> None:
    from fastapi.testclient import TestClient
    import web.server as server
    w = World(tmp)
    head = {"X-SD-Token": server.TOKEN, "Origin": "http://127.0.0.1:8770"}
    web = TestClient(server.app, base_url="http://127.0.0.1:8770")
    base = f"/api/projects/{w.pid}/chats"
    check("every call needs the console's token", all(web.request(m, base + p, json={}).status_code == 403 for m, p in (("GET", ""), ("POST", ""), ("GET", "/0123456789"), ("POST", "/0123456789/send"), ("GET", "/0123456789/events"),
                                                                                                                  ("POST", "/0123456789/delete"), ("PATCH", "/0123456789"))))
    web.headers.update(head)
    c = web.post(base).json()["chat"]
    check("a conversation is made and listed", [x["id"] for x in web.get(base).json()["chats"]] == [c["id"]] and web.get(base).json()["ready"])
    check("renamed", web.patch(f"{base}/{c['id']}", json={"title": "  a  b "}).json()["ok"] and web.get(f"{base}/{c['id']}").json()["chat"]["title"] == "a b" and not web.patch(f"{base}/{c['id']}", json={"title": " "}).json()["ok"])
    check("asked", web.post(f"{base}/{c['id']}/send", json={"text": "hello"}).json()["ok"])
    seq, over, n = 0, False, 0
    while not over and n < 60:
        d = web.get(f"{base}/{c['id']}/events?since={seq}").json()
        seq, over, n = d["seq"], d["over"], n + 1
    check("followed to the end", over and web.get(f"{base}/{c['id']}").json()["chat"]["messages"][-1]["state"] == "done")
    check("unknown ones are refused, not guessed", not web.get(f"{base}/..%2f..%2fx").is_success or not web.get(f"{base}/..%2f..%2fx").json()["ok"])
    check("so are unknown projects", not web.post("/api/projects/nope/chats").json()["ok"] and not web.post(f"/api/projects/nope/chats/{c['id']}/send", json={"text": "x"}).json()["ok"])
    check("and a conversation is found only under its own project", not web.get(f"/api/projects/ffffffffffff/chats/{c['id']}").json()["ok"])
    check("deleted", web.post(f"{base}/{c['id']}/delete").json()["ok"] and not web.get(f"{base}/{c['id']}").json()["ok"])


def main() -> int:
    saved, real = dict(os.environ), agents.acp_command
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        for fn in (answers, stream, trouble, about, plugin, api):
            print(f"-- {fn.__name__}")
            mine = pathlib.Path(d) / fn.__name__
            mine.mkdir()
            projects.STORE, pipeline.SCANS_DIR, rulegen.OUT_DIR = mine / "store", mine / "scans", mine / "rules"
            review.FILE, decisions.FILE = mine / "r.json", mine / "d.json"
            fn(mine)
            chat.shutdown()
    agents.acp_command = real
    os.environ.clear()
    os.environ.update(saved)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
