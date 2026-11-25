"""Tools the dsh audit plugin calls. One process per call: args on stdin, text out.

The project root and the task come from the environment the session was started
with; nothing the model says can point these tools somewhere else.
"""

import os
import sys

# This directory holds modules named like the standard library's (logging, profile).
sys.path[0] = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

import json  # noqa: E402
import pathlib  # noqa: E402
import re  # noqa: E402

from core import agents, codeintel, endpoints  # noqa: E402

LIMIT = 16_000


def sd_symbol(root: str, name: str) -> str:
    s = codeintel.index(root).symbol(name)
    out = [f"{t['kind']} {t['name']} {t['file']}:{t['start']}-{t['end']}" + (f" 继承/实现 {', '.join(t['supers'])}" if t["supers"] else "")
           for t in s["types"]]
    out += [f"方法 {m['owner']}.{m['name']}({m['params']}) {m['file']}:{m['start']}-{m['end']}"
            + ("" if m["body"] else "（无方法体，用 sd_implementations 找实现，或在 Mapper XML 里）") for m in s["methods"]]
    out += [f"MyBatis {x['kind']} {x['namespace'].rsplit('.', 1)[-1]}.{x['id']} {x['file']}:{x['start']}-{x['end']}"
            + (f" 含 {len(x['raw'])} 处 ${{}}" if x["raw"] else "") for x in s["statements"]]
    return "\n".join(out) or "没有找到定义（可能在依赖里，或名字不对）"


def sd_callers(root: str, method: str, owner: str = "") -> str:
    rows = codeintel.index(root).callers(method, owner)
    if not rows:
        return "没有找到调用点" + ("；去掉 owner 再试一次可以放宽范围" if owner else "")
    out = [f"{r['file']}:{r['line']} 在 {r['in'] or '类体'}: {r['code']}" for r in rows]
    if rows[0].get("unrelated_skipped"):
        out.append(f"（另有 {rows[0]['unrelated_skipped']} 处同名调用所在文件没有提到 {owner}，已略去）")
    if rows[-1].get("truncated"):
        out.append("（调用点过多，已截断，请加 owner）")
    return "\n".join(out)


def sd_implementations(root: str, name: str) -> str:
    return "\n".join(f"{t['kind']} {t['name']} {t['file']}:{t['start']}-{t['end']}"
                     for t in codeintel.index(root).implementations(name)) or "没有找到实现"


def sd_method(root: str, file: str, line: int) -> str:
    agents.inside(root, file)
    m = codeintel.index(root).method_source(str(file).replace("\\", "/"), int(line))
    return f"{m['owner']}.{m['name']} {m['file']}:{m['first']}-{m['end']}\n{m['source']}" if m else "这一行不在任何方法里，用 read 读"


def sd_endpoints(root: str, filter: str = "") -> str:
    rows = [e for e in endpoints.cached(root)
            if not filter or filter.lower() in f"{e['path']} {e['file']} {' '.join(e['features'])}".lower()]
    more = f"\n（共 {len(rows)} 个，已截断，请加 filter）" if len(rows) > 150 else ""
    return ("\n".join(f"{e['method']} {e['path']} {e['file']}:{e['line']}" for e in rows[:150]) + more) or "没有匹配的接口"


def sd_sinks(root: str, **kw) -> str:
    cls = kw.get("class", "")
    rows = codeintel.sink_sites(root, {cls} if cls else None)
    return "\n".join(f"[{s['class']}] {s['file']}:{s['line']} {s['in']}: {s['code']}" for s in rows[:200]) or "没有"


def sd_advisory(root: str, cve: str) -> str:
    # The only thing that leaves here is a CVE number, never text from the source.
    if not re.fullmatch(r"CVE-\d{4}-\d{4,7}|GHSA(-[0-9a-z]{4}){3}|GO-\d{4}-\d+|PYSEC-\d{4}-\d+", str(cve)):
        raise ValueError("需要 CVE 或 GHSA 编号")
    from core import config, intel, nvd, osv
    config.apply()
    out = [x for x in (nvd.known(cve), osv.known(cve)) if x] or ["本地缓存里没有摘要"]
    if intel.available():
        out += [f"- {x['title']} {x['url']}\n  {x['content'][:700]}" for x in intel.n_day_context(cve).get("results", [])[:4]]
    return "\n".join(out)


# ---- engines, for the open round ------------------------------------------------
def sd_findings(root: str, engine: str = "", filter: str = "") -> str:
    from core import projects
    out = []
    kinds = ["sast", "secrets", "tabby", "agent"]
    for k in ([engine] if engine in kinds else kinds):
        for r in projects.findings(root, k):
            line = f"[{k}/{r['status']}/{r.get('severity') or ''}] {r['rule_id']} {r['file']}:{r['line']} {r['message'][:100]}"
            if not filter or filter.lower() in line.lower():
                out.append(line)
    return "\n".join(out[:200]) + (f"\n（共 {len(out)} 条，已截断，请加 filter）" if len(out) > 200 else "") or "没有"


def sd_opengrep(root: str, rule, path: str = "") -> str:
    from core import airules
    target = str(agents.inside(root, path)) if path else str(agents.base_of(root))
    res = airules.run_sast([airules.only_matching(rule)], target)
    if not res["ok"] and not res["findings"]:
        return f"错误：{res['error']}"
    base, out = agents.base_of(root), []
    for x in res["findings"]:
        chain = " → ".join(f"{_rel(s['file'], base)}:{s['line']}" for s in x["trace"][:8])
        out.append(f"{_rel(x['file'], base)}:{x['line']}" + (f"  链 {chain}" if chain else ""))
    out = list(dict.fromkeys(out))
    return f"{len(out)} 处\n" + "\n".join(out[:100]) + ("\n（已截断，把规则收窄）" if len(out) > 100 else "") + ("" if res["ok"] else f"\n（引擎没有完整跑完：{res['error']}）")


def _rel(path: str, base: pathlib.Path) -> str:
    try:
        return pathlib.Path(path).resolve().relative_to(base).as_posix()
    except ValueError:
        return path


def sd_callgraph(root: str, method: str, direction: str = "callers", to: str = "", depth: int = 3) -> str:
    from core import graph, projects, store
    art = projects.load_artifact(root, "tabby") or {}
    work = pathlib.Path(art.get("workdir") or "")
    if not art.get("workdir") or not (work / "cpg.db").exists():
        return "没有字节码调用图（没有编译产物，或还没跑调用链），用 sd_callers / read"
    n = max(1, min(int(depth or 3), 8))

    def where(v, text):
        cls, _, name = text.rpartition(".")
        return f"{v}.name = ${v}n" + (f" AND ({v}.cls = ${v}c OR {v}.cls ENDS WITH ${v}d)" if cls else ""), {f"{v}n": name, **({f"{v}c": cls, f"{v}d": "." + cls.rsplit(".", 1)[-1]} if cls else {})}
    a, pa = where("a", method)
    if direction == "path":
        if not to:
            return "错误：path 需要 to"
        b, pb = where("b", to)
        q = f"MATCH p=(a:Method)-[:CALL|ALIAS* SHORTEST 1..{max(n, 8)}]->(b:Method) WHERE {a} AND {b} RETURN p LIMIT 5"
    elif direction in ("callers", "callees"):
        q, pb = (f"MATCH p=(b:Method)-[:CALL|ALIAS* SHORTEST 1..{n}]->(a:Method) WHERE {a} RETURN DISTINCT b.cls AS cls, b.name AS name, length(p) AS d ORDER BY d LIMIT 80"
                 if direction == "callers" else
                 f"MATCH p=(a:Method)-[:CALL|ALIAS* SHORTEST 1..{n}]->(b:Method) WHERE {a} RETURN DISTINCT b.cls AS cls, b.name AS name, length(p) AS d ORDER BY d LIMIT 80"), {}
    else:
        raise ValueError("direction 应为 callers / callees / path")
    with store.lock(work / "graph.json"):  # the store takes one process at a time
        conn = graph.open_db(str(work / "cpg.db"))
        try:
            rows = graph.query(conn, q, {**pa, **pb})
            if direction == "path":
                return "\n".join(" → ".join(s["text"] for s in graph.render_path({"p": r["p"]})) for r in rows) or "没有路径"
        finally:
            graph.close(conn)
    return "\n".join(f"{r['d']} 跳 {r['cls']}.{r['name']}" for r in rows) or "没有（名字不对，或图里没有这个方法）"


def sd_deps(root: str, filter: str = "") -> str:
    from core import audit, projects
    tri = projects.load_artifact(root, "triage") or {}
    reach, out = audit.load(root)["reach"], []
    for r in tri.get("kept", []):
        v = reach.get(f"{r['cve']}|{r.get('group') or r['dependency']}|{r['version']}") or {}
        line = f"{r['dependency']} {r['version']} {r['cve']} CVSS {r.get('cvss')} {v.get('verdict') or '未判断'} {(r.get('summary') or '')[:120]}"
        if not filter or filter.lower() in line.lower():
            out.append(line)
    return "\n".join(out[:120]) or "没有（或还没跑依赖筛选）"


def sd_submit(root: str, **answer) -> str:
    spec = json.loads(pathlib.Path(os.environ["SD_SPEC"]).read_text(encoding="utf-8"))
    value, why = agents.build(spec).validate(answer)
    if value is None:
        return f"未通过核对，请修正后重新提交：\n{why}"
    pathlib.Path(os.environ["SD_RESULT"]).write_text(json.dumps(answer, ensure_ascii=False), encoding="utf-8")
    return "已接受。任务完成，直接结束，不要再做别的。"


TOOLS = {f.__name__: f for f in (sd_symbol, sd_callers, sd_implementations, sd_method, sd_endpoints, sd_sinks,
                                 sd_advisory, sd_findings, sd_opengrep, sd_callgraph, sd_deps, sd_submit)}


def main() -> int:
    try:
        args = json.loads(sys.stdin.buffer.read().decode("utf-8") or "{}")
        out = TOOLS[sys.argv[1]](os.environ["SD_AUDIT_ROOT"], **args)
    except (ValueError, TypeError, KeyError, OSError) as exc:
        out = f"错误：{exc}"
    sys.stdout.buffer.write((out if len(out) <= LIMIT else out[:LIMIT] + "\n（已截断）").encode("utf-8"))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
