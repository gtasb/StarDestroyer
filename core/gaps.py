"""What the engines could not do, and an agent that does it instead.

Every reason an engine gives for being incomplete becomes work with an owner: a limit on
how far calls are followed is covered by the units that trace from sinks and broken
chains; files it could not read are read; dependencies nobody could resolve are resolved;
anything else is handed over as it stands. A gap closes when that work is done.
"""

import pathlib

from . import agents, airules, nvd, projects, review, store

DEPS_PER_UNIT, FILES_PER_UNIT = 15, 5
ENGINES = {"sast": "源码扫描", "secrets": "硬编码扫描", "triage": "依赖筛选", "tabby": "调用链"}
S = {"type": "string"}


def _obj(required, **props):
    return {"type": "object", "required": required, "properties": props}


# ---- decisions about dependencies -------------------------------------------------
def _file(root: str) -> pathlib.Path:
    return projects.STORE / projects.project_id(root) / "deps.json"


def decisions(root: str) -> dict:
    return {"deps": {}, "components": [], **store.read(_file(root), {})}


def key(c: dict) -> str:
    return f"{(c.get('vendor') or '').lower()}:{c['name'].lower()}@{c.get('version') or ''}"


def save(root: str, deps: dict, components: list[dict]) -> None:
    with store.update(_file(root), {}) as d:
        d.setdefault("deps", {}).update(deps)
        have = {(c["name"], c["version"]) for c in d.setdefault("components", [])}
        d["components"] += [c for c in components if (c["name"], c["version"]) not in have]


# ---- what is missing ----------------------------------------------------------------
def found(root: str) -> list[dict]:
    """[{engine, type, text, items, run}] of the latest runs. type: depth | files | deps | alert."""
    out, latest = [], projects.latest(root)
    for engine in ENGINES:
        art = projects.load_artifact(root, engine)
        if not art:
            continue
        run = pathlib.Path((latest.get(engine) or {}).get("file") or "").name
        seen = set()
        for text in art.get("incomplete_reasons") or []:
            if "interfile search stopped" in text or "跨文件分析到达深度上限" in text:
                kind, items = "depth", []
            elif engine == "sast" and ("源文件引擎未扫描" in text or "源文件解析失败" in text):
                led = store.read(pathlib.Path((art.get("artifacts") or {}).get("ledger_json") or "none"), {})
                kind, items = "files", sorted({*(led.get("files_unscanned") or []), *(led.get("files_failed") or {})})
            elif engine == "triage" and "个依赖没有查到结论" in text:
                kind, items = "deps", [u for u in art.get("unresolved") or [] if not u.get("asked")]  # an agent has been asked once
            else:
                kind, items = "alert", []
            if kind == "depth" and kind in seen:
                for g in out:  # one line per rule, one limit
                    if g["engine"] == engine and g["type"] == "depth":
                        g["texts"].append(text)
                continue
            seen.add(kind)
            out.append({"engine": engine, "type": kind, "text": text, "texts": [text], "items": items, "run": run})
    return out


def units(root: str) -> list[dict]:
    """{title, items, files, gap} for the plan."""
    out = []
    for g in found(root):
        label = ENGINES[g["engine"]]
        if g["type"] == "deps":
            for i in range(0, len(g["items"]), DEPS_PER_UNIT):
                part = g["items"][i:i + DEPS_PER_UNIT]
                out.append({"title": f"{label}：{len(part)} 个没有结论的依赖（{part[0]['name']} 等）", "items": [key(u) for u in part], "files": [],
                            "gap": {"engine": g["engine"], "type": "deps", "text": g["text"], "items": part}})
        elif g["type"] == "files":
            for i in range(0, len(g["items"]), FILES_PER_UNIT):
                part = g["items"][i:i + FILES_PER_UNIT]
                out.append({"title": f"{label}：引擎没扫到的 {len(part)} 个文件（{part[0]} 等）", "items": part, "files": part,
                            "gap": {"engine": g["engine"], "type": "files", "text": g["text"], "items": part}})
        elif g["type"] == "alert":
            out.append({"title": f"{label}：{g['text'][:60]}", "items": [g["text"][:300]], "files": [], "gap": {**g, "texts": []}})
    return out


def states(root: str, plan: list[dict], done) -> list[dict]:
    """Each gap with who covers it and how far that is."""
    out = []
    for g in found(root):
        if g["type"] == "depth":
            mine = [u for u in plan if u["kind"] in ("chain", "sink")]
            how = "从 sink 反向追、断链续追，不受层数限制"
        else:
            mine = [u for u in plan if u["kind"] == "gap" and u["gap"]["engine"] == g["engine"] and u["gap"]["type"] == g["type"] and (g["type"] != "alert" or u["gap"]["text"] == g["text"])]
            how = {"deps": "逐个依赖查版本、产品名和是否打进制品", "files": "逐个文件通读", "alert": "按告警内容补查"}[g["type"]]
        n = sum(done(u) for u in mine)
        left = sum(bool(u.get("asked")) for u in (projects.load_artifact(root, "triage") or {}).get("unresolved") or []) if g["type"] == "deps" else 0
        out.append({"kind": g["engine"], "type": g["type"], "text": g["text"][:300], "more": len(g["texts"]) - 1, "run": g["run"], "how": how, "done": n, "total": len(mine),
                    "closed": not left and n == len(mine) and (bool(mine) or g["type"] == "depth"), "left": left})
    return out


# ---- the agent's side -----------------------------------------------------------------
_HEAD = "引擎没能做完的事，由你补上。先读下面引擎的原话，弄清它漏了什么，再用读码、导航、引擎工具（有 shell 时也可以用命令行）把漏的部分查完。\n"


def task(u: dict, root: str, ctx: str, findings, findings_schema: dict) -> agents.Task:
    g, base = u["gap"], agents.base_of(root)

    if g["type"] == "deps":
        ids = {f"D{i}": d for i, d in enumerate(g["items"], 1)}

        def check(raw):
            got, errors = {}, []
            for x in raw.get("items") if isinstance(raw.get("items"), list) else []:
                if not isinstance(x, dict) or x.get("id") not in ids or x.get("verdict") not in ("version", "alias", "not_shipped", "unknown"):
                    continue
                i, v = x["id"], x["verdict"]
                good, bad = agents.verify(x.get("evidence"), root)
                if not str(x.get("reason") or "").strip():
                    errors.append(f"{i} 缺少 reason")
                if v in ("version", "not_shipped") and not good:
                    errors.append(f"{i} 判为 {v}，需要能核对的 evidence：" + "；".join(bad[:3]))
                if v == "version":
                    ver = str(x.get("version") or "")
                    if not nvd.comparable(ver):
                        errors.append(f"{i} 的 version 不是具体版本：{ver!r}")
                    elif good and not any(ver in e["quote"] for e in good):
                        errors.append(f"{i} 的 evidence 里要有写着 {ver} 的那一行")
                if v == "alias" and not (isinstance(x.get("product"), str) and 2 <= len(x["product"]) <= 60):
                    errors.append(f"{i} 判为 alias，需要 product（NVD CPE 里的产品名）")
                got[i] = {"verdict": v, "version": str(x.get("version") or ""), "product": str(x.get("product") or "").strip().lower(), "reason": str(x.get("reason") or "")[:400], "evidence": good[:4]}
            if missing := [i for i in ids if i not in got]:
                errors.append(f"这些还没有结论：{missing}")
            return (None, "\n".join(errors[:12])) if errors else ({"items": got}, "")
        return agents.Task("gap", _HEAD + """对**每个**依赖给出：
- version：版本没解析出来，你在 pom / BOM / 属性 / 锁文件 / lib 目录里查到了（evidence 引用写着版本的那一行）
- alias：有版本但漏洞库里找不到这个名字，你知道它在 NVD 的产品名（program 会去查，不存在就不算数）；同一产品的子模块填主产品名
- not_shipped：不会进运行制品（test / provided 作用域、仅构建用、只是 API 声明没有实现），evidence 引用作用域或声明处
- unknown：查过仍不清楚，写清查了哪里
不要自己编 CVE；受不受影响由漏洞库判断。""", f"{ctx}\n\n引擎的原话：{g['text']}\n\n依赖：\n" + "\n".join(f"- {i} {d.get('vendor') or ''}:{d['name']} 版本 {d.get('version') or '（空）'}：{d['reason']}" for i, d in ids.items()),
                           _obj(["items"], items={"type": "array", "items": _obj(["id", "verdict", "reason"], id=S, reason=S, version=S, product=S,
                                verdict={"type": "string", "enum": ["version", "alias", "not_shipped", "unknown"]}, evidence=review.EVIDENCE)}), check)

    if g["type"] == "files":
        def check(raw):
            found_, why = findings(raw.get("findings"), root)
            if why:
                return None, why
            rows = {r["file"]: {"verdict": r["verdict"], "note": str(r.get("note") or "")[:400]} for r in raw.get("files") or []
                    if isinstance(r, dict) and r.get("file") in g["items"] and r.get("verdict") in ("covered", "finding", "unclear")}
            missing = [f for f in g["items"] if f not in rows]
            if missing:
                return None, f"这些文件还没有结论：{missing}"
            if short := [f for f, r in rows.items() if len(r["note"]) < 8]:
                return None, f"note 要写清这个文件做什么、查了哪些输入和危险操作：{short}"
            if any(r["verdict"] == "finding" for r in rows.values()) != bool(found_):
                return None, "files 里标了 finding 的和 findings 对不上"
            return {"files": rows, "findings": found_}, ""
        return agents.Task("gap", _HEAD + "下面这些文件引擎没有扫到或解析失败。逐个通读，按审计员的标准查：外部输入从哪来、到了哪些危险操作、鉴权和业务逻辑。", f"{ctx}\n\n引擎的原话：{g['text']}\n\n文件：\n" + "\n".join(f"- {f}" for f in g["items"]),
                           _obj(["files", "findings"], files={"type": "array", "items": _obj(["file", "verdict", "note"], file=S, note=S, verdict={"type": "string", "enum": ["covered", "finding", "unclear"]})},
                                findings=findings_schema), check)

    def check(raw):
        found_, why = findings(raw.get("findings"), root)
        if why:
            return None, why
        if raw.get("verdict") not in ("covered", "unclear") or len(str(raw.get("checked") or "").strip()) < 20:
            return None, "需要 verdict(covered|unclear)，以及 checked：补查了什么、看了哪里、结论是什么"
        paths = [p for p in raw.get("paths") or [] if isinstance(p, str) and _there(base, p)]
        if raw["verdict"] == "covered" and not paths:
            return None, "covered 要给出实际查过的 paths"
        parts, errors = [], []
        for i, c in enumerate(raw.get("components") if isinstance(raw.get("components"), list) else []):
            good, bad = agents.verify(c.get("evidence") if isinstance(c, dict) else None, root)
            if not isinstance(c, dict) or not c.get("name") or not nvd.comparable(str(c.get("version") or "")) or not any(str(c["version"]) in e["quote"] for e in good):
                errors.append(f"components[{i}] 要有 name、具体 version，和写着这个版本的 evidence：" + "；".join(bad[:2]))
            else:
                parts.append({"vendor": str(c.get("group") or ""), "name": str(c["name"]), "version": str(c["version"]), "language": str(c.get("language") or ""), "direct": False, "paths": [good[0]["file"]], "found_by": "agent"})
        if errors:
            return None, "\n".join(errors[:8])
        return {"verdict": raw["verdict"], "checked": str(raw["checked"])[:800], "paths": paths[:30], "findings": found_, "components": parts[:300]}, ""
    return agents.Task("gap", _HEAD + "补查完后：发现漏洞就放 findings；依赖树没解析全的，把你从锁文件、lib 目录、构建文件里确认的组件放 components（程序会去查漏洞库）。补不了的部分如实写 unclear。",
                       f"{ctx}\n\n引擎：{ENGINES[g['engine']]}\n引擎的原话：{g['text']}",
                       _obj(["verdict", "checked", "findings"], verdict={"type": "string", "enum": ["covered", "unclear"]}, checked=S, paths={"type": "array", "items": S}, findings=findings_schema,
                            components={"type": "array", "items": _obj(["name", "version", "evidence"], group=S, name=S, version=S, language=S, evidence=review.EVIDENCE)}), check)


def _there(base: pathlib.Path, p: str) -> bool:
    try:
        return agents.inside(str(base), p).exists()
    except ValueError:
        return False


def take(u: dict, value: dict, root: str) -> tuple[str, list[str]]:
    """File what an agent worked out: (note, what went wrong)."""
    g, trouble = u["gap"], []
    if g["type"] == "deps":
        ids = {f"D{i}": d for i, d in enumerate(g["items"], 1)}
        save(root, {key(ids[i]): x for i, x in value["items"].items()}, [])
        tally = [x["verdict"] for x in value["items"].values()]
        return (f"查到版本 {tally.count('version')} · 补产品名 {tally.count('alias')} · 不进制品 {tally.count('not_shipped')} · 仍不清楚 {tally.count('unknown')}", trouble)
    if g["type"] == "files":
        tally = [r["verdict"] for r in value["files"].values()]
        return f"读完 {len(tally)} 个文件：有发现 {tally.count('finding')} · 不清楚 {tally.count('unclear')}", trouble
    if value["components"]:
        save(root, {}, value["components"])
    return ("已补查：" if value["verdict"] == "covered" else "没有补全：") + value["checked"][:200], trouble


# ---- for the dependency engine -----------------------------------------------------------
def overlay(root: str, components: list[dict]) -> tuple[dict, dict, list[dict]]:
    """({key: product}, {key: why it needs no answer}, components to add); versions are set in place."""
    d = decisions(root)
    alias, settled = {}, {}
    for c in components:
        x = d["deps"].get(key(c))
        if not x:
            continue
        c["asked"] = True
        if x["verdict"] == "version":
            c["version"], c["version_by"] = x["version"], "agent"
            c.pop("guessed", None)
        elif x["verdict"] == "alias":
            alias[key(c)] = x["product"]
        elif x["verdict"] == "not_shipped":
            settled[key(c)] = f"agent 查明不进运行制品：{x['reason'][:120]}"
        else:
            c["unknown_by"] = x["reason"]
    return alias, settled, d["components"]
