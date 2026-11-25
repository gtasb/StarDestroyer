"""The open round: what rules and extracted endpoints do not point at.

Runs after the engines and the lead-driven units. The method is cloudflare's
security-audit skill (MIT, references/security-audit): a coverage map of surface x
boundary x attack class, waves of hunters that own parts of it, a critic that looks
for what the map forgot. What is ours: each part is a dsh session that may delegate
to subagents and run the engines itself, source is only read, and every step of a
chain is checked. Findings go through the same independent review as all others.
"""

import functools
import json
import pathlib
import re

from . import agents, airules, codeintel, endpoints, projects

KINDS = {"rules": "AI 写规则", "map": "覆盖规划", "hunt": "自由审计", "critic": "覆盖复查"}
REF = pathlib.Path(__file__).resolve().parents[1] / "references" / "security-audit"
COMPANIONS = {"WEB-PROTOCOL-AND-AUTH": "HTTP、会话、登录、JWT、OAuth、找回密码", "CLIENT-SIDE": "前端、浏览器、postMessage、存储",
              "DATA-ISOLATION-AND-LIFECYCLE": "多租户、缓存、导出备份、删除与撤销", "PROTOCOLS-RPC-AND-MESSAGING": "RPC、消息队列、webhook"}
MAX_AREAS, MAX_EXTRA, SUBAGENTS = 12, 6, 4
S = {"type": "string"}


@functools.lru_cache
def classes() -> dict[str, str]:
    """Attack class -> its block, verbatim."""
    text = (REF / "ATTACK-CLASSES.md").read_text(encoding="utf-8")
    parts = re.split(r"^\*\*([A-Z][^*]+)\*\* \(subagent_type:[^)]*\)\n", text, flags=re.M)
    return {name.strip(): body.strip() for name, body in zip(parts[1::2], parts[2::2])}


@functools.lru_cache
def companion(name: str) -> str:
    text = (REF / f"{name}.md").read_text(encoding="utf-8")
    return text[text.index("## Core discipline"):]


METHOD = """方法（只读源码，不运行目标代码，不联网）：
- 从一个**具体的不变量**出发：低权限的谁 → 能提交什么值/动作/状态 → 应该由哪个控制拦住 → 控制之后源码实际怎么走 → 影响谁的什么资源。
- 深读，不要只看正路：同类接口、旧接口、批量、重试、取消、导入导出、迁移、异常分支，凡是产生同样效果的都要对照，看控制是否**等价**，而不只是存在。
- 比较一个组件保证了什么、下一个组件假设了什么（归一化、大小写、编码、类型、租户范围、空值/负数/超限/重复/过期/并发）。
- 存进去时安全、取出来在另一处被危险使用的（二阶）要追；字段名、排序、表名、文件名、模板名、URL、消息体都算输入。
- 发现一个可复用的根因，就在你的范围里搜它的变体，逐个确认条件。
- 不变量无论成立还是不成立，一旦弄清就停，记到 coverage 里。
- 缺一条最佳实践、没有受影响对象的，不是漏洞；部署层才能知道的事实写进 note，不要猜。"""

ENGINE_NOTE = """你可以自己动用引擎：sd_findings 看引擎和其他 agent 已经报了什么（不要重复报），sd_opengrep 现写一条规则在全项目跑（适合搜变体、验证一个模式有多少处），
sd_callgraph 查字节码调用图（有编译产物时），sd_deps 查依赖与 CVE，sd_sinks / sd_endpoints 看线索。引擎的结果只是线索。"""

DELEGATE = f"""可以用 subagent 把独立的子问题分出去（最多 {SUBAGENTS} 个，互不重叠；子 agent 看不到你的对话，要在 prompt 里写清项目根、路径、要验证的不变量和要回报的 file:line:原文）。
用 wait_agent 等它们回报。子 agent 的结论要你自己读代码核实，最后由你一个人 sd_submit。"""

_AREA = {"type": "object", "required": ["title", "boundary", "paths", "classes", "why"], "properties": {
    "title": {"type": "string", "description": "这一块是什么，如「订单导出与下载」"},
    "boundary": {"type": "string", "description": "要守住的信任边界：谁不该能做什么"},
    "paths": {"type": "array", "items": S, "description": "相对项目根的文件或目录"},
    "classes": {"type": "array", "items": S, "description": "攻击类，原样写名字"},
    "companions": {"type": "array", "items": {"type": "string", "enum": list(COMPANIONS)}},
    "why": {"type": "string", "description": "依据哪些代码认为值得查，引擎为什么覆盖不到"}}}

_MAP = """你是审计的总规划。引擎扫描、断链续追、sink 反追、接口审计已经做过一轮，下面是结果。
现在规划一轮**不依赖规则**的审计：把项目按「攻击面 × 信任边界 × 攻击类」切成 {lo}–{hi} 块，每块交给一个审计员深读。
- 优先规则和接口清单看不到的地方：业务流程与状态机、越权与多租户、定时任务、消息消费、文件导入导出、缓存、回调、管理后台、内部接口、
  加解密与签名、鉴权实现本身、配置与默认值、前端信任了什么、二阶数据流、旧代码和半成品。
- 每块要小到一个审计员读得完（通常不超过 30 个文件），路径必须真实存在。
- 已经被确认的漏洞不要再单独开一块；被判「正常」的接口可以因为别的攻击类再查。
- 攻击类只能从清单里选，清单里的每一类要么分给某一块，要么写进 excluded 并说明为什么不适用。"""

_CRITIC = """你是覆盖复查员。上一轮审计员已经按下面的规划查完。你的任务不是找漏洞，是找**没查到的地方**：
没进任何一块的入口、同样效果的平行路径、没覆盖的生命周期（撤销、删除、迁移、失败重试）、只写了 covered 却没有实际路径支撑的、审计员自己报告的 uncovered。
读源码核实后，提出最多 {hi} 块补充（可以没有）。没有就交空数组，并在 reason 里说明你核对了什么。"""


def _schema(required, **props):
    return {"type": "object", "required": required, "properties": props}


def _exists(root: pathlib.Path, rel) -> str:
    try:
        p = agents.inside(str(root), str(rel).strip().replace("\\", "/").rstrip("/") or ".")
    except ValueError:
        return ""
    return p.relative_to(root).as_posix() if p.exists() else ""


def areas(raw, root: str) -> tuple[list[dict], list[str]]:
    """Areas that are about this project, and what is wrong with the others."""
    base, out, bad = agents.base_of(root), [], []
    for i, a in enumerate(raw if isinstance(raw, list) else []):
        if not isinstance(a, dict) or not all(isinstance(a.get(k), str) and a[k].strip() for k in ("title", "boundary", "why")):
            bad.append(f"areas[{i}] 缺少 title / boundary / why")
            continue
        paths = a.get("paths") if isinstance(a.get("paths"), list) else []
        real = list(dict.fromkeys(x for x in (_exists(base, p) for p in paths) if x))
        kinds = [c for c in (a.get("classes") if isinstance(a.get("classes"), list) else []) if c in classes()]
        if missing := [str(p) for p in paths if not _exists(base, p)]:
            bad.append(f"areas[{i}]「{a['title'][:30]}」路径不存在：{missing[:5]}")
        elif not real:
            bad.append(f"areas[{i}]「{a['title'][:30]}」没有 paths")
        elif not kinds:
            bad.append(f"areas[{i}]「{a['title'][:30]}」没有有效的 classes，只能用：{list(classes())}")
        else:
            out.append({"title": a["title"].strip()[:80], "boundary": a["boundary"].strip()[:300], "why": a["why"].strip()[:600], "paths": real[:40],
                        "classes": kinds, "companions": [c for c in a.get("companions") or [] if c in COMPANIONS]})
    return out, bad


def files(area: dict, root: pathlib.Path) -> list[str]:
    """What an area reads, so that changing it audits it again."""
    idx, out = codeintel.index(str(root)).files, []
    for p in area["paths"]:
        out += [p] if (root / p).is_file() else [f for f in idx if p == "." or f.startswith(p + "/")]
    return sorted(set(out))[:400]


def _done(root: str, data: dict) -> str:
    """What is known so far, in a few lines."""
    out = []
    for kind in ("sast", "secrets", "tabby", "agent"):
        for r in projects.findings(root, kind)[:60]:
            if r["status"] != "rejected":
                out.append(f"[{kind}/{r['status']}] {r['message'][:80]} {r['file']}:{r['line']}")
    eps = [f"{k.split('|', 1)[1]} {v['auth']}/{v['verdict']}" for k, v in data["endpoints"].items()]
    return "已有发现：\n" + ("\n".join(out[:120]) or "无") + f"\n\n已审接口 {len(eps)} 个，共 {len(endpoints.cached(root))} 个：\n" + "\n".join(eps[:150])


def task(u: dict, root: str, ctx: str, findings) -> agents.Task:
    """findings: (raw list, root) -> (good, why), shared with the lead-driven units."""
    base = agents.base_of(root)
    menu = "攻击类清单：\n" + "\n".join(f"- {c}" for c in classes()) + "\n领域补充（可选）：\n" + "\n".join(f"- {k}：{v}" for k, v in COMPANIONS.items())

    if u["kind"] == "rules":
        langs = sorted({f.lang for f in codeintel.index(str(base)).files.values() if f.lang})
        lead = "这是第二轮：重点模仿**这次审计新确认的发现**，为每个根因写变体规则，看别处还有没有。\n" if u["wave"] == 2 else ""
        return agents.Task("rules", "你是安全规则工程师。\n" + airules.GUIDE.format(cap=airules.MAX_HITS) + "\n" + ENGINE_NOTE, f"{ctx}\n\n{lead}{u['known']}\n\n{airules.materials(root, langs)}",
                           airules.schema(S, _schema), lambda raw: airules.check(raw, root))

    if u["kind"] == "map":
        def check(raw):
            got, bad = areas(raw.get("areas"), root)
            if bad:
                return None, "\n".join(bad[:8])
            if not 1 <= len(got) <= MAX_AREAS:
                return None, f"areas 要有 1–{MAX_AREAS} 块，现在 {len(got)} 块"
            out = {e.get("class"): str(e.get("reason") or "").strip() for e in raw.get("excluded") or [] if isinstance(e, dict)}
            left = [c for c in classes() if c not in {k for a in got for k in a["classes"]} and not out.get(c)]
            if left:
                return None, f"这些攻击类既没有分配，也没有写 excluded 和理由：{left}"
            return {"areas": got, "excluded": {c: r[:200] for c, r in out.items() if c in classes() and r}}, ""
        return agents.Task("map", _MAP.format(lo=3, hi=MAX_AREAS), f"{ctx}\n\n{u['known']}\n\n{menu}",
                           _schema(["areas"], areas={"type": "array", "items": _AREA}, excluded={"type": "array", "items": _schema(["class", "reason"], **{"class": S, "reason": S})}), check)

    if u["kind"] == "critic":
        def check(raw):
            got, bad = areas(raw.get("areas"), root)
            if bad:
                return None, "\n".join(bad[:8])
            if not str(raw.get("reason") or "").strip():
                return None, "缺少 reason"
            return {"areas": got[:MAX_EXTRA], "reason": str(raw["reason"])[:800]}, ""
        return agents.Task("critic", _CRITIC.format(hi=MAX_EXTRA), f"{ctx}\n\n{u['known']}\n\n规划与每块的覆盖记录：\n" + json.dumps(u["ledger"], ensure_ascii=False, indent=1)[:60_000] + f"\n\n{menu}",
                           _schema(["areas", "reason"], areas={"type": "array", "items": _AREA}, reason=S), check)

    a = u["area"]

    def check(raw):
        found, why = findings(raw.get("findings"), root)
        if why:
            return None, why
        rows, errors = {}, []
        for r in raw.get("coverage") if isinstance(raw.get("coverage"), list) else []:
            if not isinstance(r, dict) or r.get("class") not in a["classes"] or r.get("status") not in ("covered", "finding", "unclear", "not_applicable"):
                continue
            paths = [x for x in (_exists(base, p) for p in (r.get("paths") if isinstance(r.get("paths"), list) else [])) if x]
            checked = str(r.get("checked") or "").strip()
            if len(checked) < 10:
                errors.append(f"{r['class']}：checked 要写清查了哪个不变量、结论是什么")
            if r["status"] in ("covered", "finding") and not paths:
                errors.append(f"{r['class']}：{r['status']} 要给出实际读过的 paths")
            rows[r["class"]] = {"class": r["class"], "status": r["status"], "paths": paths[:20], "checked": checked[:600]}
        errors += [f"这些攻击类还没有覆盖记录：{[c for c in a['classes'] if c not in rows]}"] if set(a["classes"]) - set(rows) else []
        hit = any(r["status"] == "finding" for r in rows.values())
        if hit and not found:
            errors.append("有攻击类写了 finding，但 findings 是空的")
        if found and not hit:
            errors.append("findings 不是空的，但没有攻击类写 finding：是漏洞就标上，不是就从 findings 去掉")
        if errors:
            return None, "\n".join(errors[:8])
        more = [{"title": str(x.get("title") or "")[:80], "why": str(x.get("why") or "")[:300]} for x in raw.get("uncovered") or [] if isinstance(x, dict)][:8]
        return {"findings": found, "coverage": list(rows.values()), "uncovered": more}, ""

    blocks = "\n\n".join(f"### {c}\n{classes()[c]}" for c in a["classes"]) + "".join(f"\n\n# {c}\n{companion(c)}" for c in a["companions"])
    return agents.Task("hunt", "你是资深代码审计员，负责下面这一块，目标是找出**真实可利用**、规则扫描看不到的漏洞。\n" + METHOD + "\n" + ENGINE_NOTE + "\n" + DELEGATE
                       + "\nfindings 只放漏洞；查过没问题的写在 coverage 里。",
                       f"{ctx}\n\n你的范围：{a['title']}\n边界：{a['boundary']}\n起点：{', '.join(a['paths'])}\n为什么：{a['why']}\n"
                       f"要覆盖的攻击类：{a['classes']}\n\n攻击类说明（来自 cloudflare security-audit，其中要求运行/写文件的部分不适用，只读源码）：\n{blocks}",
                       _schema(["findings", "coverage"], findings=u["findings_schema"],
                               coverage={"type": "array", "items": _schema(["class", "status", "checked"], **{"class": S, "status": {"type": "string", "enum": ["covered", "finding", "unclear", "not_applicable"]}},
                                                                           paths={"type": "array", "items": S}, checked={"type": "string", "description": "查了哪个不变量，结论和依据"})},
                               uncovered={"type": "array", "items": _schema(["title", "why"], title=S, why=S), "description": "超出你范围但值得查的"}), check)
