"""Rules an agent wrote for one project, and the round they are run in.

A model imitates well: shown how our rules look, what this project wraps and what has
been confirmed in it, it writes rules for the project's own sources, sinks, secrets and
vendored components. Nothing it writes is taken on its word -- a SAST rule must load,
hit its bad sample and leave its good one; a secret rule the same, in gitleaks (RE2, so
a hostile file cannot hang it); an SCA rule must find something, and NVD decides what
is vulnerable. What they hit is a lead: it goes back to an agent and a reviewer.
"""

import json
import pathlib
import re
import subprocess
import tempfile

from . import hardcoded, ledger, nvd, profile, projects, sfc, store
from .engines import opengrep

MAX_RULES, MAX_HITS = 12, 150
LANGS = {"java": ".java", "kotlin": ".kt", "python": ".py", "go": ".go", "javascript": ".js", "typescript": ".ts"}
SEVERITY = {"critical": "ERROR", "high": "ERROR", "medium": "WARNING", "low": "INFO"}
_KEYS = {"id", "message", "severity", "languages", "mode", "options", "metadata", "pattern", "patterns", "pattern-either", "pattern-regex",
         "pattern-not", "pattern-not-regex", "pattern-inside", "pattern-not-inside", "pattern-sources", "pattern-sinks",
         "pattern-sanitizers", "pattern-propagators", "focus-metavariable", "metavariable-regex", "metavariable-pattern",
         "metavariable-comparison", "metavariable", "regex", "comparison", "base", "strip", "from", "to", "by-side-effect", "exact",
         "requires", "label", "control", "interfile", "generic_ellipsis_max_span", "symbolic_propagation", "taint_assume_safe_numbers",
         "taint_assume_safe_booleans"}


# ---- state ------------------------------------------------------------------------
def _file(root: str) -> pathlib.Path:
    return projects.STORE / projects.project_id(root) / "airules.json"


def load(root: str) -> list[dict]:
    return store.read(_file(root), [])


def save(root: str, rules: list[dict], wave: int) -> None:
    """A wave replaces what the same wave wrote before."""
    with store.update(_file(root), []) as data:
        new = {r["id"] for r in rules}
        data[:] = [r for r in data if r["wave"] != wave and r["id"] not in new] + [{**r, "wave": wave} for r in rules]


def strike(root: str, scrub) -> None:
    with store.update(_file(root), []) as data:
        data[:] = [{**r, **scrub({k: r[k] for k in ("title", "why")})} for r in data]


def remove(root: str, rule_id: str) -> dict:
    with store.update(_file(root), []) as data:
        left = [r for r in data if r["id"] != rule_id]
        if len(left) == len(data):
            return {"ok": False, "error": "没有这条规则"}
        data[:] = left
    return {"ok": True}


def of(root: str, kind: str) -> list[dict]:
    return [r for r in load(root) if r["kind"] == kind]


# ---- SAST -------------------------------------------------------------------------
def only_matching(rule) -> dict:
    """A rule with nothing in it but matching: no fetching, no fixing, no includes."""
    def look(x, depth=0):
        if depth > 12:
            raise ValueError("规则嵌套过深")
        if isinstance(x, dict):
            bad = [k for k in x if k not in _KEYS]
            if bad:
                raise ValueError(f"规则里不支持这些键: {bad}")
            for v in x.values():
                look(v, depth + 1)
        elif isinstance(x, list):
            for v in x[:200]:
                look(v, depth + 1)
    if not isinstance(rule, dict):
        raise ValueError("rule 要是对象")
    rule = {**rule, "metadata": {}}
    look(rule)
    return {"id": "agent-rule", "message": "m", "severity": "WARNING", **rule}


def run_sast(rules: list[dict], target: str, timeout: int = 170) -> dict:
    """Opengrep with these rules only, components included."""
    with tempfile.TemporaryDirectory(prefix="sd-rule-", ignore_cleanup_errors=True) as d:
        f = pathlib.Path(d) / "rules.yaml"
        f.write_text(json.dumps({"rules": rules}, ensure_ascii=False), encoding="utf-8")
        js = any(x in ("javascript", "typescript", "js", "ts") for r in rules for x in r.get("languages") or [])
        parts = [p for p in ledger.source_files(target, "js") if p.suffix.lower() in sfc.EXTENSIONS] if js else []
        with sfc.Shadow(parts) as shadow:
            return shadow.restore(opengrep.run_scan(target, rules=str(f), timeout_s=timeout, also=[shadow.dir] if shadow.dir else [],
                                                    exclude=["/" + x for x in ledger.excluded(target)] if js else []))


def _sast(raw: list, root: str) -> tuple[list[dict], list[str]]:
    out, bad = [], []
    for i, r in enumerate(raw):
        name = f"sast[{i}]"
        try:
            rid, rule = _id(r), only_matching(r.get("rule"))
            langs = rule.get("languages") or []
            if not langs or not set(langs) <= set(LANGS):
                raise ValueError(f"rule.languages 只能用 {list(LANGS)}")
            s = r.get("samples") if isinstance(r.get("samples"), dict) else {}
            lang = s.get("lang") if s.get("lang") in langs else langs[0]
            if not all(isinstance(s.get(k), str) and s[k].strip() for k in ("bad", "good")):
                raise ValueError("samples 要有 bad（必须命中）和 good（必须不命中）两段完整代码")
            rule = {**rule, "id": rid, "message": r["title"].strip()[:200], "severity": SEVERITY[r["severity"]], "metadata": {"cwe": r["cwe"]}}
            with tempfile.TemporaryDirectory(prefix="sd-prove-", ignore_cleanup_errors=True) as d:
                for k in ("bad", "good"):
                    (pathlib.Path(d) / k).mkdir()
                    (pathlib.Path(d) / k / f"S{LANGS[lang]}").write_text(s[k], encoding="utf-8")
                res = run_sast([rule], d, 60)
            hit = {pathlib.Path(f["file"]).parent.name for f in res["findings"]}
            if not res["ok"] or res["errors"]:
                raise ValueError(f"引擎加载或解析不了：{(res.get('error') or res['errors'][0])[:300]}")
            if "bad" not in hit:
                raise ValueError("没有命中 bad 样例")
            if "good" in hit:
                raise ValueError("误报了 good 样例")
            out.append({"kind": "sast", "id": rid, "title": rule["message"], "cwe": r["cwe"], "severity": r["severity"], "why": r["why"].strip()[:500], "rule": rule})
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            bad.append(f"{name}：{exc}")
    if out:
        res = run_sast([r["rule"] for r in out], root)
        if not res["ok"] and not res["findings"]:
            return [], bad + [f"在项目上跑不完这些规则，收窄后再试：{res.get('error')}"]
        for r in out:
            r["hits"] = len({(f["file"], f["line"]) for f in res["findings"] if f["rule_id"] == r["id"]})
            if r["hits"] > MAX_HITS:
                bad.append(f"{r['id']}：在项目里命中 {r['hits']} 处，太宽，收窄到能说明问题的写法")
    return [r for r in out if r["hits"] <= MAX_HITS], bad


def files(root: str) -> list[str]:
    """The project's SAST rules as a file for the engine."""
    rules = [r["rule"] for r in of(root, "sast")]
    f = _file(root).with_name("airules.yaml")
    if not rules:
        return []
    f.write_text(json.dumps({"rules": rules}, ensure_ascii=False), encoding="utf-8")
    return [str(f)]


# ---- secrets, in gitleaks ------------------------------------------------------------
def _toml(rules: list[dict]) -> str:
    q = lambda s: json.dumps(str(s), ensure_ascii=False).replace("\x7f", "")  # a JSON string is a TOML basic string
    out = ['title = "agent"']
    for r in rules:
        out += ["[[rules]]", f"id = {q(r['id'])}", 'description = "agent"', f"regex = {q(r['regex'])}", f"secretGroup = {int(r.get('group') or 0)}"]
        if r.get("path"):
            out.append(f"path = {q(r['path'])}")
        if r.get("keywords"):
            out.append("keywords = [" + ", ".join(q(k) for k in r["keywords"]) + "]")
    return "\n".join(out) + "\n"


def _leaks(rules: list[dict], target: str, timeout: int = 120) -> list[dict]:
    exe = hardcoded.binary()
    if not exe:
        raise ValueError("没有 gitleaks，这类规则跑不了")
    with tempfile.TemporaryDirectory(prefix="sd-leaks-", ignore_cleanup_errors=True) as d:
        try:
            return hardcoded._leaks(exe, target, pathlib.Path(d), timeout, _toml(rules))[0]
        except subprocess.TimeoutExpired:
            raise ValueError("跑得太慢") from None
        except (RuntimeError, OSError) as exc:
            raise ValueError(f"gitleaks 不接受：{exc}") from None


def _id(r: dict) -> str:
    rid = "ai-" + re.sub(r"[^a-z0-9]+", "-", str(r.get("id") or "").lower().removeprefix("ai-")).strip("-")[:50]
    if len(rid) < 6:
        raise ValueError("id 要用有意义的英文短名")
    for k in ("title", "why"):
        if not isinstance(r.get(k), str) or len(r[k].strip()) < 4:
            raise ValueError(f"缺少 {k}")
    if r.get("severity", "medium") not in SEVERITY:
        raise ValueError("severity 要是 critical|high|medium|low")
    if "cwe" in r and not re.fullmatch(r"CWE-\d+", str(r["cwe"])):
        raise ValueError("cwe 写成 CWE-数字")
    return rid


def _rows(rows: list[dict], base: pathlib.Path) -> list[dict]:
    """gitleaks rows inside the project's own code."""
    out = []
    for x in rows:
        f = pathlib.Path(x["File"])
        try:
            rel = f.resolve().relative_to(base)
        except ValueError:
            continue
        if not set(rel.parts[:-1]) & profile.SKIP_DIRS - {"dist"}:
            out.append({**x, "rel": rel.as_posix()})
    return out


def _secrets(raw: list, root: str) -> tuple[list[dict], list[str]]:
    base, out, bad = pathlib.Path(root).resolve(), [], []
    known = [v for v in (hardcoded.raw(r, base) for r in projects.findings(root, "secrets")) if len(v) >= 6]
    for i, r in enumerate(raw):
        try:
            rule = {"kind": "secrets", "id": _id(r), "title": r["title"].strip()[:200], "cwe": r["cwe"], "severity": r["severity"], "why": r["why"].strip()[:500],
                    "regex": r["regex"], "group": int(r.get("group") or 0), "path": str(r.get("path") or ""), "keywords": [str(k) for k in r.get("keywords") or []][:8]}
            if not isinstance(rule["regex"], str) or not 4 <= len(rule["regex"]) <= 600:
                raise ValueError("regex 长度要在 4–600")
            if any(v in rule["regex"] for v in known):
                raise ValueError("regex 里写死了项目里的真实值，要写成模式")
            s = r.get("samples") if isinstance(r.get("samples"), dict) else {}
            lines = {k: [x for x in s.get(k) or [] if isinstance(x, str) and x.strip()] for k in ("bad", "good")}
            if not lines["bad"] or not lines["good"]:
                raise ValueError("samples.bad 和 samples.good 各要至少一行（用编造的值）")
            with tempfile.TemporaryDirectory(prefix="sd-prove-", ignore_cleanup_errors=True) as d:
                name = re.sub(r"[^\w./\-]", "_", str(s.get("path") or "sample.txt")).replace("..", "_").lstrip("/")
                for k, rows in lines.items():
                    for n, text in enumerate(rows):
                        f = pathlib.Path(d) / k / str(n) / name
                        f.parent.mkdir(parents=True)
                        f.write_text(text + "\n", encoding="utf-8")
                hit = {tuple(pathlib.Path(x["File"]).resolve().relative_to(pathlib.Path(d).resolve()).parts[:2]) for x in _leaks([rule], d, 60)}
            if miss := [n for n in range(len(lines["bad"])) if ("bad", str(n)) not in hit]:
                raise ValueError(f"没有命中 bad 样例 {miss}")
            if any(k == "good" for k, _ in hit):
                raise ValueError("误报了 good 样例")
            rule["hits"] = len(_rows(_leaks([rule], root), base))
            if rule["hits"] > MAX_HITS:
                raise ValueError(f"在项目里命中 {rule['hits']} 处，太宽")
            out.append(rule)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            bad.append(f"secrets[{i}]：{exc}")
    return out, bad


def secret_hits(root: pathlib.Path) -> tuple[list[dict], list[str]]:
    """What the project's secret rules find, in hardcoded's shape."""
    rules = {r["id"]: r for r in of(str(root), "secrets")}
    if not rules:
        return [], []
    try:
        rows = _rows(_leaks(list(rules.values()), str(root), 600), root if root.is_dir() else root.parent)
    except ValueError as exc:
        return [], [f"AI 写的硬编码规则没有跑成：{exc}"]
    return [{"rule": x["RuleID"], "cwe": rules[x["RuleID"]]["cwe"], "severity": rules[x["RuleID"]]["severity"], "what": rules[x["RuleID"]]["title"], "key": "",
             "value": str(x["Secret"]), "rel": x["rel"], "line": int(x["StartLine"])} for x in rows], []


# ---- SCA ------------------------------------------------------------------------------
def _glob(pattern: str) -> re.Pattern:
    """A path with * ** and one {version}; nothing else, so nothing can blow up."""
    out = "".join({"**": ".*", "*": "[^/]*", "{version}": r"(?P<v>\d[\w.\-]*?)"}.get(p, re.escape(p)) for p in re.split(r"(\*\*|\*|\{version\})", pattern) if p)
    return re.compile(out + r"\Z", re.I)


def _find(rule: dict, root: pathlib.Path) -> list[dict]:
    """Components a rule recognises: {name, version, path}."""
    got = []
    if rule.get("regex"):
        for x in _rows(_leaks([rule], str(root)), root):
            got.append((str(x["Secret"]), x["rel"]))
    else:
        rx = _glob(rule["path"])
        for f in profile._walk(root):
            rel = f.relative_to(root).as_posix()
            if m := rx.match(rel):
                got.append((m.group("v"), rel))
    return [{"name": rule["product"], "vendor": rule.get("group_id", ""), "version": v, "path": p} for v, p in got if nvd.comparable(v)]


def _sca(raw: list, root: str) -> tuple[list[dict], list[str]]:
    base, out, bad = pathlib.Path(root).resolve(), [], []
    tri = projects.load_artifact(root, "triage") or {}
    names = {u["name"].lower() for u in tri.get("unresolved") or []}
    for i, r in enumerate(raw):
        try:
            rid, kind = _id(r), r.get("type")
            rule = {"kind": "sca", "type": kind, "id": rid, "title": r["title"].strip()[:200], "why": r["why"].strip()[:500], "product": str(r.get("product") or "").strip().lower()}
            if not re.fullmatch(r"[a-z0-9][\w.\-@/]{1,60}", rule["product"]):
                raise ValueError("product 要是 NVD / 包管理器里的产品名")
            if kind == "alias":
                rule["dependency"] = str(r.get("dependency") or "").strip()
                if rule["dependency"].lower() not in names:
                    raise ValueError(f"dependency 要取自没有结论的依赖，{rule['dependency']!r} 不在里面")
                if not nvd._resolve_vendors(rule["product"]):
                    raise ValueError(f"CPE 字典里没有产品 {rule['product']!r}")
                rule["hits"] = 1
            elif kind == "component":
                rule.update(path=str(r.get("path") or ""), regex=str(r.get("regex") or ""), group=int(r.get("group") or 0), group_id=str(r.get("group_id") or ""))
                if not rule["regex"] and rule["path"].count("{version}") != 1:
                    raise ValueError("要么 path 里有一个 {version}（只支持 * 和 **），要么给 regex + group 从文件内容取版本")
                rule["hits"] = len(_find(rule, base))
                if not rule["hits"]:
                    raise ValueError("在项目里一个也没找到")
                if rule["hits"] > MAX_HITS:
                    raise ValueError(f"命中 {rule['hits']} 个文件，太宽")
            else:
                raise ValueError("type 要是 alias 或 component")
            out.append(rule)
        except (ValueError, KeyError, TypeError, AttributeError) as exc:
            bad.append(f"sca[{i}]：{exc}")
        except Exception as exc:  # the CPE dictionary is a network service
            bad.append(f"sca[{i}]：CPE 字典查不到结果：{exc}")
    return out, bad


def components(root: str) -> list[dict]:
    out, base = [], pathlib.Path(root).resolve()
    for r in of(root, "sca"):
        if r["type"] == "component" and base.is_dir():
            try:
                out += [{"vendor": c["vendor"], "name": c["name"], "version": c["version"], "language": "", "direct": True, "paths": [c["path"]], "found_by": r["id"]} for c in _find(r, base)]
            except ValueError:
                continue
    return out


def aliases(root: str) -> dict[str, str]:
    return {r["dependency"].lower(): r["product"] for r in of(root, "sca") if r["type"] == "alias"}


# ---- the agent's answer ----------------------------------------------------------------
def check(raw: dict, root: str) -> tuple[dict | None, str]:
    rows = {k: raw.get(k) if isinstance(raw.get(k), list) else [] for k in ("sast", "secrets", "sca")}
    if sum(map(len, rows.values())) > MAX_RULES * 2:
        return None, f"规则太多，挑最有价值的，最多 {MAX_RULES * 2} 条"
    if not str(raw.get("reason") or "").strip():
        return None, "缺少 reason：说明这些规则补的是什么空白；没有可写的也要说明为什么"
    got, bad = [], []
    for k, fn in (("sast", _sast), ("secrets", _secrets), ("sca", _sca)):
        a, b = fn(rows[k], root) if rows[k] else ([], [])
        got += a
        bad += b
    ids = [r["id"] for r in got]
    if dup := {i for i in ids if ids.count(i) > 1}:
        bad.append(f"id 重复：{sorted(dup)}")
    if bad:
        return None, "这些规则没有通过验证，改好或去掉后整体重新提交：\n" + "\n".join(bad[:12])
    return {"rules": got, "reason": str(raw["reason"])[:800]}, ""


def rerun(root: str, rules: list[dict]) -> tuple[list[str], list[str]]:
    """Run the engines again with the new rules: (what came of it, what went wrong)."""
    from . import proc, toolset
    said, gaps, kinds = [], [], {r["kind"] for r in rules}
    ids = {r["id"] for r in rules}
    steps = (("sast", "源码", lambda: toolset.auto_scan(root)), ("secrets", "硬编码", lambda: hardcoded.scan(root)),
             ("triage", "依赖", lambda: toolset.sca_triage_scan(root, max_lookups=60)))
    for kind, label, go in steps:
        if (kind if kind != "triage" else "sca") not in kinds:
            continue
        proc.stage(f"用 AI 写的规则再跑一轮：{label}")
        res = go()
        if not res.get("ok"):
            gaps.append(f"用 AI 写的规则再跑{label}失败：{res.get('error')}")
            continue
        projects.save_artifact(root, kind, res)
        if kind == "triage":
            said.append(f"依赖保留 {len(res.get('kept') or [])} 个 CVE")
        else:
            said.append(f"{label}新规则命中 {sum(r['rule_id'] in ids for r in projects.findings(root, kind))} 处")
    return said, gaps


def schema(S: dict, obj) -> dict:
    common = {"id": {"type": "string", "description": "英文短名"}, "title": {"type": "string", "description": "命中时给人看的一句话"}, "why": {"type": "string", "description": "补的是什么空白，模仿了哪条，依据哪些代码"}}
    sev = {"type": "string", "enum": list(SEVERITY)}
    lines = {"type": "array", "items": S}
    return obj(["sast", "secrets", "sca", "reason"],
               sast={"type": "array", "items": obj(["id", "title", "why", "cwe", "severity", "rule", "samples"], **common, cwe=S, severity=sev,
                                                   rule={"type": "object", "properties": {}, "additionalProperties": True, "description": "Opengrep 规则对象"},
                                                   samples=obj(["bad", "good"], lang=S, bad=S, good=S))},
               secrets={"type": "array", "items": obj(["id", "title", "why", "cwe", "severity", "regex", "samples"], **common, cwe=S, severity=sev,
                                                      regex={"type": "string", "description": "RE2 正则"}, group={"type": "integer", "description": "值所在的捕获组"},
                                                      path={"type": "string", "description": "文件路径正则，可空"}, keywords=lines,
                                                      samples=obj(["bad", "good"], bad=lines, good=lines, path=S))},
               sca={"type": "array", "items": obj(["id", "title", "why", "type", "product"], **common, type={"type": "string", "enum": ["alias", "component"]}, product=S,
                                                  dependency={"type": "string", "description": "alias：没有结论的依赖名"}, group_id=S,
                                                  path={"type": "string", "description": "component：如 web/js/jquery-{version}.js"}, regex=S, group={"type": "integer"})},
               reason=S)


GUIDE = """你要为这个项目**写规则**，再由程序跑一轮。模仿下面给出的规则样式和这个项目里已经确认的漏洞，写通用规则库不可能有、只适用于这个项目的规则：
- sast（Opengrep）：项目自己封装的危险方法当 sink，自己的取参方式（BaseController、自定义注解、工具类、消息体）当 source，自己的净化函数当 sanitizer；
  已确认漏洞的变体（同样写法换了方法、换了模块）；框架用法上的错误（漏注解、漏校验、错误的默认值）。taint 规则记得 options.interfile: true。
- secrets（gitleaks，RE2 正则）：这个项目特有的凭据写法，如自定义键名、编码后的口令、写死的盐和密钥、内部系统的令牌格式。
- sca：component 识别没进依赖树的组件（直接拷进来的 js、lib 目录的 jar、改名打包的），版本从文件名或内容取；alias 给「没有结论的依赖」补 NVD 的产品名。只负责认出组件，受不受影响由 NVD 判断，不要自己编 CVE。
每条 SAST / secrets 规则都要带样例，程序会用真引擎验证：命中 bad、不命中 good、能加载、在项目里不超过 {cap} 处。提交前可以用 sd_opengrep 试跑。
命中只是线索，会再交给别的 agent 追链和复核，所以宁可写得准。没有值得写的那一类就交空数组。
先读懂再动手：每一类最多 4 条，最有价值的先写；试跑不要超过 10 次，总共不要超过 30 次工具调用，写完就提交。why 里说明依据即可，不要抄整行源码。样例里的口令、密钥一律编造，不要抄项目里的真实值。"""


def materials(root: str, langs: list[str]) -> str:
    """What to imitate: rules we have, what this project wraps, what nobody could resolve."""
    from . import codeintel, rulebase
    shown = []
    for lang in langs:
        shown += [rulebase.render(r) for r in rulebase.RULES if r["lang"] == lang][:2]
    wraps: dict[str, list] = {}
    for s in codeintel.sink_sites(root):
        if s["in"]:
            wraps.setdefault(s["in"], []).append(s["class"])
    rows = sorted(wraps.items(), key=lambda kv: -len(kv[1]))[:80]
    tri = projects.load_artifact(root, "triage") or {}
    lost = [f"{u['name']} {u['version']}（{u['reason'][:40]}）" for u in tri.get("unresolved") or []][:80]
    mine = [f"[{r['kind']}] {r['id']} {r['title']}" for r in load(root)]
    secret = "\n".join(f"- {r[0]}: {r[5].pattern[:220]}" for r in hardcoded.RULES[:1] + hardcoded.RULES[6:7] + hardcoded.RULES[9:10])
    return ("规则样式（YAML，提交时写成同样键的 JSON 对象）：\n" + "\n\n".join(shown) + f"\n\n已有的硬编码规则（不要重复）：\n{secret}\n\n"
            "项目里直接调用危险 API 的方法（它们的调用者才是真正的入口，适合当 sink）：\n" + ("\n".join(f"- {k}：{'、'.join(sorted(set(v)))}" for k, v in rows) or "无")
            + "\n\n没有结论的依赖：\n" + ("\n".join(lost) or "无（或没跑依赖筛选）") + "\n\n之前写过的规则（不要重复）：\n" + ("\n".join(mine) or "无"))
