"""Rule generation.

The agent writes rules from the project's own dependency evidence, then proves
each one before it is used: the engine must load it, it must hit a vulnerable
sample and stay quiet on a safe one. Rules are kept per project under
.work/rules/generated/<project>/, so one project's rules never run on another.
"""

import hashlib
import pathlib
import shutil
import tempfile

from . import rulebase, store
from .engines import opengrep

OUT_DIR = pathlib.Path(__file__).resolve().parents[1] / ".work" / "rules" / "generated"

_J = "class S {{ Object m(HttpServletRequest r, {t} x) {{ return x.{call}; }} }}\n"
_P = "from flask import request\n@app.route('/')\ndef f():\n    {}\n"
_G = "package m\nfunc h(w http.ResponseWriter, r *http.Request) {{\n\t{}\n}}\n"
_BAD, _OK = '"a"+r.getParameter("q")', '"a=?", r.getParameter("q")'

# sample = (vulnerable, safe)
CATALOG = {
    "jdbc": {
        "language": "java", "vul": "sqli", "cwe": "CWE-89", "why": "JdbcTemplate",
        "sinks": [f"(JdbcTemplate $J).{m}($Q, ...)" for m in (
            "query", "queryForList", "queryForObject", "queryForMap", "queryForRowSet", "queryForStream",
            "update", "batchUpdate", "execute")]
        + [f"(NamedParameterJdbcTemplate $N).{m}($Q, ...)" for m in ("query", "queryForList", "queryForObject", "update")],
        "sample": (_J.format(t="JdbcTemplate", call=f"queryForList({_BAD})"),
                   _J.format(t="JdbcTemplate", call=f"queryForList({_OK})")),
    },
    "jpa": {
        "language": "java", "vul": "sqli", "cwe": "CWE-89", "why": "JPA/Hibernate",
        "sinks": ["(EntityManager $E).createQuery($Q, ...)", "(EntityManager $E).createNativeQuery($Q, ...)",
                  "(Session $S).createQuery($Q, ...)", "(Session $S).createNativeQuery($Q, ...)",
                  "(Session $S).createSQLQuery($Q)"],
        "sample": (_J.format(t="EntityManager", call=f"createNativeQuery({_BAD})"),
                   _J.format(t="EntityManager", call='createNativeQuery("a=?").setParameter(1, r.getParameter("q"))')),
    },
    "mybatis": {
        "language": "java", "vul": "sqli", "cwe": "CWE-89", "why": "MyBatis SqlRunner / Wrapper",
        "sinks": ["(SqlRunner $R).selectAll($Q, ...)", "(SqlRunner $R).selectOne($Q, ...)",
                  "(SqlRunner $R).run($Q)", "$W.apply($Q, ...)", "$W.last($Q)", "$W.orderByAsc($Q)",
                  "$W.orderByDesc($Q)", "$W.inSql($C, $Q)", "$W.having($Q, ...)"],
        "sample": (_J.format(t="QueryWrapper", call=f"last({_BAD})"),
                   _J.format(t="QueryWrapper", call='eq("a", r.getParameter("q"))')),
    },
    "flask": {
        "language": "python", "vul": "sqli", "cwe": "CWE-89", "why": "Flask",
        "sinks": ["$S.execute($Q, ...)", "$S.executemany($Q, ...)"],
        "sample": (_P.format('db.execute("a" + request.args.get("q"))'),
                   _P.format('db.execute("a=?", (request.args.get("q"),))')),
    },
    "sqlalchemy": {
        "language": "python", "vul": "sqli", "cwe": "CWE-89", "why": "SQLAlchemy",
        "sinks": ["text($Q)", "sqlalchemy.text($Q)", "$S.execute($Q, ...)", "$S.filter(text($Q))"],
        "sample": (_P.format('db.execute(text("a" + request.args.get("q")))'),
                   _P.format('db.execute(text("a=:q"), {"q": request.args.get("q")})')),
    },
    "django": {
        "language": "python", "vul": "sqli", "cwe": "CWE-89", "why": "Django",
        "sinks": ["$M.raw($Q, ...)", "$M.extra(where=[$Q], ...)", "RawSQL($Q, ...)", "$CUR.execute($Q, ...)"],
        "sample": ('def f(request):\n    User.objects.raw("a" + request.GET.get("q"))\n',
                   'def f(request):\n    User.objects.raw("a=%s", [request.GET.get("q")])\n'),
    },
    "gorm": {
        "language": "go", "vul": "sqli", "cwe": "CWE-89", "why": "GORM",
        "sinks": [f"$DB.{m}($Q, ...)" for m in ("Raw", "Exec", "Where", "Order", "Having", "Select", "Group", "Joins")],
        "sample": (_G.format('db.Raw("a" + r.FormValue("q"))'), _G.format('db.Raw("a=?", r.FormValue("q"))')),
    },
}
_EXT = {"java": ".java", "python": ".py", "go": ".go"}


def rule_id(family: str) -> str:
    spec = CATALOG[family]
    return f"gen-{spec['language']}-{spec['vul']}-{family}"


def render(family: str) -> str:
    spec = CATALOG[family]
    return rulebase.document([rulebase.rule(
        rule_id(family), spec["language"], spec["cwe"],
        f"外部输入流入 {spec['why']} 数据访问 API", spec["sinks"], "$Q")])


def propose(prof: dict, only: list[str] | None = None) -> list[dict]:
    if not prof.get("ok"):
        return []
    out = []
    for family in prof.get("frameworks", []):
        spec = CATALOG.get(family)
        if not spec or (only and family not in only):
            continue
        if spec["language"] not in prof.get("file_counts", {}):
            continue
        deps = prof.get("framework_evidence", {}).get(family) or [f"source hint: {family}"]
        out.append({
            "id": rule_id(family),
            "family": family,
            "vul": spec["vul"],
            "language": spec["language"],
            "reason": f"检测到依赖 {', '.join(deps[:3])} → {spec['why']} 数据访问 API",
            "yaml": render(family),
        })
    return out


def prove(family: str, yaml: str | None = None) -> dict:
    """Load the rule and run it on both samples with the real engine."""
    spec = CATALOG[family]
    with tempfile.TemporaryDirectory(prefix="ruleprove-") as d:
        tmp = pathlib.Path(d)
        (tmp / "rule.yaml").write_text(yaml or render(family), encoding="utf-8")
        for name, code in zip(("bad", "ok"), spec["sample"]):
            (tmp / "src" / name).mkdir(parents=True)
            (tmp / "src" / name / f"s{_EXT[spec['language']]}").write_text(code, encoding="utf-8")
        res = opengrep.run_scan(str(tmp / "src"), rules=str(tmp / "rule.yaml"), timeout_s=120)
    if not res["ok"]:
        return {"ok": False, "error": res.get("error")}
    hits = {pathlib.Path(f["file"]).parent.name for f in res["findings"]}
    if "bad" not in hits:
        return {"ok": False, "error": "规则没有命中漏洞样例"}
    if "ok" in hits:
        return {"ok": False, "error": "规则误报了安全样例"}
    return {"ok": True}


_PROVED: dict[str, dict] = {}


def write(proposals: list[dict], project_root: str) -> dict:
    """Prove each rule, keep the ones that hold. A bad rule costs only itself."""
    key = hashlib.sha256(str(pathlib.Path(project_root).resolve()).encode()).hexdigest()[:12]
    d = OUT_DIR / key
    applied, failed, manifest = [], [], {}
    with store.lock(OUT_DIR / f"{key}.build"):
        shutil.rmtree(d, ignore_errors=True)
        d.mkdir(parents=True, exist_ok=True)
        for p in proposals:
            digest = hashlib.sha256((opengrep.binary() + p["yaml"]).encode()).hexdigest()
            res = _PROVED.get(digest) or prove(p["family"], p["yaml"])
            if not res["ok"]:
                failed.append({"id": p["id"], "error": res["error"]})
                continue
            _PROVED[digest] = res
            path = d / f"{p['id']}.yaml"
            path.write_text(p["yaml"], encoding="utf-8")
            applied.append(str(path))
            manifest[p["id"]] = {"family": p["family"], "reason": p["reason"],
                                 "language": p["language"], "root": str(project_root)}
        store.write(d / "manifest.json", manifest)
    return {"ok": True, "dir": str(d), "files": applied, "failed": failed}


def load_manifest() -> dict:
    """{project key: {rule id: {...}}} for every project with generated rules."""
    return {f.parent.name: store.read(f, {}) for f in sorted(OUT_DIR.glob("*/manifest.json"))}
