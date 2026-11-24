"""Rule generation.

The agent writes rules from the project's own dependency evidence, then proves
they parse before they are used. Rules are kept per-project under
.work/rules/generated/ with a manifest, so a later audit retrieves the ones that
apply instead of loading every rule ever written.
"""

import hashlib
import json
import pathlib
import subprocess
import tempfile

from .engines import opengrep

OUT_DIR = pathlib.Path(__file__).resolve().parents[1] / ".work" / "rules" / "generated"

SPRING_SOURCES = [
    "(HttpServletRequest $R).getParameter(...)",
    "(HttpServletRequest $R).getHeader(...)",
    "$REQ.getParameter(...)",
]
FLASK_SOURCES = ["request.args.get(...)", "request.form.get(...)",
                 "request.get_json(...)", "request.values.get(...)"]
DJANGO_SOURCES = ["request.GET.get(...)", "request.POST.get(...)", "request.body"]
GO_SOURCES = ["$R.URL.Query().Get(...)", "$R.FormValue(...)",
              "$R.PostFormValue(...)"]

CATALOG = {
    "jdbc": {
        "language": "java", "vul": "sqli", "sources": SPRING_SOURCES,
        "sinks": ["(JdbcTemplate $J).query($Q, ...)", "(JdbcTemplate $J).queryForList($Q, ...)",
                  "(JdbcTemplate $J).queryForObject($Q, ...)", "(JdbcTemplate $J).update($Q, ...)",
                  "(NamedParameterJdbcTemplate $N).query($Q, ...)"],
        "why": "JdbcTemplate",
    },
    "jpa": {
        "language": "java", "vul": "sqli", "sources": SPRING_SOURCES,
        "sinks": ["(EntityManager $E).createQuery($Q)", "(EntityManager $E).createNativeQuery($Q)",
                  "(Session $S).createQuery($Q)", "(Session $S).createNativeQuery($Q)"],
        "why": "JPA/Hibernate",
    },
    "flask": {
        "language": "python", "vul": "sqli", "sources": FLASK_SOURCES,
        "sinks": ["$S.execute($Q, ...)", "$S.executemany($Q, ...)"],
        "why": "Flask",
    },
    "sqlalchemy": {
        "language": "python", "vul": "sqli", "sources": FLASK_SOURCES,
        "sinks": ["$S.execute(text($Q))", "$S.execute($Q, ...)"],
        "why": "SQLAlchemy",
    },
    "django": {
        "language": "python", "vul": "sqli", "sources": DJANGO_SOURCES,
        "sinks": ["$M.raw($Q)", "$CUR.execute($Q, ...)"],
        "why": "Django",
    },
    "gorm": {
        "language": "go", "vul": "sqli", "sources": GO_SOURCES,
        "sinks": ["$DB.Raw($Q, ...)", "$DB.Exec($Q, ...)", "$DB.Where($Q, ...)"],
        "why": "GORM",
    },
}


def _yaml(spec: dict, rule_id: str, family: str) -> str:
    lines = [
        "rules:",
        f"  - id: {rule_id}",
        "    mode: taint",
        f"    languages: [{spec['language']}]",
        "    severity: ERROR",
        f"    message: 外部输入流入 {spec['why']} 数据访问 API",
        "    options:",
        "      interfile: true",
        "    pattern-sources:",
        "      - pattern-either:",
    ]
    lines += [f"          - pattern: {s}" for s in spec["sources"]]
    lines += ["    pattern-sinks:", "      - patterns:", "          - pattern-either:"]
    lines += [f"              - pattern: {s}" for s in spec["sinks"]]
    lines += ["          - focus-metavariable: $Q"]
    return "\n".join(lines) + "\n"


def propose(prof: dict, only: list[str] | None = None) -> list[dict]:
    if not prof.get("ok"):
        return []
    out = []
    for family in prof.get("frameworks", []):
        spec = CATALOG.get(family)
        if not spec or (only and family not in only):
            continue
        if spec["language"] != prof.get("language"):
            continue
        rule_id = f"gen-{spec['language']}-{spec['vul']}-{family}"
        deps = [d for d in prof.get("dependencies", [])
                if family.split("-")[0] in d or family in d] or \
               [f"source hint: {family}"]
        out.append({
            "id": rule_id,
            "family": family,
            "vul": spec["vul"],
            "language": spec["language"],
            "reason": f"检测到依赖 {', '.join(deps[:3])} → {spec['why']} 数据访问 API",
            "yaml": _yaml(spec, rule_id, family),
        })
    return out


def write(proposals: list[dict], out_dir: str | None = None) -> dict:
    d = pathlib.Path(out_dir or OUT_DIR)
    d.mkdir(parents=True, exist_ok=True)
    manifest_path = d / "manifest.json"
    manifest = {}
    if manifest_path.exists():
        try:
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            manifest = {}
    written = []
    for p in proposals:
        path = d / f"{p['id']}.yaml"
        path.write_text(p["yaml"], encoding="utf-8")
        manifest[p["id"]] = {
            "family": p["family"], "reason": p["reason"],
            "fingerprint": hashlib.sha256(p["yaml"].encode()).hexdigest()[:16],
        }
        written.append(str(path))
    manifest_path.write_text(json.dumps(manifest, ensure_ascii=False, indent=2),
                             encoding="utf-8")
    return {"ok": True, "written": written, "dir": str(d)}


def validate(rules_dir: str | None = None) -> dict:
    """Parse the rules with the engine itself; an invalid rule is never applied."""
    d = pathlib.Path(rules_dir or OUT_DIR)
    if not d.exists():
        return {"ok": False, "error": f"规则目录不存在: {d}"}
    fd, outp = tempfile.mkstemp(suffix=".json", prefix="ruleval-")
    probe = tempfile.mkdtemp(prefix="ruleval-src-")
    try:
        subprocess.run([opengrep.binary(), "scan", "-c", str(d), "--json", "-o", outp, probe],
                       capture_output=True, text=True, timeout=120,
                       encoding="utf-8", errors="replace")
        doc = json.loads(pathlib.Path(outp).read_text(encoding="utf-8", errors="replace"))
    except Exception as exc:
        return {"ok": False, "error": f"校验失败: {exc}"}
    errors = [e.get("message", "")[:300] for e in doc.get("errors", [])]
    return {"ok": not errors, "errors": errors, "rules_dir": str(d)}


def load_manifest(rules_dir: str | None = None) -> dict:
    p = pathlib.Path(rules_dir or OUT_DIR) / "manifest.json"
    if not p.exists():
        return {}
    try:
        return json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
