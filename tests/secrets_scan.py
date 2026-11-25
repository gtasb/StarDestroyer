"""Hardcoded credentials: found, masked everywhere, not switched off by the project,
judged by an agent. Real gitleaks, offline. Samples are assembled, not stored.
"""

import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
__import__("os").environ["SCA_OSV"] = "0"  # offline

import _env  # noqa: F401
from core import agents, audit, codeintel, config, decisions, hardcoded, pipeline, projects, review, rulegen, tasks, toolset

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
    return str(d.resolve())


AWS = "AKIA" + "YRWQG5EJLPZLBYNP"
DB, KEY, SHIRO = "Pr0d" + "Pass9x", "s3cr3t" + "SigningKey77", "kPH+bIxk5D2d" + "eZiIxcaaaA=="

# (file, line, wanted)
CASES = [
    ("a.yml", f"  password: {DB}", True), ("a.yml", "  password: root", True), ("a.yml", f"spring.datasource.password: '{DB}'", True), ("a.properties", f"db.pwd={DB}", True),
    (".env", f"export DB_PASSWORD={DB}", True), (".env.prod", f"JWT_SECRET={DB}", True), ("a.json", f'  "clientSecret": "{DB}",', True), ("a.yml", "  password: 123456", True),
    ("a.yml", "  password: ${DB_PASSWORD}", False), ("a.yml", f"  password: ${{DB_PASSWORD:{DB}}}", True), ("a.yml", "  password: ${DB_PASSWORD:}", False), ("a.yml", "  password: ENC(abc123)", False), ("a.yml", "  password:", False), ("a.yml", "  password: {{ db_password }}", False),
    ("a.yml", "  token-header: X-Access-Token", False), ("a.yml", "  tokenExpire: 3600", False), ("a.yml", "  token: 3600", False), ("a.yml", "  password-encoder: bcrypt1", False),
    ("a.yml", "  secretName: db-cred1", False), ("a.yml", "  password: <your password>", False), ("messages_en.properties", "login_password_empty=Password2 is empty", False),
    ("a.yml", "  password: 请输入密码", False), ("a.json", '  "lockfileVersion": 3', False),
    ("a.xml", f'<property name="password" value="{DB}"/>', True), ("a.xml", f"<password>{DB}</password>", True), ("a.xml", "<password>${db.password}</password>", False),
    ("a.yml", f"  url: redis://:{DB}@10.0.0.1:6379/0", True), ("A.java", f'String u = "jdbc:mysql://h/d?user=r&password={DB}";', True), ("a.yml", "  url: http://h:8080/a@b", False),
    ("A.java", f'private static final String PASSWORD = "{DB}";', True), ("a.py", f"SECRET_KEY = '{DB}'", True), ("a.ts", f'const apiKey: string = "{DB}";', True), ("a.go", f'password := "{DB}"', True),
    ("A.java", f'DriverManager.getConnection(url, "root", "{DB}");', True), ("A.java", f'jedis.auth("{DB}");', True), ("a.vue", f"const token = '{DB}'", True),
    ("A.java", 'static final String PASSWORD = "password";', False), ("A.java", 'String TOKEN_KEY = "X-Access-Token";', False), ("A.java", '@RequiresPermissions("sys:user:resetPwd")', False),
    ("A.java", 'String msg = "password is wrong 3 times";', False), ("A.java", "String password = user.getPassword();", False), ("a.ts", "const password = `${a}1`;", False),
    ("A.java", 'String tokenUrl = "/oauth2/token1";', False), ("a.py", "password = os.environ['X1']", False),
    ("A.java", f'new SecretKeySpec("{KEY}".getBytes(), "AES");', True), ("A.java", f'Algorithm.HMAC256("{KEY}")', True), ("A.java", f'Jwts.parser().setSigningKey("{KEY}")', True),
    ("a.js", f"jwt.sign(payload, '{KEY}')", True), ("a.js", f"CryptoJS.enc.Utf8.parse('{KEY}')", True), ("a.py", f"AES.new(b'{KEY}', AES.MODE_ECB)", True),
    ("A.java", 'new SecretKeySpec(key.getBytes(), "AES");', False), ("a.js", "jwt.sign(payload, process.env.KEY)", False),
]


def rules(tmp) -> None:
    for i, (name, line, want) in enumerate(CASES):
        root = put(tmp / f"c{i}", {name: f"x\n{line}\n"})
        rows, _ = hardcoded.own(pathlib.Path(root))
        check(f"{'finds' if want else 'leaves'} {name}: {line.strip()[:60]}", bool(rows) is want and all(r["line"] == 2 for r in rows), rows)


def scanning(tmp) -> None:
    root = put(tmp / "app", {
        "src/main/resources/application.yml": f"db:\n  username: root\n  password: {DB}\naws: {AWS}\n",
        "src/main/java/Jwt.java": f'class Jwt {{\n  static String SECRET = "{KEY}"; // gitleaks:allow\n  String t() {{ return sign(SECRET); }}\n}}\n',
        "src/main/java/Shiro.java": f'class S {{ void a() {{ m.setCipherKey(Base64.decode("{SHIRO}")); }} }}\n',
        "src/test/resources/application-test.yml": f"password: {DB}\n", "conf/sample.yml": "password: changeme1\n",
        "target/classes/application.yml": f"password: {DB}\naws: {AWS}\n", "node_modules/x/a.yml": f"password: {DB}\n", "web/app.min.js": f"var password='{DB}'\n",
        "b.py": f"aws = '{AWS}'  # gitleaks:allow\n"})
    r = hardcoded.scan(root)
    recs = json.loads(pathlib.Path(r["artifacts"]["findings_json"]).read_text(encoding="utf-8"))
    at = {(x["file"], x["line"]): x for x in recs}
    yml, jwt = "src/main/resources/application.yml", "src/main/java/Jwt.java"
    check("both engines", r["ok"] and r["complete"] and r["by_engine"]["gitleaks"] >= 2 and r["by_engine"]["rules"] >= 2, (r["by_engine"], r["incomplete_reasons"]))
    check("passwords and tokens, at their line", {(yml, 3), (yml, 4), (jwt, 2), ("b.py", 1), ("src/main/java/Shiro.java", 1)} <= set(at), list(at))
    check("an allow comment does not hide anything", (jwt, 2) in at and at[("b.py", 1)]["rule_id"].startswith("gitleaks-"), at.keys())
    check("build output and vendored code are left out", not [f for f, _ in at if f.startswith(("target", "node_modules", "web"))], list(at))
    check("a public default key is critical", at[("src/main/java/Shiro.java", 1)]["severity"] == "critical", at[("src/main/java/Shiro.java", 1)])
    check("test and sample values rank low", at[("src/test/resources/application-test.yml", 1)]["severity"] == at[("conf/sample.yml", 1)]["severity"] == "low", at)
    check("reuse is shown", any("application-test.yml:1" in x for x in at[(yml, 3)]["also"]), at[(yml, 3)]["also"])
    check("everything waits for a judgement", {x["status"] for x in recs} == {"needs_review"} and all(x["suppress_key"] for x in recs))
    everything = "".join(p.read_text(encoding="utf-8") for p in pathlib.Path(r["artifacts"]["findings_json"]).parent.iterdir()) + json.dumps(r)
    check("no value is written anywhere", not [v for v in (DB, KEY, AWS, SHIRO) if v in everything], [v for v in (DB, KEY, AWS, SHIRO) if v in everything])
    check("nor left in the temp directory", not list(pathlib.Path(tempfile.gettempdir()).glob("sd-leaks-*/report.json")))
    check("hosts can run it", "secrets_scan" in [t[0] for t in toolset.TOOLS] and config.allowed("GITLEAKS_BIN"))

    (pathlib.Path(root) / ".gitleaks.toml").write_text('title="x"\n[allowlist]\npaths=["""(?s).*"""]\n'.replace('"""', "'''"), encoding="utf-8")
    (pathlib.Path(root) / ".gitleaksignore").write_text("\n".join(f"{(pathlib.Path(root) / f).as_posix()}:{x['rule_id'].removeprefix('gitleaks-')}:{n}" for (f, n), x in at.items()) + "\n", encoding="utf-8")
    again, gaps = hardcoded.collect(root)
    check("the project cannot switch it off", {(x["file"], x["line"]) for x in again} >= set(at) and not gaps, (set(at) - {(x["file"], x["line"]) for x in again}, gaps))
    os.environ["GITLEAKS_CONFIG"] = str(pathlib.Path(root) / ".gitleaks.toml")
    check("nor can the environment", len(hardcoded.collect(root)[0]) == len(again))
    os.environ.pop("GITLEAKS_CONFIG")

    real = hardcoded.binary
    hardcoded.binary = lambda: ""
    r = hardcoded.scan(root)
    check("without gitleaks: our rules, and a gap", r["ok"] and r["complete"] is False and "没有找到 gitleaks" in r["incomplete_reasons"][0] and r["reportable"])
    hardcoded.binary = lambda: sys.executable
    check("a broken gitleaks is a gap too", "没有跑成" in hardcoded.scan(root)["incomplete_reasons"][0])
    hardcoded.binary = real
    check("no such path is an error", not hardcoded.scan(str(tmp / "nope"))["ok"])


def judging(tmp) -> None:
    root = put(tmp / "app", {"application.yml": f"db:\n  password: {DB}\n", "Jwt.java": f'class Jwt {{\n  static String SECRET = "{KEY}";\n  String t() {{ return sign(SECRET); }}\n}}\n', "conf/sample.yml": "password: changeme1\n"})
    p = projects.add(root)["project"]
    projects.save_artifact(root, "secrets", hardcoded.scan(root))
    u = next(x for x in audit.plan(root) if x["kind"] == "secret")
    ids = {r["file"]: f"S{i}" for i, r in enumerate(u["secrets"], 1)}
    data = audit.load(root)
    t = audit.task(audit.spec(u, root, data))
    check("the agent is told where, not what", "application.yml:2" in t.prompt and not [v for v in (DB, KEY) if v in t.prompt + json.dumps(audit.spec(u, root, data))])
    ev = lambda f, n, q: [{"file": f, "line": n, "quote": q}]
    item = lambda f, v, **k: {"id": ids[f], "verdict": v, "reason": "r", **k}
    good = [item("application.yml", "real", what=f"生产库，口令 {DB}", severity="critical", evidence=ev("application.yml", 2, f"password: {DB}")),
            item("Jwt.java", "real", what="签发 JWT", severity="high", evidence=ev("Jwt.java", 3, "return sign(SECRET);")), item("conf/sample.yml", "placeholder", evidence=ev("conf/sample.yml", 1, "password:"))]
    bad = lambda *rows: t.validate({"items": list(rows)})[1]
    check("every one needs an answer", "还没有结论" in bad(*good[:2]))
    check("a verdict needs evidence that holds", "能核对的 evidence" in bad({**good[0], "evidence": ev("application.yml", 2, "nothing like it")}, *good[1:]))
    check("real needs what it opens and how bad", "能打开什么" in bad({**good[0], "what": ""}, *good[1:]) and "severity" in bad({**good[0], "severity": "x"}, *good[1:]))
    value, why = t.validate({"items": good})
    check("a full answer is accepted", value and not why, why)
    check("values are struck from what the agent hands in", not [v for v in (DB, KEY) if v in json.dumps(value, ensure_ascii=False)] and "***" in value["items"][ids["application.yml"]]["what"], value)
    audit.take(u, value, root, data)
    recs = {r["file"]: r for r in projects.findings(root, "secrets")}
    check("real is confirmed, with what it opens and its severity", recs["application.yml"]["status"] == "confirmed" and recs["application.yml"]["severity"] == "critical" and "生产库" in recs["application.yml"]["reason"], recs["application.yml"])
    check("a placeholder waits for a person, it is not dropped", recs["conf/sample.yml"]["status"] == "needs_review" and "占位" in recs["conf/sample.yml"]["reason"])
    check("what is judged is not asked again", not [x for x in audit.plan(root) if x["kind"] == "secret"])
    check("the project list follows", projects.list_all()["projects"][0]["runs"]["secrets"]["summary"]["confirmed"] == 2, projects.list_all()["projects"][0]["runs"]["secrets"]["summary"])
    decisions.put(recs["application.yml"]["suppress_key"], "accepted_risk", "")
    now = {r["file"]: r for r in projects.findings(root, "secrets")}
    check("a person outranks the agent", now["application.yml"]["status"] == "rejected")
    decisions.put(recs["application.yml"]["suppress_key"], "")
    review.FILE.unlink()
    check("without the judgement the first severity is back", {r["file"]: r for r in projects.findings(root, "secrets")}["application.yml"]["severity"] == "high")
    (pathlib.Path(root) / "application.yml").write_text(f"db:\n  password: {DB}x\n", encoding="utf-8")
    check("a moved value cannot be read back by position into a wrong mask", hardcoded.raw({"file": "gone.yml", "line": 1, "span": [0, 3]}, pathlib.Path(root)) == "")
    found = {"findings": [{"title": "t", "cwe": "CWE-798", "severity": "high", "auth": "anonymous", "impact": f"泄露 {KEY}", "conditions": "", "fix": "", "chain": [{"role": "sink", "file": "Jwt.java", "line": 2, "quote": f'static String SECRET = "{KEY}";'}]}],
             "coverage": [], "uncovered": []}
    real, review.one = review.one, lambda *a, **k: {"verdict": "unavailable", "reason": "x"}
    audit.take({"kind": "hunt", "area": {"title": "x"}}, found, root, audit.load(root))
    review.one = real
    check("other agents' findings do not carry values either", KEY not in json.dumps(audit.load(root), ensure_ascii=False))

    import web.server as server
    from fastapi.testclient import TestClient
    web = TestClient(server.app, base_url="http://127.0.0.1:8770", headers={"X-SD-Token": server.TOKEN})
    md = web.get(f"/api/projects/{p['id']}/export/sast/md").text
    check("the report includes them, masked", "secret-config" in md and not [v for v in (DB, KEY) if v in md], md[:300])
    check("and the list does", web.get(f"/api/findings?project_id={p['id']}&kind=secrets").json()["total"] == 3)
    tasks.FILE = tmp / "tasks.json"
    check("it is a task like the other engines", tasks._RUN["secrets"](p, {})["ok"] and "secrets" in tasks.ENGINES)


def main() -> int:
    if not hardcoded.binary():
        print("FAIL: 没有 gitleaks，本套件不允许跳过")
        return 1
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        for fn in (rules, scanning, judging):
            print(f"-- {fn.__name__}")
            mine = tmp / fn.__name__
            mine.mkdir()
            projects.STORE, pipeline.SCANS_DIR, rulegen.OUT_DIR = mine / "store", mine / "scans", mine / "rules"
            review.FILE, decisions.FILE = mine / "r.json", mine / "d.json"
            fn(mine)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
