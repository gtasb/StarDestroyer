"""JavaScript / TypeScript / Vue coverage, and compiling Java before the call graph.

Real Opengrep, offline. The build tool is a script.
"""

import json
import os
import pathlib
import sys
import tempfile
import zipfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
__import__("os").environ["SCA_OSV"] = "0"  # offline

import _env  # noqa: F401
from core import (audit, build, codeintel, config, decisions, endpoints, ledger, pipeline, profile, projects, review, rulegen, sca,
                  sca_triage, sfc, tasks, toolset)
from core.engines import opengrep

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:400]}"))
    if not ok:
        FAILED.append(name)


def put(d: pathlib.Path, files: dict) -> str:
    for k, v in files.items():
        (d / k).parent.mkdir(parents=True, exist_ok=True)
        (d / k).write_text(v, encoding="utf-8")
    codeintel._CACHE.clear()
    endpoints._CACHE.clear()
    return str(d.resolve())


APP = {
    "package.json": '{"dependencies": {"express": "^4.18.0", "lodash": "4.17.10", "vue": "2.6.0"}, "devDependencies": {"jest": "*"}}',
    "package-lock.json": '{"lockfileVersion": 3, "packages": {"": {}, "node_modules/express": {"version": "4.18.2"}, "node_modules/a/node_modules/@s/q": {"version": "1.0.0"}}}',
    "server/db.ts": "import { exec } from 'child_process';\nexport class Svc {\n  go(c: string) {\n    exec('ls ' + c);\n  }\n  static safe = (c: string) => c.trim();\n}\nexport const helper = async (a, b) => {\n  return new Svc().go(a);\n};\nexport function plain(x) { return /['\"`]/.test(x); }\nexport default { list: async (q) => { return q; } };\n",
    "server/app.ts": "import express from 'express';\nimport { Svc, helper } from './db';\nimport _ from 'lodash';\nconst app = express();\nconst users = express.Router();\nconst s = new Svc();\napp.use('/users', users);\napp.get('/run', (req, res) => { s.go(req.query.x as string); });\nusers.post('/:id', (req, res) => helper(req.body.a, 1));\napp.route('/multi').get((q, r) => 1).put((q, r) => 2);\nconst port = app.get('port');\n// app.get('/commented', f)\n",
    "web/Page.vue": "<template>\n  <div v-html=\"html\">it's</div>\n</template>\n<script>\nexport default {\n  mounted() {\n    this.$el.innerHTML = this.$route.query.q;\n  },\n}\n</script>\n<style>a{}</style>\n",
    "web/Setup.vue": "<template><b/></template>\n<script setup lang=\"ts\">\nconst q: string = location.hash\ndocument.write(q)\n</script>\n",
    "web/Plain.vue": "<template><b/></template>\n",
    "web/App.jsx": "export function A() { const h = location.hash; return <div dangerouslySetInnerHTML={{__html: h}} />; }\n",
    "node_modules/x/i.js": "eval(location.hash)\n",
    "dist/bundle.js": "eval(location.hash)\n",
    "web/lib.min.js": "eval(location.hash)\n",
    "web/types.d.ts": "declare const a: string;\n",
    "src/dist/Kept.js": "eval(location.hash)\n",
}


def scanning(tmp) -> None:
    root = put(tmp / "app", APP)
    (pathlib.Path(root) / "web/big.js").write_text("var a=1;" * 20000 + "eval(location.hash)", encoding="utf-8")
    prof = profile.profile(root)
    check("the project is recognised", prof["language"] == "js" and {"express", "vue"} <= set(prof["frameworks"]) and "lodash" in prof["dependencies"], prof)
    r = pipeline.scan(root)
    recs = pipeline.last_findings(root)
    at = {(x["file"], x["line"], x["rule_id"]) for x in recs}
    check("a chain across TypeScript files", ("server/db.ts", 4, "js-command-injection") in at, at)
    chain = next((x for x in recs if x["file"] == "server/db.ts"), {"trace": []})
    check("with its steps in both files", {s["file"] for s in chain["trace"]} == {"server/app.ts", "server/db.ts"}, chain)
    check("Vue options api, at the component's own line", ("web/Page.vue", 7, "js-dom-xss") in at, at)
    check("Vue script setup", ("web/Setup.vue", 4, "js-dom-xss") in at, at)
    vue = next((x for x in recs if x["file"] == "web/Page.vue"), {"trace": [], "suppress_key": ""})
    check("its trace points into the component", all(s["file"] == "web/Page.vue" for s in vue["trace"]) and vue["suppress_key"], vue)
    check("JSX", any(f == "web/App.jsx" for f, *_ in at), at)
    files = {x[0] for x in at}
    check("vendored, built and minified code is not audited", not files & {"node_modules/x/i.js", "dist/bundle.js", "web/lib.min.js", "web/big.js"}, files)
    check("a source directory called dist is", "src/dist/Kept.js" in files, files)
    cov = r["coverage"]
    check("nothing the project wrote is left out", r["complete"] and cov["units_skipped"] == 0 and cov["units_blocked"] == 0, (r["incomplete_reasons"], cov))
    left = set(ledger.excluded(root))
    check("what was left out on purpose is listed", {"node_modules", "dist", "web/lib.min.js", "web/big.js", "web/types.d.ts"} == left, left)
    check("the run says how many", cov.get("excluded") == 5, cov)
    check("a component without script is covered", "web/Plain.vue" not in (r.get("files_unscanned") or []))
    broken = pipeline.scan(put(tmp / "broken", {"a.vue": "<script>\nfunction ( {{{\n</script>\n", "b.js": "let a = 1;"}))
    check("a component that does not parse is a gap", broken["complete"] is False, broken.get("incomplete_reasons"))
    both = pipeline.scan(put(tmp / "both", {"A.java": "class A {}", "a.ts": "eval(location.hash);"}))
    check("a Java project's scripts are scanned with it", both["language"] == "java+js" and both["raw_hits"] == 1, both.get("language"))


def navigating(tmp) -> None:
    root = put(tmp / "app", APP)
    idx = codeintel.index(root)
    f = idx.files["server/db.ts"]
    got = {(m["owner"], m["name"], m["start"], m["end"]) for m in f.methods}
    check("methods, arrows and functions", {("Svc", "go", 3, 5), ("", "helper", 8, 10), ("", "plain", 11, 11), ("", "list", 12, 12)} <= got, got)
    check("calls are not definitions", not [m for m in f.methods if m["name"] in ("exec", "test", "trim")], got)
    callers = [(c["file"], c["line"]) for c in idx.callers("go", "Svc")]
    check("callers", ("server/app.ts", 8) in callers and ("server/db.ts", 9) in callers, callers)
    check("a regex literal does not swallow the rest", "list" in {m["name"] for m in f.methods})
    vue = idx.files["web/Page.vue"]
    check("a component's methods keep their lines", [(m["name"], m["start"]) for m in vue.methods] == [("mounted", 6)], vue.methods)
    sites = {(s["class"], s["file"], s["line"]) for s in codeintel.sink_sites(root)}
    check("sinks", {("cmd", "server/db.ts", 4), ("dom_xss", "web/Page.vue", 2), ("dom_xss", "web/Page.vue", 7), ("dom_xss", "web/Setup.vue", 4), ("dom_xss", "web/App.jsx", 1)} <= sites, sites)
    check("a comparison is not a sink", not [s for s in codeintel.sink_sites(put(tmp / "cmp", {"a.js": "if (a.innerHTML == b) { x.exec(y); }"}))])
    check("tests are not leads", not codeintel.sink_sites(put(tmp / "t", {"a.test.ts": "eval(x)", "__tests__/b.js": "eval(x)"})))
    eps = {(e["method"], e["path"]) for e in endpoints.extract(root)}
    check("express routes, mounted routers and route chains", eps == {("GET", "/run"), ("POST", "/users/:id"), ("GET", "/multi"), ("PUT", "/multi")}, eps)
    more = put(tmp / "more", {
        "n.ts": "@Controller('cats')\nexport class C {\n  @Get(':id')\n  a() {}\n  @Post()\n  b() {}\n}\n",
        "f.js": "const fastify = require('fastify')();\nfastify.route({ method: 'PUT', url: '/f', handler: h });\nfastify.get('/g', h);\n",
        "k.js": "const Router = require('koa-router');\nconst r1 = 1; const apiRouter = new Router({ prefix: '/k' });\napiRouter.get('/x', f);\n",
        "app/(shop)/api/items/route.ts": "export async function GET(req) {}\nexport const POST = f;\n",
        "pages/api/users/index.ts": "export default function h(req, res) {}\n",
        "server/api/hello.get.ts": "export default defineEventHandler(() => 1)\n",
        "client.ts": "import axios from 'axios';\nconst api = axios.create();\napi.get('/not-a-route', { a: 1 });\naxios.get('/nor-this', c);\n"})
    eps = {(e["method"], e["path"]) for e in endpoints.extract(more)}
    check("nest, fastify, koa, next and nuxt", eps == {("GET", "/cats/:id"), ("POST", "/cats"), ("PUT", "/f"), ("GET", "/g"), ("GET", "/k/x"), ("GET", "/api/items"),
                                                       ("POST", "/api/items"), ("ANY", "/api/users"), ("GET", "/api/hello")}, eps)
    kinds = {u["kind"] for u in audit.plan(root)}
    check("the agent gets sinks and endpoints to work on", {"brief", "sink", "endpoint"} <= kinds, kinds)


def packages(tmp) -> None:
    root = put(tmp / "app", APP)
    got = {(c["name"], c["version"]) for c in sca.builtin(root)["components"]}
    check("lock file versions, nested and scoped", {("express", "4.18.2"), ("@s/q", "1.0.0")} <= got, got)
    check("a range is not a version", ("vue", "2.6.0") in got and ("lodash", "4.17.10") in got and ("jest", "") in got, got)
    y = put(tmp / "y", {"package.json": '{"dependencies": {"a": "^1"}}', "yarn.lock": '"@b/c@^2.0.0", "@b/c@^2.1.0":\n  version "2.1.3"\n\na@^1:\n  version "1.2.0"\n'})
    check("yarn", {("@b/c", "2.1.3"), ("a", "1.2.0")} == {(c["name"], c["version"]) for c in sca.builtin(y)["components"]}, sca.builtin(y))
    p = put(tmp / "p", {"package.json": '{"dependencies": {"a": "^1"}}', "pnpm-lock.yaml": "packages:\n\n  '@b/c@2.1.3':\n    resolution: {}\n\n  a@1.2.0(x@1):\n    resolution: {}\n\n  /old@3.0.0:\n    x: 1\n"})
    check("pnpm", {("@b/c", "2.1.3"), ("a", "1.2.0"), ("old", "3.0.0")} == {(c["name"], c["version"]) for c in sca.builtin(p)["components"]}, sca.builtin(p))
    check("a broken manifest is not a crash", sca.builtin(put(tmp / "z", {"package.json": "{", "a/package.json": "[]"}))["components"] == [])
    used = sca_triage._usage(root, {"name": "lodash", "language": "JavaScript"})
    check("imports are found", used["used"] and "server/app.ts:3" in used["evidence"][0], used)
    none = sca_triage._usage(root, {"name": "jest", "language": "JavaScript"})
    check("no import does not prove a package unused", not none["used"] and not none["conclusive"], none)


POM = "<project><modelVersion>4.0.0</modelVersion><groupId>g</groupId><artifactId>a</artifactId><version>1</version></project>"
FAKE = '''import json, os, pathlib, sys, zipfile
pathlib.Path(os.environ["TEMP"], "fake-mvn.json").write_text(json.dumps({"cwd": os.getcwd(), "argv": sys.argv[1:], "env": sorted(os.environ)}))
here = pathlib.Path.cwd()
plan = json.loads((here / "plan.json").read_text()) if (here / "plan.json").exists() else {}
for name, entry in plan.get("jars", {"target/app.jar": "BOOT-INF/classes/A.class"}).items():
    (here / name).parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(here / name, "w") as z: z.writestr(entry, b"x")
print("[ERROR] A.java:[1,2] cannot find symbol" if plan.get("exit") else "BUILD SUCCESS")
sys.exit(plan.get("exit", 0))
'''


def compiling(tmp) -> None:
    build.WORK = tmp / "builds"
    fake, seen = tmp / "fake.py", pathlib.Path(os.environ["TEMP"], "fake-mvn.json")
    fake.write_text(FAKE, encoding="utf-8")
    real, build._command = build._command, lambda root, kind: [sys.executable, str(fake), kind, *build._MVN_ARGS]
    os.environ["DEEPSEEK_API_KEY"] = os.environ["LLM_KEY_X"] = "secret"
    root = put(tmp / "p", {"pom.xml": POM, "src/main/java/build/A.java": "class A {}", "target/old.jar": "x", "node_modules/x/pom.xml": POM, ".git/c": "x"})
    r = build.run(root)
    check("a build gives a target", r["ok"] and pathlib.Path(r["target"]).name == "app.jar" and not r["notes"], r)
    call = json.loads(seen.read_text())
    check("on a copy", not pathlib.Path(call["cwd"]).resolve().is_relative_to(root), call["cwd"])
    check("the audited tree is untouched", sorted(p.name for p in (pathlib.Path(root) / "target").iterdir()) == ["old.jar"])
    check("without our keys", not [k for k in call["env"] if "KEY" in k.upper()], call["env"])
    check("without running tests", "-Dmaven.test.skip=true" in call["argv"])
    seen.unlink()
    check("unchanged source is not built again", build.run(root)["reused"] and not seen.exists())
    (pathlib.Path(root) / "src/main/java/build/A.java").write_text("class A { int x; }", encoding="utf-8")
    check("changed source is", not build.run(root)["reused"])
    check("a package called build is kept, output and vendored code is not", {f.relative_to(root).as_posix() for f in build._files(pathlib.Path(root))} == {"pom.xml", "src/main/java/build/A.java"})
    thin = put(tmp / "thin", {"pom.xml": POM, "plan.json": json.dumps({"jars": {"m1/target/a.jar": "x/A.class", "m2/target/b.jar": "x/B.class", "m1/target/a-sources.jar": "A.java",
                                                                                "m1/target/a-tests.jar": "x/T.class", "target/original-app.jar": "x/A.class", "lib/c.jar": "x/C.class"}})})
    r = build.run(thin)
    check("modules without a runnable jar go in together, and that is a gap", r["jars"] == ["a.jar", "b.jar"] and pathlib.Path(r["target"]).is_dir() and "第三方依赖" in r["notes"][0], r)
    part = put(tmp / "part", {"pom.xml": POM, "plan.json": json.dumps({"exit": 1})})
    r = build.run(part)
    check("a partial build is used, and is a gap", r["ok"] and "没有完整编译" in r["notes"][0] and r["tail"], r)
    check("and is tried again", not build.run(part)["reused"])
    none = build.run(put(tmp / "none", {"pom.xml": POM, "plan.json": json.dumps({"exit": 1, "jars": {}})}))
    check("no output is a failure, with the compiler's words", not none["ok"] and "cannot find symbol" in none["error"], none)
    many = put(tmp / "many", {"a/pom.xml": POM, "a/sub/pom.xml": POM, "b/build.gradle": "", "c/x.txt": ""})
    check("every topmost build is found", [(r.name, k) for r, k in build.roots(many)] == [("a", "maven"), ("b", "gradle")], build.roots(many))
    build._command = real
    check("nothing to build is said so", "没有找到" in build.run(put(tmp / "empty", {"A.java": "class A {}"}))["error"])

    which, build.shutil.which = build.shutil.which, lambda n: None
    check("a missing tool is said so", "Maven" in build.why_not(root), build.why_not(root))
    g = put(tmp / "g", {"build.gradle": "", "gradlew.bat": "", "gradlew": ""})
    check("a Gradle wrapper will do", not build.why_not(g))
    build.shutil.which = which
    for k in ("DEEPSEEK_API_KEY", "LLM_KEY_X"):
        os.environ.pop(k)


def task(tmp) -> None:
    projects.STORE, tasks.FILE = tmp / "store", tmp / "tasks.json"
    root = put(tmp / "p", {"pom.xml": POM})
    p = projects.add(root, build="")["project"]
    m = tasks.Manager()
    check("no jar and no build option is refused", not m.submit(p, "tabby")["ok"])
    p = projects.edit(p["id"], {"build": "auto"})["project"]
    check("the option is stored", projects.get(p["id"])["build"] == "auto")
    real, seen = (build.run, pipeline.tabby_audit), []
    build.run = lambda path: {"ok": True, "target": str(tmp / "built.jar"), "jars": ["built.jar"], "notes": ["缺口"], "tail": [], "reused": False}
    pipeline.tabby_audit = lambda target, *a, **k: (seen.append(target), {"ok": True, "complete": True, "incomplete_reasons": [], "chains": 0})[-1]
    r = tasks._tabby({**p, "jar": "old.jar"}, {})
    check("the call graph reads what was built", seen == [str(tmp / "built.jar")] and r["complete"] is False and r["incomplete_reasons"] == ["缺口"], (seen, r))
    tasks._tabby(p, {"jar": "explicit.jar"})
    check("a jar named for this run wins", seen[-1] == "explicit.jar")
    build.run = lambda path: {"ok": False, "error": "编译没有产出 jar", "tail": ["x"]}
    check("a failed build is a failed task", tasks._tabby(p, {})["error"] == "编译没有产出 jar" and len(seen) == 2)
    build.run, pipeline.tabby_audit = real
    check("hosts can build", "java_build" in [t[0] for t in toolset.TOOLS] and config.allowed("BUILD_JAVA_HOME"))


def main() -> int:
    if not opengrep.capabilities().get("available"):
        print("FAIL: opengrep 不可用，本套件不允许跳过")
        return 1
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        for fn in (scanning, navigating, packages, compiling, task):
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
