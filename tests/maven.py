"""Versions come from the parent chain and the BOMs, and what cannot be known is said. Offline."""

import json
import os
import pathlib
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import _env  # noqa: F401
from core import epss, gaps, maven, net, nvd, osv, pipeline, projects, sca, sca_triage
from core.engines import opengrep

FAILED: list[str] = []


def check(name: str, ok, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {str(detail)[:700]}"))
    if not ok:
        FAILED.append(name)


def gav(x: str, tag: str = "", **k) -> str:
    g, a, *v = x.split(":")
    return f"<groupId>{g}</groupId><artifactId>{a}</artifactId>" + (f"<version>{v[0]}</version>" if v and v[0] else "") + "".join(f"<{n}>{t}</{n}>" for n, t in k.items())


def dep(x: str, **k) -> str:
    return f"<dependency>{gav(x, **k)}</dependency>"


def pom(x: str, parent: str = "", deps=(), mgmt=(), props=None, packaging="", rel=None, extra="") -> str:
    g, a, *v = x.split(":")
    up = f"<parent>{gav(parent)}{'' if rel is None else f'<relativePath>{rel}</relativePath>'}</parent>" if parent else ""
    return (f'<?xml version="1.0"?><project xmlns="http://maven.apache.org/POM/4.0.0">{up}' + (f"<groupId>{g}</groupId>" if g else "") + f"<artifactId>{a}</artifactId>"
            + (f"<version>{v[0]}</version>" if v else "") + (f"<packaging>{packaging}</packaging>" if packaging else "")
            + "<properties>" + "".join(f"<{k}>{t}</{k}>" for k, t in (props or {}).items()) + "</properties>"
            + "<dependencyManagement><dependencies>" + "".join(mgmt) + "</dependencies></dependencyManagement><dependencies>" + "".join(deps) + f"</dependencies>{extra}</project>")


class World:
    def __init__(self, tmp: pathlib.Path):
        self.tmp, self.m2, self.public, self.asked = tmp, tmp / "m2", {}, []
        os.environ.update(MAVEN_REPO_LOCAL=str(self.m2), SCA_MAVEN="https://repo.test/maven")
        maven.CACHE = tmp / "cache"
        net.get_bytes = self.get

    def get(self, url, **k):
        self.asked.append(url)
        if url not in self.public:
            raise net.NotFound(url)
        return self.public[url].encode()

    def local(self, x: str, text: str) -> None:
        g, a, v = x.split(":")
        f = self.m2 / g.replace(".", "/") / a / v / f"{a}-{v}.pom"
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_text(text, encoding="utf-8")

    def publish(self, x: str, text: str) -> None:
        g, a, v = x.split(":")
        self.public[f"https://repo.test/maven/{g.replace('.', '/')}/{a}/{v}/{a}-{v}.pom"] = text

    def project(self, name: str, files: dict) -> str:
        for k, t in files.items():
            f = self.tmp / name / k
            f.parent.mkdir(parents=True, exist_ok=True)
            f.write_text(t, encoding="utf-8")
        return str(self.tmp / name)


def got(r: dict) -> dict:
    return {c["name"]: c for c in r["components"]}


def versions(tmp) -> None:
    w = World(tmp / "ws")
    w.publish("org.lib:web:1.0", pom("org.lib:web:1.0", deps=[dep("org.lib:core:1.0"), dep("org.lib:opt:1.0", optional="true"), dep("org.lib:t:1.0", scope="test"), dep("org.lib:bad:1.0"), dep("org.lib:deep:1.0")]))
    w.publish("org.lib:core:2.0", pom("org.lib:core:2.0", deps=[dep("org.lib:deep:9.9")]))
    w.publish("org.lib:deep:1.0", pom("org.lib:deep:1.0", deps=[dep("org.lib:deeper:${v}")], props={"v": "4.4"}))
    w.publish("org.lib:deeper:4.4", pom("org.lib:deeper:4.4"))
    w.publish("org.lib:bom:7", pom("org.lib:bom:7", mgmt=[dep("org.lib:core:${c}"), dep("org.lib:fromparent:0.1")], props={"c": "2.0"}, packaging="pom"))
    w.publish("org.lib:fromparent:3.3", pom("org.lib:fromparent:3.3"))
    w.publish("org.lib:rt:1.0", pom("org.lib:rt:1.0"))
    w.publish("org.lib:junit:4", pom("org.lib:junit:4", deps=[dep("org.lib:hamcrest:1")]))
    w.publish("org.lib:hamcrest:1", pom("org.lib:hamcrest:1"))
    w.publish("org.lib:neg:1.0", pom("org.lib:neg:1.0", deps=[dep("org.lib:managed")],
              extra=f"<profiles><profile><id>p</id><activation><property><name>!skip</name></property></activation><dependencyManagement><dependencies>{dep('org.lib:managed:5.5')}</dependencies></dependencyManagement></profile></profiles>"))
    w.publish("org.lib:managed:5.5", pom("org.lib:managed:5.5"))
    root = w.project("repos/app", {
        "pom.xml": pom(":app", "com.corp.build:parent:1", packaging="pom", rel=""),
        "api/pom.xml": pom(":api", "com.corp.build:app:1.0"),
        "core/pom.xml": pom(":core-app", "com.corp.build:app:1.0", deps=[
            dep("com.corp.build:api:${project.version}"), f"<dependency>{gav('org.lib:web:1.0')}<exclusions><exclusion>{gav('org.lib:bad')}</exclusion></exclusions></dependency>",
            dep("org.lib:fromparent"), dep("org.lib:rt:1.0", scope="runtime"), dep("org.lib:junit:4", scope="test"), dep("org.lib:neg:1.0"), dep("org.lib:nowhere")])})
    (pathlib.Path(root) / "pom.xml").write_text(pom(":app:1.0", "com.corp.build:parent:1", packaging="pom", rel=""), encoding="utf-8")
    w.project("repos/fw/parent", {"pom.xml": pom("com.corp.build:parent:1", mgmt=[dep("org.lib:fromparent:3.3"), dep("org.lib:bom:7", type="pom", scope="import")], packaging="pom")})
    r = maven.resolve(root)
    c = got(r)
    check("a private parent is found beside the project", "com.corp.build:parent:1" in r["sources"] and not [x for x in r["missing"] if "父 POM" in x["what"]], r["missing"])
    check("and never asked for outside", not [u for u in w.asked if "com/corp" in u], w.asked)
    check("what it manages has its version, before a BOM's", c["fromparent"]["version"] == "3.3" and c["fromparent"]["direct"], c.get("fromparent"))
    check("a BOM decides indirect versions over what a library declares", c["core"]["version"] == "2.0" and not c["core"]["direct"], c.get("core"))
    check("the nearest declaration wins", c["deep"]["version"] == "1.0", c.get("deep"))
    check("properties are filled in", c["deeper"]["version"] == "4.4" and c["deeper"]["via"] == "web > deep > deeper", c.get("deeper"))
    check("excluded, optional and a library's test dependencies are left out", not {"bad", "opt", "t"} & set(c), sorted(c))
    check("scopes are kept", c["rt"]["scope"] == "runtime" and c["junit"]["scope"] == "test" and c["hamcrest"]["scope"] == "test" and c["web"]["scope"] == "compile")
    check("a profile that is on unless turned off counts", c["managed"]["version"] == "5.5", c.get("managed"))
    check("the project's own modules are not dependencies", not {"api", "app", "core-app"} & set(c))
    check("a version nobody gives is said so, not guessed", [u["name"] for u in r["unversioned"]] == ["nowhere"] and not r["complete"], r["unversioned"])
    n = len(w.asked)
    maven.resolve(root)
    check("what was fetched, and what is not there, is remembered", len(w.asked) == n, w.asked[n:])
    os.environ["SCA_MAVEN"] = "0"
    maven.CACHE = tmp / "cache2"
    r = maven.resolve(root)
    check("turned off, nothing is fetched, and what is unknown shows", len(w.asked) == n and any("BOM org.lib:bom:7" in x["what"] for x in r["missing"]) and any("依赖树 org.lib:web" in x["what"] for x in r["missing"]), r["missing"])
    check("nor over plain http", not (os.environ.update(SCA_MAVEN="http://x"), maven.remote())[1])


def unknowns(tmp) -> None:
    w = World(tmp / "ws2")
    w.publish("org.lib:old:1.0", pom("org.lib:old:1.0", deps=[dep("org.lib:framework:2.5")]))
    w.publish("org.lib:framework:2.5", pom("org.lib:framework:2.5"))
    root = w.project("alone/app", {"pom.xml": pom("com.corp.x:app:1", "com.corp.x:gone:9", deps=[dep("org.lib:old:1.0"), dep("org.lib:starter"), dep("com.corp.x:sdk:2.0")])})
    r = maven.resolve(root)
    c = got(r)
    check("a parent out of reach is reported", any(x["what"] == "父 POM com.corp.x:gone:9" for x in r["missing"]), r["missing"])
    check("what it might have managed is marked as guessed", c["framework"].get("guessed") and not c["old"].get("guessed"), c)
    check("so is a private artifact whose tree is unknown", any("依赖树 com.corp.x:sdk:2.0" in x["what"] for x in r["missing"]))
    w.project("alone/sdk", {"pom.xml": pom("com.corp.x:sdk:1.9", deps=[dep("org.lib:framework:2.5")])})
    maven.CACHE = tmp / "c3"
    r = maven.resolve(root)
    check("a neighbouring version shows roughly what hangs under it, marked", any("按相邻的 1.9 推测" in x["what"] for x in r["missing"]) and got(r)["sdk"]["version"] == "2.0" and not got(r)["sdk"].get("guessed"), r["missing"])
    for bad in ('<!DOCTYPE x [<!ENTITY a "b">]><project><artifactId>x</artifactId></project>', "<html/>", "<project>", "x" * 10):
        try:
            maven.Pom(bad)
            check(f"not a POM: {bad[:20]}", False)
        except Exception:
            check(f"not a POM: {bad[:20]}", True)
    f = maven.Finder(pathlib.Path(root))
    w.asked.clear()
    check("a coordinate cannot lead elsewhere", f.get("..", "a/../../b", "1") is None and f.get("g", "a", "../x") is None and not w.asked)
    loop = w.project("loop/app", {"pom.xml": pom("com.y.z:a:1", "com.y.z:b:1", rel=""), "b/pom.xml": pom("com.y.z:b:1", "com.y.z:a:1", rel="", packaging="pom")})
    check("a parent loop ends", maven.resolve(loop) is not None)
    (tmp / "empty").mkdir()
    check("no POM, no answer", maven.resolve(str(tmp / "empty")) is None)


def dependencies(tmp) -> None:
    w = World(tmp / "ws3")
    w.publish("org.lib:a:1.0", pom("org.lib:a:1.0", deps=[dep("org.lib:b:1.0")]))
    w.publish("org.lib:b:2.0", pom("org.lib:b:2.0"))
    root = w.project("r/app", {"pom.xml": pom("com.corp.q:app:1", deps=[dep("org.lib:a:1.0"), dep("org.lib:tt:1.0", scope="test")], mgmt=[dep("org.lib:b:2.0")])})
    comp = lambda n, v, path="app\\pom.xml\\[x]", lang="Java": {"vendor": "org.lib", "name": n, "version": v, "language": lang, "direct": n == "a", "paths": [path]}
    sca.run_opensca = lambda r, timeout_s=0: {"ok": True, "components": [comp("a", "1.0"), comp("b", "1.0"), {**comp("left-pad", "1.3.0", "app\\package-lock.json", "JavaScript"), "vendor": ""}]}
    nvd.lookup = lambda k, v=None, group="": {"ok": True, "cached": True, "affected": [{"id": "CVE-2020-1", "score": 9.0, "cwes": [], "summary": ""}] if (k, v) == ("b", "1.0") else []}
    epss.scores = lambda ids: {}
    os.environ["SCA_OSV"] = "0"
    r = sca.enrich(root)
    have = {(c["name"], c["version"]) for c in r["components"]}
    check("the POMs overrule OpenSCA for Maven, and nothing else", ("b", "2.0") in have and ("b", "1.0") not in have and ("left-pad", "1.3.0") in have, have)
    check("so the wrong version's CVE is gone", not [c for c in r["components"] if c.get("cves")])
    check("test dependencies are listed, not looked up", r["test_skipped"] == 1 and r["complete"], (r["test_skipped"], r["incomplete_reasons"]))
    (pathlib.Path(root) / "pom.xml").write_text(pom("com.corp.q:app:1", "com.corp.q:lost:1", deps=[dep("org.lib:a:1.0")]), encoding="utf-8")
    nvd.lookup = lambda k, v=None, group="": {"ok": True, "cached": True, "affected": [{"id": "CVE-2020-1", "score": 9.0, "cwes": [], "summary": ""}] if k == "b" else []}
    w.publish("org.lib:b:1.0", pom("org.lib:b:1.0"))
    maven.CACHE = tmp / "c4"
    r = sca.enrich(root)
    check("a lost parent makes it incomplete, in so many words", r["complete"] is False and any("父 POM com.corp.q:lost:1" in x for x in r["incomplete_reasons"]), r["incomplete_reasons"])
    check("a guessed version is something to settle", any(u["name"] == "b" and "推测" in u["reason"] for u in r["unresolved"]), r["unresolved"])
    t = sca_triage.triage(r, app_root=root)
    check("and its CVEs are marked", [k.get("guessed") for k in t["kept"] if k["dependency"] == "b"] == [True], t["kept"])
    from core import audit
    projects.save_artifact(root, "triage", t)
    check("no agent judges CVEs of a guessed version", not [u for u in audit.plan(root, ["dependency"]) if u["kind"] == "dependency"])
    gaps.save(root, {f"org.lib:b@1.0": {"verdict": "version", "version": "1.0", "reason": "r"}}, [])
    r = sca.enrich(root)
    check("once an agent has found it, they are", not [u for u in r["unresolved"] if u["name"] == "b"] and not next(c for c in r["components"] if c["name"] == "b").get("guessed"), r["unresolved"])


def depth(tmp) -> None:
    d = tmp / "deep"
    d.mkdir()
    n = 9
    (d / "C.java").write_text('import org.springframework.web.bind.annotation.*;\n@RestController\npublic class C {\n  private S1 s = new S1();\n  @GetMapping("/x")\n  public String x(@RequestParam String name) { return s.f(name); }\n}\n', encoding="utf-8")
    for i in range(1, n + 1):
        body = f"return new S{i + 1}().f(a);" if i < n else 'try { java.sql.Statement st = java.sql.DriverManager.getConnection("x").createStatement(); st.executeQuery("select \'" + a + "\'"); } catch (Exception e) {} return a;'
        (d / f"S{i}.java").write_text(f"public class S{i} {{\n  public String f(String a) {{ {body} }}\n}}\n", encoding="utf-8")
    os.environ.pop("AUDIT_INTERFILE_DEPTH", None)
    r = pipeline.scan(str(d), "java")
    check("a chain through nine files is found", r["ok"] and r["raw_hits"] == 1 and r["complete"], r.get("incomplete_reasons"))
    os.environ["AUDIT_INTERFILE_DEPTH"] = "3"
    check("which the engine's own default loses, and says so", pipeline.scan(str(d), "java")["raw_hits"] == 0)
    os.environ.pop("AUDIT_INTERFILE_DEPTH")
    F = lambda line: {"rule_id": "r", "file": "f", "line": line}
    runs = []

    def run(at):
        runs.append(at)
        return {"ok": True, "findings": [F(1), F(2)] if at else [F(2), F(3)], "error_items": []}
    got_ = pipeline._deep(True, run)
    check("what only the shallow search finds is added", [f["line"] for f in got_["findings"]] == [2, 3, 1] and runs == [None, "3"], (got_, runs))
    runs.clear()
    pipeline._deep(False, run)
    check("not on large projects", runs == [None])
    bad = pipeline._deep(True, lambda at: {"ok": not at, "findings": [], "error": "x", "error_items": []})
    check("a second search that fails is a gap, not a loss", bad["ok"] and any("浅层补扫" in e["message"] for e in bad["error_items"]))
    os.environ["AUDIT_INTERFILE_DEPTH"] = "x"
    check("a depth that is no number is refused", not opengrep.run_scan(str(d), rules=pipeline.rules_for("java"))["ok"])
    os.environ.pop("AUDIT_INTERFILE_DEPTH")


def main() -> int:
    saved = dict(os.environ)
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True, prefix="sd-maven-") as d:
        base = pathlib.Path(d) / "deep" / "enough"  # neighbours are looked for two levels up
        for fn in (versions, unknowns, dependencies, depth):
            print(f"-- {fn.__name__}")
            mine = base / fn.__name__
            mine.mkdir(parents=True)
            projects.STORE, pipeline.SCANS_DIR = mine / "store", mine / "scans"
            fn(mine)
    os.environ.clear()
    os.environ.update(saved)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
