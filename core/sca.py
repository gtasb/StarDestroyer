"""Software composition analysis.

OpenSCA gives the dependency tree (including indirect deps); it does not ship
a vulnerability database, so CVE mapping goes through NVD here. When OpenSCA is
absent, versions are parsed from the build files directly -- less complete, but
it still produces evidence.
"""

import json
import os
import pathlib
import re
import subprocess
import tempfile

from . import nvd, proc as procs
from .profile import _walk

def opensca_bin() -> str:
    env = os.environ.get("OPENSCA_BIN")
    if env:
        return env
    here = pathlib.Path(__file__).resolve()
    for base in (here.parents[2], here.parents[3]):
        for name in ("opensca-cli.exe", "opensca-cli"):
            cand = base / ".work" / "opensca" / "bin" / name
            if cand.exists():
                return str(cand)
    return ""

_BUILD = ("pom.xml", "build.gradle", "requirements.txt", "package.json")
_MANIFESTS = {*_BUILD, "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "go.mod", "go.sum", "pyproject.toml", "poetry.lock", "settings.gradle"}


def available() -> bool:
    return bool(opensca_bin()) and pathlib.Path(opensca_bin()).exists()


def _flatten(node: dict, depth: int = 0) -> list[dict]:
    out = [{
        "vendor": node.get("vendor", ""),
        "name": node.get("name", ""),
        "version": node.get("version", ""),
        "language": node.get("language", ""),
        "direct": bool(node.get("direct")),
        "root": depth == 0,
        "paths": node.get("paths", []),
    }]
    for child in node.get("children") or []:
        out.extend(_flatten(child, depth + 1))
    return out


def run_opensca(root: str, timeout_s: int = 300) -> dict:
    if not available():
        return {"ok": False, "error": "OpenSCA 未安装"}
    fd, out = tempfile.mkstemp(suffix=".json", prefix="sca-")
    os.close(fd)
    try:
        proc = procs.run([opensca_bin(), "-path", str(pathlib.Path(root).resolve()), "-out", out],
                         timeout=timeout_s, cwd=tempfile.gettempdir())  # it drops a log in cwd
        if not pathlib.Path(out).exists() or pathlib.Path(out).stat().st_size == 0:
            return {"ok": False, "error": "OpenSCA 未产出报告",
                    "stderr": (proc.stderr or "")[-800:]}
        doc = json.loads(pathlib.Path(out).read_text(encoding="utf-8", errors="replace"))
        comps = _flatten(doc)
        return {"ok": True, "components": comps, "task": doc.get("task_info", {})}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"OpenSCA 超时（{timeout_s}s）"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}
    finally:
        pathlib.Path(out).unlink(missing_ok=True)


def builtin(root: str) -> dict:
    """Fallback: versions straight from build descriptors."""
    p = pathlib.Path(root)
    comps: list[dict] = []
    for anc in (p, p.parent):
        if anc is not p and comps:
            break  # the parent's descriptor is only a stand-in when ours is missing
        pom = anc / "pom.xml"
        if pom.exists():
            text = pom.read_text(encoding="utf-8", errors="replace")
            text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
            for block in re.findall(r"<dependency>(.*?)</dependency>", text, re.S):
                art = re.search(r"<artifactId>\s*([^<\s]+)", block)
                ver = re.search(r"<version>\s*([^<\s]+)", block)
                grp = re.search(r"<groupId>\s*([^<\s]+)", block)
                if art:
                    comps.append({"vendor": grp.group(1) if grp else "", "name": art.group(1),
                                  "version": ver.group(1) if ver else "", "language": "Java",
                                  "direct": True, "paths": [str(pom)]})
        gradle = next((anc / n for n in ("build.gradle", "build.gradle.kts")
                       if (anc / n).exists()), None)
        if gradle:
            for g, a, v in re.findall(r"""['"]([\w.\-]+):([\w.\-]+):([\w.\-]+)['"]""",
                                      gradle.read_text(encoding="utf-8", errors="replace")):
                comps.append({"vendor": g, "name": a, "version": v, "language": "Java",
                              "direct": True, "paths": [str(gradle)]})
        req = anc / "requirements.txt"
        if req.exists():
            for line in req.read_text(encoding="utf-8", errors="replace").splitlines():
                # unpinned requirements are listed too: they end up unresolved, not gone
                m = re.match(r"\s*([A-Za-z0-9][\w.\-]*)(?:\[[^\]]*\])?\s*(?:==\s*([\w.\-]+))?", line)
                if m:
                    comps.append({"vendor": "", "name": m.group(1), "version": m.group(2) or "",
                                  "language": "Python", "direct": True, "paths": [str(req)]})
    comps += _npm(p)
    return {"ok": True, "components": comps, "task": {"error": "builtin parser"}}


def _npm(root: pathlib.Path) -> list[dict]:
    """npm packages: resolved versions from a lock file, else what package.json pins."""
    out = []

    def add(name, version, f, direct):
        if name:
            out.append({"vendor": "", "name": name, "version": version, "language": "JavaScript", "direct": direct, "paths": [str(f)]})
    for f in _walk(root) if root.is_dir() else []:
        if f.name != "package.json":
            continue
        try:
            doc = json.loads(f.read_text(encoding="utf-8", errors="replace"))
        except (OSError, ValueError):
            continue
        wanted = {k: str(v) for sec in ("dependencies", "optionalDependencies", "devDependencies")
                  for k, v in (doc.get(sec) if isinstance(doc, dict) and isinstance(doc.get(sec), dict) else {}).items()}
        try:
            got = _lock(f.parent)
        except (OSError, ValueError):
            got = set()
        for name, version in sorted(got):
            add(name, version, f.parent, name in wanted)
        for name, spec in wanted.items():
            if name not in {n for n, _ in got}:  # a range is not a version: unresolved, not guessed
                add(name, spec if re.fullmatch(r"\d+\.\d+\.\d+[\w.\-]*", spec) else "", f, True)
    return out


def _lock(d: pathlib.Path) -> set[tuple[str, str]]:
    npm, yarn, pnpm = d / "package-lock.json", d / "yarn.lock", d / "pnpm-lock.yaml"
    if npm.is_file():
        doc = json.loads(npm.read_text(encoding="utf-8", errors="replace"))
        if isinstance(doc.get("packages"), dict):
            return {(k.rsplit("node_modules/", 1)[1], str(v.get("version") or "")) for k, v in doc["packages"].items() if "node_modules/" in k}
        out, todo = set(), [doc.get("dependencies") or {}]
        while todo:
            for k, v in todo.pop().items():
                out.add((k, str(v.get("version") or "")))
                todo.append(v.get("dependencies") or {})
        return out
    if yarn.is_file():
        return set(re.findall(r'^"?(@?[^@\s"]+)@[^\n]*:\n\s+version:?\s+"?([^\s"]+)', yarn.read_text(encoding="utf-8", errors="replace"), re.M))
    if pnpm.is_file():
        return set(re.findall(r"^  '?/?(@?[^@\s'()]+)@(\d[\w.\-]*)[^\n]*:\s*$", pnpm.read_text(encoding="utf-8", errors="replace"), re.M))
    return set()


def _own_modules(root: str) -> set[tuple[str, str]]:
    """(groupId, artifactId) of every pom.xml under root."""
    out = set()
    for f in _walk(pathlib.Path(root)):
        if f.name != "pom.xml":
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        text = re.sub(r"<!--.*?-->", "", text, flags=re.S)
        parent = re.search(r"<parent>(.*?)</parent>", text, re.S)
        # What is left after removing nested sections is the project's own identity.
        head = re.sub(r"<(parent|dependencies|dependencyManagement|build|profiles|plugins|reporting)>.*?</\1>",
                      "", text, flags=re.S)
        art = re.search(r"<artifactId>\s*([^<\s]+)", head)
        grp = re.search(r"<groupId>\s*([^<\s]+)", head) or (parent and re.search(r"<groupId>\s*([^<\s]+)", parent.group(1)))
        if art:
            out.add((grp.group(1) if grp else "", art.group(1)))
    return out


def components(root: str) -> dict:
    """OpenSCA's tree, with everything Maven decides put right from the POMs themselves."""
    from . import maven
    res, mv = _opensca(root), None
    if pathlib.Path(root).is_dir():
        try:
            mv = maven.resolve(root)
        except Exception as exc:  # a POM nobody thought of must not cost the scan
            from . import logging
            logging.warn("maven", "resolve failed", path=root, error=f"{type(exc).__name__}: {exc}")
    if not mv or not (mv["components"] or mv["unversioned"]):
        return res
    known = {(c["vendor"], c["name"]) for c in [*mv["components"], *mv["unversioned"]]}
    kept = []
    for c in res.get("components") or []:
        from_pom = any("pom.xml" in p for p in c.get("paths") or [])
        if c.get("root") or not from_pom:
            kept.append(c)
        elif (c["vendor"], c["name"]) not in known and not mv["complete"]:
            kept.append({**c, "guessed": True})  # somebody's declaration, which the project may overrule
    return {**res, "ok": True, "source": "maven+opensca" if res.get("source") == "opensca" else "maven", "components": kept + mv["components"] + mv["unversioned"],
            "opensca_error": "", "maven": {k: mv[k] for k in ("missing", "sources", "modules", "complete", "timed_out")}}


def _opensca(root: str) -> dict:
    res = run_opensca(root)
    # Modules of a multi-module project show up as components of their own.
    own = _own_modules(root)
    for c in res.get("components") or []:
        if (c["vendor"], c["name"]) in own:
            c["root"] = True
    # The same artifact hangs under many parents; once is enough.
    uniq: dict[tuple, dict] = {}
    for c in res.get("components") or []:
        kept = uniq.setdefault((c["vendor"], c["name"], c["version"], bool(c.get("root"))), c)
        kept["direct"] = bool(kept.get("direct") or c.get("direct"))
    if res.get("components"):
        res["components"] = list(uniq.values())
    deps = [c for c in res.get("components") or [] if not c.get("root")]
    if res.get("ok") and deps:
        res["source"] = "opensca"
        return res
    # OpenSCA drops dependencies whose version it cannot resolve (BOM-managed
    # ones), leaving only the project itself. That is not "no dependencies".
    fallback = builtin(root)
    if res.get("ok") and not fallback["components"]:
        res["source"] = "opensca"
        return res
    fallback["source"] = "builtin"
    fallback["opensca_error"] = res.get("error") or "OpenSCA 只解析出项目自身，没有依赖"
    return fallback


def indirect_wanted(root: str, asked: bool | None = None) -> bool:
    """This run's choice, else the project's, else the setting; on unless turned off."""
    if asked is not None:
        return asked
    from . import projects
    mine = (projects.get(projects.project_id(root)) or {}).get("indirect") or ""
    return (mine or os.environ.get("SCA_INDIRECT") or "1") != "0"


def enrich(root: str, max_lookups: int = 12, indirect: bool | None = None) -> dict:
    """Attach NVD CVEs to components that carry a version.

    The lookup cap is reported, not silent: an unchecked dependency must never
    read as "no known CVEs".
    """
    if not str(root).strip() or not pathlib.Path(root).exists():
        return {"ok": False, "error": f"路径不存在: {root}"}
    procs.stage("解析依赖树")
    from . import checkpoint
    saved = checkpoint.Checkpoint(root, "triage", checkpoint.fingerprint(root, lambda n: n in _MANIFESTS or n.endswith((".gradle", ".gradle.kts"))), opensca_bin())
    saved.total = 2
    comps = saved.get("components")
    if comps is None:
        comps = components(root)
        if comps.get("ok"):
            saved.put("components", comps)
    if not comps.get("ok"):
        return comps
    want, left_out = indirect_wanted(root, indirect), 0
    if not want:
        # A choice, said as such; not something that went wrong.
        left_out = sum(not c.get("direct") and not c.get("root") for c in comps["components"])
        comps["components"] = [c for c in comps["components"] if c.get("direct") or c.get("root")]
    comps["indirect"], comps["indirect_skipped"] = want, left_out
    seen, lookups, skipped, unresolved = set(), 0, 0, []
    from . import airules, gaps, osv
    by_agent, settled, extra = gaps.overlay(root, comps["components"])
    alias = airules.aliases(root)
    have = {(c["name"].lower(), c["version"]) for c in comps["components"]}
    comps["components"] += [c for c in [*airules.components(root), *extra] if (c["name"].lower(), c["version"]) not in have]
    # OSV answers by coordinate, all at once; NVD fills in, one product at a time.
    answers, osv_error = {}, ""
    asking = [c for c in comps["components"] if not c.get("root") and c["name"] and c.get("scope") != "test" and nvd.comparable(c["version"])]
    if osv.enabled():
        procs.stage("查询 OSV")
        got = saved.get("osv")
        if got is None:
            answers, osv_error = osv.query(asking)
            if answers and not osv_error:
                saved.put("osv", {"want": want, "rows": [[list(k), v] for k, v in answers.items()]})
        elif got["want"] == want or got["want"]:
            answers = {tuple(k): v for k, v in got["rows"]}
        else:
            answers, osv_error = osv.query(asking)
    explained = []

    def miss(c: dict, reason: str) -> None:
        unresolved.append({"vendor": c.get("vendor", ""), "name": c["name"],
                           "version": c["version"], "reason": reason, **({"asked": True} if c.get("asked") else {})})

    for c in comps["components"]:
        c["cves"] = []
        if c.get("root") or not c["name"]:
            continue  # the audited project itself, not a dependency
        key = ((c.get("vendor") or "").lower(), c["name"].lower(), c["version"])
        if key in seen:
            continue
        seen.add(key)
        if c.get("scope") == "test":
            c["skipped"] = "test"
            continue  # never in what is deployed
        if gaps.key(c) in settled:
            explained.append({"name": c["name"], "version": c["version"], "reason": settled[gaps.key(c)]})
            continue
        if not nvd.comparable(c["version"]):
            miss(c, f"版本未解析，agent 也没有查清：{c['unknown_by'][:120]}" if c.get("unknown_by") else "版本未解析，无法判断是否受影响")
            continue
        if c.get("guessed"):
            miss(c, f"版本是推测的（{c.get('via') or '来自别的库的声明'}）" + (f"，agent 也没有查清：{c['unknown_by'][:120]}" if c.get("unknown_by") else ""))
        c["cves"] = list(answers.get(key) or [])
        # NVD answers one product per request, seconds apart: ask it only what OSV did not
        # know. What it answered before costs nothing.
        if key in answers and not by_agent.get(gaps.key(c)) and not nvd.cached(c["name"], c["version"], c.get("vendor") or ""):
            continue
        if lookups >= max_lookups:
            c["skipped"] = "lookup cap"
            skipped += 1
            if key not in answers:
                miss(c, f"超过单次 {max_lookups} 个的查询上限，重跑会从这里继续")
            continue
        procs.stage(f"查询 NVD：{c['name']} {c['version']}")
        named = by_agent.get(gaps.key(c)) or alias.get(c["name"].lower())
        r = nvd.lookup(named, c["version"]) if named else nvd.lookup(c["name"], c["version"], group=c.get("vendor") or "")
        if not r.get("cached"):  # cached answers are free, so reruns make progress
            lookups += 1
        more = r.get("affected", []) if r.get("ok") else []
        ids = {x["id"] for x in more}
        c["cves"] = more + [x for x in c["cves"] if x["id"] not in ids]
        c["nvd_error"] = r.get("error")
        if key in answers:
            continue  # OSV knows the package; NVD not knowing the name is no gap
        if r.get("error") and c.get("unknown_by"):
            miss(c, f"NVD 没有这个名字，agent 也没有查清：{c['unknown_by'][:120]}")
        elif r.get("error"):
            miss(c, f"NVD 查询{'不完整' if r.get('ok') else '失败'}：{r['error'][:160]}")
        elif named and not c["cves"]:  # the name was an agent's guess
            miss(c, f"按 AI 给出的产品名 {named} 没有命中，不能当作没有 CVE")
    comps["lookups"] = lookups
    comps["skipped"] = skipped
    comps["unresolved"] = unresolved
    comps["explained"], comps["osv"] = explained, {"answered": len(answers), "error": osv_error}
    comps["test_skipped"] = sum(c.get("skipped") == "test" for c in comps["components"])
    comps["incomplete_reasons"] = incomplete_reasons(comps)
    comps["complete"] = not comps["incomplete_reasons"]
    saved.done()
    from . import logging
    logging.info("sca", "dependencies resolved", components=len(comps.get("components", [])),
                 source=comps.get("source"), lookups=lookups, skipped=skipped,
                 unresolved=len(unresolved))
    return comps


def incomplete_reasons(comps: dict) -> list[str]:
    out = []
    missed = comps.get("unresolved") or []
    if missed:
        names = "、".join(f"{m['name']}@{m['version'] or '?'}" for m in missed[:3])
        out.append(f"{len(missed)} 个依赖没有查到结论（不等于没有漏洞），如 {names}")
    if (comps.get("osv") or {}).get("error") and missed:
        out.append(comps["osv"]["error"][:160])
    if comps.get("opensca_error") and comps.get("indirect", True):
        out.append(f"间接依赖未解析，只读了构建文件：{comps['opensca_error']}")
    mv = comps.get("maven") or {}
    lost = [x["what"] for x in mv.get("missing") or []]
    heads, trees = [x for x in lost if not x.startswith("依赖树")], [x.removeprefix("依赖树 ") for x in lost if x.startswith("依赖树")]
    if heads:
        out.append(f"取不到 {'、'.join(heads[:4])}{f' 等 {len(heads)} 个' if len(heads) > 4 else ''}：由它管的版本不可信")
    if trees and comps.get("indirect", True):
        out.append(f"{len(trees)} 个构件的 POM 取不到，它们的间接依赖没有查：{'、'.join(trees[:4])}")
    if mv.get("timed_out"):
        out.append("依赖树太大，没有在时限内还原完")
    return out
