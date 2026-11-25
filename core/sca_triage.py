"""SCA triage: drop what cannot hurt, then map what remains to sinks.

Order matters. The gate is deterministic and auditable -- CVSS, EPSS percentile,
and whether the code touches the package at all. A model pass may annotate a
remaining item or explain it, but it can never revive something the gate
dropped, because a fabricated "this looks exploitable" is exactly the failure
mode this module exists to prevent.
"""

import hashlib
import pathlib
import re

from . import codeintel, epss, ledger, store
from .profile import _walk

DEFAULT_CVSS = 7.0          # HIGH and above
DEFAULT_EPSS_PCT = 0.95     # top 5% exploitation likelihood

CWE_FAMILY = {
    "CWE-502": "deserialization", "CWE-611": "xxe", "CWE-918": "ssrf",
    "CWE-89": "sqli", "CWE-78": "command", "CWE-77": "command",
    "CWE-74": "command", "CWE-94": "code_injection", "CWE-917": "expression",
    "CWE-22": "path_traversal", "CWE-23": "path_traversal",
}

SINKS = {
    "deserialization": ["ObjectInputStream.readObject", "readResolve",
                        "XStream.fromXML", "Hessian2Input.readObject",
                        "ObjectInputStream.readUnshared"],
    "sqli": ["Statement.execute", "Statement.executeQuery", "Statement.executeUpdate",
             "JdbcTemplate.query", "JdbcTemplate.update",
             "EntityManager.createNativeQuery", "EntityManager.createQuery"],
    "command": ["Runtime.exec", "ProcessBuilder.command", "ProcessBuilder.start"],
    "ssrf": ["URL.openConnection", "URL.openStream", "HttpURLConnection.connect"],
    "expression": ["ExpressionParser.parseExpression", "ScriptEngine.eval"],
    "xxe": ["DocumentBuilder.parse", "SAXParser.parse", "XMLInputFactory.createXMLStreamReader"],
    "path_traversal": ["new File(", "Paths.get", "Files.readAllBytes"],
    "code_injection": ["ScriptEngine.eval", "Method.invoke", "Class.forName"],
}

_SRC = {".java", ".kt", ".py", ".go"}


# Import names that cannot be derived from the coordinates.
_IMPORTS = {
    "guava": ["com.google.common"], "httpclient": ["org.apache.http"], "httpcore": ["org.apache.http"],
    "commons-collections": ["org.apache.commons.collections"], "commons-io": ["org.apache.commons.io"],
    "commons-fileupload": ["org.apache.commons.fileupload"], "commons-codec": ["org.apache.commons.codec"],
    "commons-beanutils": ["org.apache.commons.beanutils"], "commons-lang": ["org.apache.commons.lang"],
    "dom4j": ["org.dom4j"], "junit": ["junit.", "org.junit"], "log4j": ["org.apache.log4j"],
    "xstream": ["com.thoughtworks.xstream"], "snakeyaml": ["org.yaml.snakeyaml"], "fastjson": ["com.alibaba.fastjson"],
    "mybatis": ["org.apache.ibatis"], "gson": ["com.google.gson"], "ognl": ["ognl."],
    "pyyaml": ["yaml"], "pillow": ["PIL"], "beautifulsoup4": ["bs4"], "python-dateutil": ["dateutil"],
    "scikit-learn": ["sklearn"], "opencv-python": ["cv2"], "pyjwt": ["jwt"], "pycryptodome": ["Crypto"],
    "mysqlclient": ["MySQLdb"], "psycopg2-binary": ["psycopg2"], "protobuf": ["google.protobuf"],
    "python-multipart": ["multipart"], "msgpack-python": ["msgpack"], "attrs": ["attr"],
    "django-rest-framework": ["rest_framework"], "djangorestframework": ["rest_framework"],
}


def _tokens(component: dict) -> list[str]:
    """Import prefixes for a component; empty when they cannot be known.

    Deliberately wide: a prefix that is too short keeps a CVE that could have been
    dropped, one that is too long drops a CVE that is in use.
    """
    name = (component.get("name") or "").strip()
    low = name.lower()
    group = (component.get("vendor") or "").strip()
    if low in _IMPORTS:
        return _IMPORTS[low]
    lang = (component.get("language") or "").lower()
    if "/" in name:  # Go module path is the import path
        return [re.sub(r"/v\d+$", "", name)]
    if "." in group:
        return [".".join(group.split(".")[:2]) + "."]
    if lang == "python":
        return list(dict.fromkeys([low.replace("-", "_"), low.replace("-", "."), low]))
    return []


_IMPORT_LINE = re.compile(r"^\s*(?:import|from|package|using)\b(.*)$|^\s*(?:[\w.]+\s+)?\"([\w.\-/]+)\"\s*$")


_JS_LANG = ("javascript", "js", "typescript", "npm", "node")
_JS_IMPORT = re.compile(r"""(?:\bfrom|\bimport|\brequire)\s*\(?\s*['"]([^'"]+)['"]""")


def _js_usage(root: str, name: str) -> dict:
    """Not finding an import proves nothing: loaders and plugins are named in strings."""
    hits, seen = [], 0
    for f in ledger.source_files(root, "js") if root and pathlib.Path(root).is_dir() else []:
        seen += 1
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in _JS_IMPORT.finditer(text):
            if m.group(1) == name or m.group(1).startswith(name + "/"):
                n = text.count("\n", 0, m.start()) + 1
                hits.append(f"{f.relative_to(root).as_posix()}:{n}: {m.group(0)[:100]}")
                break
        if len(hits) >= 5:
            break
    return {"used": bool(hits), "scanned": seen, "evidence": hits, "conclusive": False}


def _usage(root: str, component: dict) -> dict:
    if (component.get("language") or "").lower() in _JS_LANG:
        return _js_usage(root, (component.get("name") or "").strip())
    return _source_usage(root, _tokens(component))


def _source_usage(root: str, tokens: list[str], max_files: int = 20000) -> dict:
    """Does any source file import the package?

    `conclusive` is the point: only a full pass over existing source with known
    import names can say "not used". Anything else is "could not tell".
    """
    if not root or not tokens:
        return {"used": False, "scanned": 0, "evidence": [], "conclusive": False}
    p = pathlib.Path(root)
    hits: list[str] = []
    seen, whole = 0, True
    for f in _walk(p):
        if f.suffix.lower() not in _SRC | {".xml", ".jsp", ".gradle", ".yml", ".yaml", ".properties"}:
            continue
        if f.suffix.lower() in _SRC:
            seen += 1
        if seen > max_files:
            whole = False
            break
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            whole = False
            continue
        source = f.suffix.lower() in _SRC
        for n, line in enumerate(text.splitlines(), 1):
            if source:
                m = _IMPORT_LINE.match(line)
                if not m:
                    continue
                line = m.group(1) or m.group(2) or ""
            if any(re.search(r"(?<![\w.])" + re.escape(t), line) for t in tokens):
                # a build file naming the dependency is not a use of it
                if not source and f.name in ("pom.xml", "build.gradle"):
                    continue
                hits.append(f"{f.relative_to(p).as_posix()}:{n}: {line.strip()[:100]}")
                break
        if len(hits) >= 5:
            break
    return {"used": bool(hits), "scanned": seen, "evidence": hits,
            "conclusive": whole and seen > 0}


def _family(cwes: list[str], summary: str = "") -> str | None:
    for cwe in cwes or []:
        fam = CWE_FAMILY.get(cwe)
        if fam:
            return fam
    low = (summary or "").lower()
    for token, fam in (("deserializ", "deserialization"), ("sql injection", "sqli"),
                       ("command injection", "command"), ("ssrf", "ssrf"),
                       ("xml external", "xxe"), ("path traversal", "path_traversal")):
        if token in low:
            return fam
    return None


_SITE = {"deserialization": "deserialization", "sqli": "sqli", "command": "cmd", "ssrf": "ssrf", "expression": "expression",
         "xxe": "xxe", "path_traversal": "path_traversal", "code_injection": "code_injection"}


def triage(components: dict, app_root: str | None = None, cvss_min: float = DEFAULT_CVSS,
           epss_pct_min: float = DEFAULT_EPSS_PCT) -> dict:
    """Split dependency CVEs into keep / ignore with a citable reason each."""
    if not components.get("ok"):
        return {"ok": False, "error": components.get("error")}

    rows = []
    cve_ids = []
    for c in components.get("components", []):
        for cve in c.get("cves") or []:
            row = {
                "_comp": c, "group": c.get("vendor", ""),
                "dependency": c.get("name", ""), "version": c.get("version", ""),
                "cve": cve.get("id"), "cvss": cve.get("score") or 0.0,
                "cvss_unknown": cve.get("score") is None,
                "cwes": cve.get("cwes") or [], "summary": (cve.get("summary") or "")[:200],
                "cpes": cve.get("cpes") or [],
                **({"guessed": True} if c.get("guessed") else {}), **({"via": c["via"]} if c.get("via") else {}),
                "cpe_matched": bool(cve.get("matched_version")),
            }
            rows.append(row)
            cve_ids.append(row["cve"])

    scores = epss.scores(cve_ids)
    usage_cache: dict[str, dict] = {}
    kept, ignored = [], []

    for row in rows:
        e = scores.get(row["cve"], {})
        row["epss"] = e.get("epss")
        row["percentile"] = e.get("percentile")
        high = (row["cvss"] >= cvss_min) or ((row["percentile"] or 0) >= epss_pct_min)
        unknown = [label for label, hit in (("CVSS 缺失", row["cvss_unknown"]),
                                            ("EPSS 查询失败", e.get("failed"))) if hit]

        comp = row.pop("_comp")
        key = (comp.get("vendor", ""), comp.get("name", ""))
        if key not in usage_cache:
            usage_cache[key] = _usage(app_root or "", comp)
        usage = usage_cache[key]
        row["used"] = usage["used"]
        row["usage"] = "used" if usage["used"] else "unused" if usage["conclusive"] else "unknown"
        # An indirect dependency is called by other libraries, not by this source.
        if row["usage"] == "unused" and not comp.get("direct", True):
            row["usage"] = "indirect"
        row["source_scanned"] = usage["scanned"]
        row["usage_evidence"] = usage["evidence"][:3]

        fam = _family(row["cwes"], row["summary"])
        row["family"] = fam
        row["sinks"] = SINKS.get(fam, []) if fam else []

        if not high and unknown:
            row["reason"] = f"{'、'.join(unknown)}，分数未知不能当作低分丢弃"
            kept.append(row)
        elif not high and row["usage"] == "unused":
            row["reason"] = (f"CVSS {row['cvss']} < {cvss_min} 且 EPSS 百分位 "
                             f"{row['percentile'] or 0} < {epss_pct_min}，且代码未引用该包")
            ignored.append(row)
        elif not high and row["usage"] in ("unknown", "indirect"):
            why = "是间接依赖" if row["usage"] == "indirect" else "没有源码或包名不明，判断不了是否引用"
            row["reason"] = f"分数不足（CVSS {row['cvss']}），但{why}，不能以「未使用」为由丢弃"
            kept.append(row)
        elif not high and row["used"]:
            row["reason"] = (f"分数不足以直接定性（CVSS {row['cvss']}），但代码引用了该包，"
                             "保留以核对 sink 调用点")
            kept.append(row)
        else:
            why = []
            if row["cvss"] >= cvss_min:
                why.append(f"CVSS {row['cvss']}")
            if (row["percentile"] or 0) >= epss_pct_min:
                why.append(f"EPSS 百分位 {row['percentile']}")
            row["reason"] = "；".join(why)
            kept.append(row)

    return {
        "ok": True,
        "thresholds": {"cvss_min": cvss_min, "epss_percentile_min": epss_pct_min},
        "stats": {
            "dependencies": len(components.get("components", [])),
            "cves": len(rows),
            "kept": len(kept),
            "ignored": len(ignored),
            "epss_known": sum(1 for r in rows if r["epss"] is not None),
            "unresolved": len(components.get("unresolved") or []),
            "indirect_skipped": components.get("indirect_skipped") or 0,
            "test_skipped": components.get("test_skipped") or 0,
        },
        "complete": not (components.get("incomplete_reasons") or []),
        "incomplete_reasons": components.get("incomplete_reasons") or [],
        "unresolved": components.get("unresolved") or [],
        "kept": kept,
        "ignored": ignored,
    }


def sink_report(triaged: dict, app_root: str) -> dict:
    """For what survived: which sinks it implies and where the app calls them."""
    families: dict[str, dict] = {}
    for row in triaged.get("kept", []):
        fam = row.get("family")
        if not fam:
            continue
        slot = families.setdefault(fam, {"family": fam, "sinks": SINKS.get(fam, []),
                                         "cves": [], "hints": []})
        if row["cve"] not in slot["cves"]:
            slot["cves"].append(row["cve"])
    sites: dict[str, list] = {}
    for s in codeintel.sink_sites(app_root) if app_root and pathlib.Path(app_root).exists() else []:
        sites.setdefault(s["class"], []).append(s)
    for slot in families.values():
        # Leads only. Whether one is reached by the CVE is the audit agent's job.
        slot["hints"] = sites.get(_SITE.get(slot["family"], ""), [])[:60]
        slot["verdict"] = f"{len(slot['hints'])} 处调用点，由 agent 追链" if slot["hints"] else "未见调用点"
    return {"families": list(families.values()),
            "unmapped": [r["cve"] for r in triaged.get("kept", []) if not r.get("family")]}


VERDICT_FILE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "sca-verdicts"


def candidates(triaged: dict, app_root: str, limit: int = 20) -> dict:
    """What an agent still has to decide, with the checks to run first.

    No model is called here. The gate is deterministic; the remaining question --
    "is the vulnerable API actually reachable in *this* code" -- needs a reader
    with tools, so it is handed over as a task with concrete steps.
    """
    pending = [r for r in triaged.get("kept", []) if r.get("decision") != "kept"]
    pending.sort(key=lambda r: (-(r["cvss"] or 0), -(r["percentile"] or 0)))
    out = []
    for row in pending[:limit]:
        tokens = _tokens({"name": row["dependency"], "vendor": row.get("group", "")}) or [row["dependency"]]
        out.append({
            "cve": row["cve"], "dependency": row["dependency"], "version": row["version"],
            "cvss": row["cvss"], "epss": row["epss"], "percentile": row["percentile"],
            "cwes": row["cwes"], "family": row["family"], "sinks": row["sinks"],
            "why_kept": row["reason"],
            "hint_files": row.get("usage_evidence", []),
            "verify": {
                "goal": "确认该依赖的易受影响 API 在本应用中是否可达",
                "steps": [
                    f"在项目里搜索 {' / '.join(tokens)}，定位引用",
                    "read 命中文件，确认是否真正调用 sinks 中的 API",
                    "可达 -> keep，并给出 file:line；不可达 -> ignore，并给出证据",
                ],
                "package_tokens": tokens,
                "sinks": row["sinks"],
            },
        })
    return {"ok": True, "app_root": app_root, "count": len(out), "total": len(pending),
            "remaining": len(pending) - len(out), "candidates": out,
            "instruction": "逐条用 read/grep 核实后再调用 sca_record_verdicts，带上 cve、dependency、"
                           "version；ignore 的证据会被复查：file:line 必须存在，"
                           "check=unused 会由工具重新搜索引用。无证据一律 keep。"}


def _verdict_file(app_root: str) -> pathlib.Path:
    root = str(pathlib.Path(app_root).resolve())
    return VERDICT_FILE / (hashlib.sha256(root.encode()).hexdigest()[:16] + ".json")


def _vkey(cve: str, dependency: str, version: str) -> str:
    return f"{cve}|{dependency}|{version}"


def _checked(root: pathlib.Path, e, v: dict) -> dict | None:
    """Evidence the tool itself could confirm, with what it found; None otherwise."""
    if not isinstance(e, dict):
        return None
    if e.get("file"):
        from . import projects
        if not projects.inside(root, str(e["file"])):
            return None
        try:
            text = (root / str(e["file"])).read_text(encoding="utf-8", errors="replace").splitlines()
            line = int(e.get("line"))
        except (OSError, TypeError, ValueError):
            return None
        return {"file": str(e["file"]), "line": line, "text": text[line - 1].strip()[:120]} \
            if 1 <= line <= len(text) else None
    if e.get("check"):
        usage = _usage(str(root), ({"name": v["dependency"], "vendor": v.get("group", ""),
                                                  "language": v.get("language", "")}))
        if usage["conclusive"] and not usage["used"]:
            return {"check": "unused", "scanned": usage["scanned"]}
    return None


def record_verdicts(app_root: str, verdicts: list[dict]) -> dict:
    """Persist an agent's keep/ignore decisions. An ignore needs evidence that holds
    up when checked here: the agent has been reading untrusted source."""
    root = pathlib.Path(app_root).resolve()
    accepted, rejected = [], []
    for v in verdicts if isinstance(verdicts, list) else [verdicts]:
        if not isinstance(v, dict):
            rejected.append({"cve": None, "why": "每条裁决必须是对象"})
            continue
        cve, verdict, dep = v.get("cve"), v.get("verdict"), v.get("dependency")
        if not cve or verdict not in ("keep", "ignore"):
            rejected.append({"cve": cve, "why": "verdict must be keep|ignore"})
            continue
        if not dep or not v.get("version"):
            rejected.append({"cve": cve, "why": "需要 dependency 和 version：同一 CVE 可能命中多个依赖"})
            continue
        given = v.get("evidence")
        evidence = [c for c in (_checked(root, e, v) for e in (given if isinstance(given, list) else []))
                    if c]
        if verdict == "ignore" and not evidence:
            rejected.append({"cve": cve, "why": "ignore 需要经得起复查的证据：存在的 file:line，或工具复查确认未引用"})
            continue
        accepted.append({"cve": cve, "dependency": dep, "version": v["version"], "verdict": verdict,
                         "reason": str(v.get("reason") or "")[:300], "evidence": evidence[:5]})
    if not accepted:
        return {"ok": False, "recorded": 0, "rejected": rejected}

    key = _verdict_file(app_root)
    with store.update(key, {}) as data:
        for row in accepted:
            data[_vkey(row["cve"], row["dependency"], row["version"])] = row
    return {"ok": True, "recorded": len(accepted), "rejected": rejected,
            "file": str(key), "verdicts": store.read(key, {})}


def load_verdicts(app_root: str) -> dict:
    # Entries from before dependency and version were part of the key match nothing.
    return store.read(_verdict_file(app_root), {})


def apply_verdicts(triaged: dict, verdicts: dict) -> dict:
    """Fold recorded decisions back into the gate result."""
    kept, ignored = [], list(triaged.get("ignored", []))
    for row in triaged.get("kept", []):
        v = verdicts.get(_vkey(row["cve"], row["dependency"], row["version"]))
        if not v:
            row["decision"] = "pending"
            kept.append(row)
        elif v["verdict"] == "ignore":
            row["reason"] = "复核否决：" + v.get("reason", "")
            row["evidence"] = v.get("evidence", [])
            ignored.append(row)
        else:
            row["decision"] = "kept"
            row["reason"] = v.get("reason") or row["reason"]
            row["evidence"] = v.get("evidence", [])
            kept.append(row)
    triaged["kept"], triaged["ignored"] = kept, ignored
    triaged.setdefault("stats", {}).update({"kept": len(kept), "ignored": len(ignored)})
    return triaged
