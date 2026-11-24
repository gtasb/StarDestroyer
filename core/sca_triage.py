"""SCA triage: drop what cannot hurt, then map what remains to sinks.

Order matters. The gate is deterministic and auditable -- CVSS, EPSS percentile,
and whether the code touches the package at all. A model pass may annotate a
remaining item or explain it, but it can never revive something the gate
dropped, because a fabricated "this looks exploitable" is exactly the failure
mode this module exists to prevent.
"""

import json
import pathlib
import re

from . import epss

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


def _tokens(component: dict) -> list[str]:
    out = []
    vendor = (component.get("vendor") or "").strip()
    if "." in vendor:
        out.append(vendor)
    name = (component.get("name") or "").replace("-", ".")
    if len(name) >= 4:
        out.append(name)
    return out


def _source_usage(root: str, tokens: list[str], max_files: int = 2000) -> dict:
    """Fuzzy reachability: does any source file reference the package?

    `scanned` matters: "no usage" and "nothing to scan" are different facts, and
    conflating them silently drops every finding for jar-only targets.
    """
    if not root or not tokens:
        return {"used": False, "scanned": 0, "evidence": []}
    p = pathlib.Path(root)
    hits: list[str] = []
    seen = 0
    for f in p.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in _SRC:
            continue
        seen += 1
        if seen > max_files:
            break
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            low = line.strip()
            if not low.startswith(("import ", "from ", "package ", "using ")):
                continue
            if any(t in low for t in tokens):
                hits.append(f"{f.relative_to(p).as_posix()}: {low[:100]}")
                break
        if len(hits) >= 5:
            break
    return {"used": bool(hits), "scanned": seen, "evidence": hits}


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


def check_sinks(root: str, sinks: list[str], max_files: int = 2000) -> list[dict]:
    """Where the application actually calls a sink API (hint, not proof)."""
    if not root:
        return []
    short = [s.split(".")[-1].rstrip("(") for s in sinks]
    p = pathlib.Path(root)
    out, seen = [], 0
    for f in p.rglob("*"):
        if not f.is_file() or f.suffix.lower() not in _SRC:
            continue
        seen += 1
        if seen > max_files:
            break
        try:
            lines = f.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for i, line in enumerate(lines, 1):
            for name in short:
                if name and name in line and not line.strip().startswith(("*", "//")):
                    out.append({"file": f.relative_to(p).as_posix(), "line": i,
                                "api": name, "text": line.strip()[:120]})
                    break
        if len(out) >= 40:
            break
    return out


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
                "dependency": c.get("name", ""), "version": c.get("version", ""),
                "cve": cve.get("id"), "cvss": cve.get("score") or 0.0,
                "cwes": cve.get("cwes") or [], "summary": (cve.get("summary") or "")[:200],
                "cpes": cve.get("cpes") or [],
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

        key = row["dependency"]
        if key not in usage_cache:
            comp = next((c for c in components["components"] if c.get("name") == key), {})
            usage_cache[key] = _source_usage(app_root or "", _tokens(comp))
        usage = usage_cache[key]
        row["used"] = usage["used"]
        row["source_scanned"] = usage["scanned"]
        row["usage_evidence"] = usage["evidence"][:3]

        fam = _family(row["cwes"], row["summary"])
        row["family"] = fam
        row["sinks"] = SINKS.get(fam, []) if fam else []

        if not high and not row["used"] and row["source_scanned"] > 0:
            row["reason"] = (f"CVSS {row['cvss']} < {cvss_min} 且 EPSS 百分位 "
                             f"{row['percentile'] or 0} < {epss_pct_min}，且代码未引用该包")
            ignored.append(row)
        elif not high and row["source_scanned"] == 0:
            row["reason"] = (f"分数不足（CVSS {row['cvss']}），且没有源码可判断可达性，"
                             "不能以「未使用」为由丢弃")
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
        },
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
    for slot in families.values():
        slot["hints"] = check_sinks(app_root, slot["sinks"])
        slot["verdict"] = "有调用点，需逐点复核" if slot["hints"] else "未见调用点"
    return {"families": list(families.values()),
            "unmapped": [r["cve"] for r in triaged.get("kept", []) if not r.get("family")]}


VERDICT_FILE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "sca-verdicts"


def candidates(triaged: dict, app_root: str, limit: int = 20) -> dict:
    """What an agent still has to decide, with the checks to run first.

    No model is called here. The gate is deterministic; the remaining question --
    "is the vulnerable API actually reachable in *this* code" -- needs a reader
    with tools, so it is handed over as a task with concrete steps.
    """
    out = []
    for row in triaged.get("kept", [])[:limit]:
        tokens = [row["dependency"].replace("-", ".")]
        out.append({
            "cve": row["cve"], "dependency": row["dependency"], "version": row["version"],
            "cvss": row["cvss"], "epss": row["epss"], "percentile": row["percentile"],
            "cwes": row["cwes"], "family": row["family"], "sinks": row["sinks"],
            "why_kept": row["reason"],
            "hint_files": row.get("usage_evidence", []),
            "verify": {
                "goal": "确认该依赖的易受影响 API 在本应用中是否可达",
                "steps": [
                    f"grep -rn '<package>' {app_root}  # 先定位引用",
                    "read 命中文件，确认是否真正调用 sinks 中的 API",
                    "可达 -> keep，并给出 file:line；不可达 -> ignore，并给出证据",
                ],
                "package_tokens": tokens,
                "sinks": row["sinks"],
            },
        })
    return {"ok": True, "app_root": app_root, "count": len(out),
            "candidates": out,
            "instruction": "逐条用 read/grep 核实后再调用 sca_record_verdicts；"
                           "ignore 必须带证据（file:line），无证据一律 keep。"}


def record_verdicts(app_root: str, verdicts: list[dict]) -> dict:
    """Persist an agent's keep/ignore decisions. Rejects unevidenced ignores."""
    root = pathlib.Path(app_root).resolve()
    accepted, rejected = [], []
    for v in verdicts or []:
        cve, verdict = v.get("cve"), v.get("verdict")
        if not cve or verdict not in ("keep", "ignore"):
            rejected.append({"cve": cve, "why": "verdict must be keep|ignore"})
            continue
        # absence of usage cannot cite a file:line, so a grep result counts too
        evidence = [e for e in (v.get("evidence") or [])
                    if e.get("file") or e.get("check")]
        if verdict == "ignore" and not evidence:
            rejected.append({"cve": cve, "why": "ignore 需要证据：file:line 或一次 grep 结果"})
            continue
        accepted.append({"cve": cve, "verdict": verdict,
                         "reason": (v.get("reason") or "")[:300],
                         "evidence": evidence[:5]})
    if not accepted:
        return {"ok": False, "recorded": 0, "rejected": rejected}

    VERDICT_FILE.mkdir(parents=True, exist_ok=True)
    key = VERDICT_FILE / (__import__("hashlib").sha256(str(root).encode()).hexdigest()[:16] + ".json")
    store = {}
    if key.exists():
        try:
            store = json.loads(key.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            store = {}
    for row in accepted:
        store[row["cve"]] = row
    key.write_text(json.dumps(store, ensure_ascii=False, indent=2), encoding="utf-8")
    return {"ok": True, "recorded": len(accepted), "rejected": rejected,
            "file": str(key), "verdicts": store}


def load_verdicts(app_root: str) -> dict:
    root = pathlib.Path(app_root).resolve()
    key = VERDICT_FILE / (__import__("hashlib").sha256(str(root).encode()).hexdigest()[:16] + ".json")
    if not key.exists():
        return {}
    try:
        return json.loads(key.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}


def apply_verdicts(triaged: dict, verdicts: dict) -> dict:
    """Fold recorded decisions back into the gate result."""
    kept, ignored = [], list(triaged.get("ignored", []))
    for row in triaged.get("kept", []):
        v = verdicts.get(row["cve"])
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
