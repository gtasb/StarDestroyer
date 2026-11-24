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


def ai_annotate(triaged: dict, max_rows: int = 5) -> dict:
    """Model pass over what the gate kept.

    It may demote (keep -> ignore) with a stated reason. It may never promote:
    a model cannot invent impact that the deterministic gate did not see.
    """
    from . import llm

    if not llm.available():
        return {"ok": False, "error": "DEEPSEEK_API_KEY 未设置"}
    kept = triaged.get("kept", [])
    judged = 0
    for row in kept[:max_rows]:
        prompt = (
            "判断这个依赖漏洞在该应用中是否可能造成有效危害。只输出一个 JSON 对象："
            '{"verdict":"keep|ignore","reason":"<=60字"}\n'
            "ignore 的条件：仅影响未使用的功能、需要不可达的前置条件、或描述与所装版本功能无关。\n"
            "cpe_matched=true 表示 NVD 的 CPE 版本区间已确认该安装版本受影响；"
            "摘要里提到其它产品不构成 ignore 理由，那只是描述文本质量差。\n"
            "source_scanned=0 表示没有源码可判断可达性，此时不得以「未使用」为由 ignore。\n"
            "证据不足时输出 keep。"
        )
        ev = {"dependency": row["dependency"], "version": row["version"],
              "cve": row["cve"], "cvss": row["cvss"], "epss": row["epss"],
              "cwes": row["cwes"], "summary": row["summary"],
              "cpe_matched": row.get("cpe_matched"),
              "cpe_ranges": [c.get("criteria") + " " + str(c.get("end") or "") for c in row.get("cpes", [])][:3],
              "source_scanned": row.get("source_scanned"),
              "code_uses_package": row.get("used"),
              "usage_evidence": row.get("usage_evidence", [])}
        r = llm.chat(prompt, json.dumps(ev, ensure_ascii=False))
        judged += 1
        if not r.get("ok"):
            continue
        text = r["text"]
        start, end = text.find("{"), text.rfind("}")
        if start < 0 or end <= start:
            continue
        try:
            obj = json.loads(text[start:end + 1])
        except json.JSONDecodeError:
            continue
        row["ai_verdict"] = obj.get("verdict")
        row["ai_reason"] = obj.get("reason", "")[:200]
        if obj.get("verdict") == "ignore" and row in kept:
            kept.remove(row)
            row["reason"] = "模型复核降级：" + row["ai_reason"]
            triaged.setdefault("ignored", []).append(row)
    triaged.setdefault("stats", {})["kept"] = len(kept)
    triaged["stats"]["ignored"] = len(triaged.get("ignored", []))
    triaged["ai_judged"] = judged
    return {"ok": True, "judged": judged}


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
