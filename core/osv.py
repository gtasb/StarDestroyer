"""OSV.dev: known vulnerabilities by package coordinate, a thousand per request.

NVD is keyed by product names that packages do not have, and answers one product at a
time; what it cannot name or has no budget for used to stay unanswered. OSV is keyed by
the coordinate itself. Only package names and versions are sent. SCA_OSV=0 turns it off.
"""

import concurrent.futures
import json
import math
import os
import pathlib
import re
import time

from . import net

API = "https://api.osv.dev/v1"
CACHE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "osv"
TTL_S = 7 * 24 * 3600
_ECO = {"java": "Maven", "kotlin": "Maven", "python": "PyPI", "javascript": "npm", "js": "npm", "typescript": "npm", "node": "npm", "npm": "npm",
        "go": "Go", "golang": "Go", "php": "Packagist", "ruby": "RubyGems", "rust": "crates.io"}
_LABEL = {"CRITICAL": 9.0, "HIGH": 7.0, "MODERATE": 4.0, "MEDIUM": 4.0, "LOW": 1.0}


def enabled() -> bool:
    return os.environ.get("SCA_OSV", "1") != "0"


def coordinate(c: dict) -> dict | None:
    """What OSV calls this component; None when there is no telling."""
    eco = _ECO.get((c.get("language") or "").lower())
    name, group = (c.get("name") or "").strip(), (c.get("vendor") or "").strip()
    if not eco or not name:
        return None
    if eco == "Maven":
        if not group:
            return None  # an artifact id alone is ambiguous
        name = f"{group}:{name}"
    elif eco == "npm" and group and not name.startswith("@"):
        name = f"{group if group.startswith('@') else '@' + group}/{name}" if group.startswith("@") else name
    elif eco == "PyPI":
        name = re.sub(r"[-_.]+", "-", name).lower()
    version = c["version"]
    return {"package": {"ecosystem": eco, "name": name}, "version": version[1:] if eco == "Go" and version.startswith("v") else version}


# ---- scores -----------------------------------------------------------------------
_W = {"AV": {"N": .85, "A": .62, "L": .55, "P": .2}, "AC": {"L": .77, "H": .44}, "UI": {"N": .85, "R": .62},
      "C": {"H": .56, "L": .22, "N": 0}, "I": {"H": .56, "L": .22, "N": 0}, "A": {"H": .56, "L": .22, "N": 0}}
_PR = {"U": {"N": .85, "L": .62, "H": .27}, "C": {"N": .85, "L": .68, "H": .5}}


def base_score(vector: str) -> float | None:
    """CVSS v3 base score of a vector."""
    m = dict(p.split(":", 1) for p in vector.split("/")[1:] if ":" in p)
    try:
        scope = m["S"]
        iss = 1 - (1 - _W["C"][m["C"]]) * (1 - _W["I"][m["I"]]) * (1 - _W["A"][m["A"]])
        impact = 6.42 * iss if scope == "U" else 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15
        ease = 8.22 * _W["AV"][m["AV"]] * _W["AC"][m["AC"]] * _PR[scope][m["PR"]] * _W["UI"][m["UI"]]
    except KeyError:
        return None
    if impact <= 0:
        return 0.0
    raw = min(10, (impact + ease) * (1 if scope == "U" else 1.08))
    return math.ceil(round(raw * 10, 5)) / 10


def _score(v: dict) -> float | None:
    got = [base_score(s["score"]) for s in v.get("severity") or [] if s.get("type") == "CVSS_V3" and str(s.get("score", "")).startswith("CVSS:3")]
    got = [x for x in got if x is not None]
    if got:
        return max(got)
    return _LABEL.get(str((v.get("database_specific") or {}).get("severity") or "").upper())


# ---- queries ----------------------------------------------------------------------
def _vuln(vid: str) -> dict:
    f = CACHE / (re.sub(r"[^\w.\-]", "_", vid) + ".json")
    if f.exists() and time.time() - f.stat().st_mtime < TTL_S:
        try:
            return json.loads(f.read_text(encoding="utf-8"))
        except ValueError:
            pass
    v = net.request_json(f"{API}/vulns/{vid}", timeout=30)
    CACHE.mkdir(parents=True, exist_ok=True)
    f.write_text(json.dumps(v, ensure_ascii=False), encoding="utf-8")
    return v


def _row(v: dict, name: str) -> dict:
    ranges = [e for a in v.get("affected") or [] if (a.get("package") or {}).get("name") == name for r in a.get("ranges") or [] for e in [r.get("events") or []]]
    cpes = [{"criteria": f"osv:{name}", "start": next((x["introduced"] for x in e if "introduced" in x), None), "end": next((x.get("fixed") or x.get("last_affected") for x in e if "fixed" in x or "last_affected" in x), None)} for e in ranges]
    return {"id": next((a for a in v.get("aliases") or [] if a.startswith("CVE-")), v["id"]), "summary": (v.get("summary") or v.get("details") or "")[:600], "score": _score(v),
            "cwes": sorted((v.get("database_specific") or {}).get("cwe_ids") or []), "published": (v.get("published") or "")[:10], "matched_version": True, "cpes": cpes[:5], "source": "osv"}


def query(components: list[dict]) -> tuple[dict, str]:
    """({(vendor, name, version): [cve rows]}, what went wrong). Absent = not answered."""
    asked = {}
    for c in components:
        q = coordinate(c)
        if q:
            asked[((c.get("vendor") or "").lower(), c["name"].lower(), c["version"])] = q
    keys, found, error = list(asked), {}, ""
    for i in range(0, len(keys), 500):
        part = keys[i:i + 500]
        try:
            res = net.post_json(f"{API}/querybatch", {"queries": [asked[k] for k in part]}, timeout=60)["results"]
            if len(res) != len(part):
                raise ValueError("结果数量对不上")
        except Exception as exc:
            error = f"OSV 查询失败：{exc}"
            continue
        for k, r in zip(part, res):
            ids, token = [x["id"] for x in r.get("vulns") or []], r.get("next_page_token")
            try:
                while token:
                    more = net.post_json(f"{API}/query", {**asked[k], "page_token": token}, timeout=60)
                    ids += [x["id"] for x in more.get("vulns") or []]
                    token = more.get("next_page_token")
            except Exception as exc:
                error = f"OSV 查询不完整：{exc}"
                continue
            found[k] = ids
    details: dict[str, dict] = {}
    with concurrent.futures.ThreadPoolExecutor(8) as pool:
        jobs = {pool.submit(_vuln, x): x for x in {i for ids in found.values() for i in ids}}
        for f in concurrent.futures.as_completed(jobs):
            try:
                details[jobs[f]] = f.result()
            except Exception as exc:
                error = f"OSV 详情查询失败：{exc}"
    out = {}
    for k, ids in found.items():
        if any(i not in details for i in ids):
            continue  # a vulnerability we cannot describe is not an answer
        rows: dict[str, dict] = {}
        for i in ids:
            if not details[i].get("withdrawn"):
                r = _row(details[i], asked[k]["package"]["name"])
                old = rows.get(r["id"])
                if not old or (r["score"] or 0) > (old["score"] or 0):
                    rows[r["id"]] = r
        out[k] = list(rows.values())
    return out, error


def known(vid: str) -> str:
    """What was cached about an id or its CVE alias; no request is made."""
    for f in CACHE.glob("*.json"):
        try:
            v = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if vid in (v.get("id"), *(v.get("aliases") or [])):
            return f"{v['id']} {' '.join(v.get('aliases') or [])}\n{v.get('summary', '')}\n{(v.get('details') or '')[:3000]}"
    return ""
