"""NVD lookup.

NVD's public API allows 5 requests per 30s without a key, so calls are spaced
and every answer is cached to disk. Version matching is done against the CPE
ranges NVD returns -- a bare keyword hit is not evidence that this version is
affected.
"""

import json
import os
import pathlib
import time
import urllib.parse

from . import net

BASE = os.environ.get("NVD_API_BASE", "https://services.nvd.nist.gov/rest/json/cves/2.0")
CPE_BASE = os.environ.get("NVD_CPE_BASE", "https://services.nvd.nist.gov/rest/json/cpes/2.0")
def api_key() -> str:
    return os.environ.get("NVD_API_KEY", "")
CACHE_DIR = pathlib.Path(__file__).resolve().parents[1] / ".work" / "nvd"
CACHE_DIR.mkdir(parents=True, exist_ok=True)
_MIN_GAP_KEYED, _MIN_GAP_ANON = 1.0, 6.0
_last_call = [0.0]


def _throttle() -> None:
    limit = _MIN_GAP_KEYED if api_key() else _MIN_GAP_ANON
    gap = time.time() - _last_call[0]
    if gap < limit:
        time.sleep(limit - gap)
    _last_call[0] = time.time()


def _cache_path(key: str) -> pathlib.Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)[:80]
    return CACHE_DIR / f"{safe}.json"


def _get(params: dict, attempts: int = 3, base: str | None = None) -> dict:
    qs = urllib.parse.urlencode(params)
    url = f"{base or BASE}?{qs}"
    headers = {"User-Agent": "stardestroyer/0.1"}
    if api_key():
        headers["apiKey"] = api_key()
    _throttle()
    return net.request_json(url, headers=headers, attempts=attempts)


def _ver_tuple(v: str) -> tuple:
    out = []
    for part in v.replace("-", ".").replace("_", ".").split("."):
        out.append(int(part) if part.isdigit() else part)
    return tuple(out)


def _cmp(a: tuple, b: tuple) -> int:
    for x, y in zip(a, b):
        if isinstance(x, int) and isinstance(y, int):
            if x != y:
                return -1 if x < y else 1
        else:
            sx, sy = str(x), str(y)
            if sx != sy:
                return -1 if sx < sy else 1
    return (len(a) > len(b)) - (len(a) < len(b))


def _version_in_range(version: str, cpe_match: dict) -> bool:
    v = _ver_tuple(version)
    if "versionEndExcluding" in cpe_match and _cmp(v, _ver_tuple(cpe_match["versionEndExcluding"])) >= 0:
        return False
    if "versionEndIncluding" in cpe_match and _cmp(v, _ver_tuple(cpe_match["versionEndIncluding"])) > 0:
        return False
    if "versionStartIncluding" in cpe_match and _cmp(v, _ver_tuple(cpe_match["versionStartIncluding"])) < 0:
        return False
    if "versionStartExcluding" in cpe_match and _cmp(v, _ver_tuple(cpe_match["versionStartExcluding"])) <= 0:
        return False
    criteria = cpe_match.get("criteria", "")
    parts = criteria.split(":")
    if len(parts) > 5 and parts[5] not in ("*", "-") and version:
        if _cmp(_ver_tuple(parts[5]), v) != 0:
            return False
    return True


def _score(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        items = metrics.get(key) or []
        if items:
            data = items[0].get("cvssData", {})
            return data.get("baseScore")
    return None


def _cpe_product(keyword: str) -> str:
    import re
    return re.sub(r"[^a-z0-9]+", "_", keyword.lower()).strip("_")


def _resolve_vendors(product: str) -> list[str]:
    """CPE dictionary first: the vendor segment decides which CVE query is valid.
    A wildcard vendor in virtualMatchString returns unstable, unrelated sets."""
    doc = _get({"cpeMatchString": f"cpe:2.3:a:*:{product}:*:*:*:*:*:*:*:*",
                "resultsPerPage": 50}, base=CPE_BASE)
    vendors = []
    for p in doc.get("products", []):
        parts = (p.get("cpe") or {}).get("cpeName", "").split(":")
        if len(parts) > 3 and parts[3] not in ("*", "-") and parts[3] not in vendors:
            vendors.append(parts[3])
    return vendors[:3]


def _search(keyword: str, limit: int) -> dict:
    product = _cpe_product(keyword)
    vendors = _resolve_vendors(product)
    if not vendors:
        raise LookupError(f"CPE 字典中找不到产品: {product}")
    merged: dict[str, dict] = {}
    errors = []
    for vendor in vendors:
        try:
            # cpeName rejects wildcard versions (404); virtualMatchString with a
            # resolved vendor is the stable query.
            doc = _get({"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",
                        "resultsPerPage": min(limit, 100)})
        except Exception as exc:
            errors.append(f"{vendor}: {exc}")
            continue
        for item in doc.get("vulnerabilities", []):
            cid = (item.get("cve") or {}).get("id")
            if cid:
                merged[cid] = item
    if not merged and errors:
        raise RuntimeError("; ".join(errors))
    return {"vulnerabilities": list(merged.values()), "totalResults": len(merged)}


def _product_of(criteria: str) -> str:
    parts = criteria.split(":")
    return parts[4] if len(parts) > 4 else ""


def lookup(keyword: str, version: str | None = None, limit: int = 20) -> dict:
    """CVEs for a product; with a version, only those whose CPE range covers it."""
    cache_key = f"v3:{keyword}@{version or '*'}"
    cp = _cache_path(cache_key)
    if cp.exists():
        try:
            return json.loads(cp.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    try:
        doc = _search(keyword, limit)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "keyword": keyword}

    product = _cpe_product(keyword)
    out = []
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve", {})
        matched = False
        cpes = []
        product_seen = False
        for conf in cve.get("configurations") or []:
            for node in conf.get("nodes", []):
                for cm in node.get("cpeMatch", []):
                    if not cm.get("vulnerable"):
                        continue
                    criteria = cm.get("criteria", "")
                    # A keyword hit can be a CVE about some other product that
                    # merely mentions ours in prose; only CPE product matches count.
                    if _product_of(criteria) != product:
                        continue
                    product_seen = True
                    cpes.append({"criteria": criteria,
                                 "start": cm.get("versionStartIncluding"),
                                 "end": cm.get("versionEndIncluding") or cm.get("versionEndExcluding")})
                    if version and _version_in_range(version, cm):
                        matched = True
        if not product_seen:
            continue
        desc = next((d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"), "")
        cwes = sorted({
            d.get("value") for w in cve.get("weaknesses", [])
            for d in w.get("description", [])
            if (d.get("value") or "").startswith("CWE-")
        })
        out.append({
            "id": cve.get("id"),
            "summary": desc[:600],
            "score": _score(cve),
            "cwes": cwes,
            "published": (cve.get("published") or "")[:10],
            "matched_version": matched,
            "cpes": cpes[:5],
        })

    result = {"ok": True, "keyword": keyword, "version": version,
              "total": len(out), "cves": out,
              "affected": [c for c in out if c["matched_version"]]}
    cp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
