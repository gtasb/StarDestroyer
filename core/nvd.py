"""NVD lookup.

NVD's public API allows 5 requests per 30s without a key, so calls are spaced
and every answer is cached to disk. Version matching is done against the CPE
ranges NVD returns -- a bare keyword hit is not evidence that this version is
affected.
"""

import hashlib
import json
import os
import pathlib
import re
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
PAGE = 2000                 # NVD's maximum for /cves/2.0
CPE_PAGE = 10000            # a small page fills up with one vendor's versions
MAX_VENDORS = 5
CACHE_TTL_S = 24 * 3600     # new CVEs land daily; an old "0 CVE" is not evidence

# Maven artifactId -> CPE product, where the two names differ. Anything not
# listed is tried under its own name; a miss is reported, never read as clean.
_CPE_ALIAS = {
    "log4j-core": "log4j", "log4j-api": "log4j",
    "spring-core": "spring_framework", "spring-web": "spring_framework",
    "spring-webmvc": "spring_framework", "spring-webflux": "spring_framework",
    "spring-beans": "spring_framework", "spring-context": "spring_framework",
    "spring-expression": "spring_framework", "spring-aop": "spring_framework",
    "spring-jdbc": "spring_framework", "spring-tx": "spring_framework",
    "spring-messaging": "spring_framework", "spring-orm": "spring_framework",
    "spring-boot-starter-web": "spring_boot", "spring-boot-autoconfigure": "spring_boot",
    "spring-security-core": "spring_security", "spring-security-web": "spring_security",
    "spring-security-config": "spring_security",
    "tomcat-embed-core": "tomcat", "tomcat-catalina": "tomcat", "tomcat-coyote": "tomcat",
    "struts2-core": "struts", "shiro-core": "shiro", "shiro-web": "shiro",
    "jetty-server": "jetty", "jetty-http": "jetty",
    "netty-all": "netty", "netty-codec-http": "netty", "netty-handler": "netty",
    "undertow-core": "undertow", "hibernate-core": "hibernate_orm",
    "mysql-connector-java": "mysql_connector\\/j", "mysql-connector-j": "mysql_connector\\/j",
    "fastjson2": "fastjson", "velocity": "velocity_engine",
    "commons-fileupload2-core": "commons_fileupload",
}


# Families whose modules share one CPE product.
_CPE_PREFIX = [("spring-boot", "spring_boot"), ("spring-security", "spring_security"), ("logback-", "logback"),
               ("netty-", "netty"), ("tomcat-embed-", "tomcat"), ("shiro-", "shiro"), ("jetty-", "jetty"),
               ("undertow-", "undertow"), ("hutool-", "hutool"), ("poi-", "poi"), ("druid", "druid"),
               ("xxl-job", "xxl-job"), ("log4j-", "log4j"), ("kafka-", "kafka")]


def _throttle() -> None:
    limit = _MIN_GAP_KEYED if api_key() else _MIN_GAP_ANON
    gap = time.time() - _last_call[0]
    if gap < limit:
        time.sleep(limit - gap)
    _last_call[0] = time.time()


def _cache_path(key: str) -> pathlib.Path:
    safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in key)[:60]
    digest = hashlib.sha256(key.encode()).hexdigest()[:12]
    return CACHE_DIR / f"{safe}-{digest}.json"


def _get(params: dict, attempts: int = 3, base: str | None = None) -> dict:
    qs = urllib.parse.urlencode(params)
    url = f"{base or BASE}?{qs}"
    headers = {"User-Agent": "stardestroyer/0.1"}
    if api_key():
        headers["apiKey"] = api_key()
    _throttle()
    return net.request_json(url, headers=headers, attempts=attempts)


# Order of pre- and post-release words around the plain release (0). Words that
# only name the build (RELEASE, Final, jre8, v20220622, android) are the release.
_WORDS = {"dev": -6, "snapshot": -1, "alpha": -5, "a": -5, "beta": -4, "b": -4,
          "milestone": -3, "m": -3, "pre": -2, "preview": -2, "rc": -2, "cr": -2, "c": -2,
          "sp": 1, "post": 1, "patch": 1, "p": 1}
_VER = re.compile(r"\d+|[a-z]+")


def _ver_key(v: str) -> tuple[list[int], int, int]:
    """(numeric parts without trailing zeros, qualifier rank, qualifier number)."""
    v = v.strip().lower().split("+", 1)[0]
    v = re.sub(r"[.\-_]v\d{8}.*$", "", re.sub(r"^[v=]+(?=\d)", "", v))
    nums: list[int] = []
    rank = number = 0
    tokens = _VER.findall(v)
    for i, tok in enumerate(tokens):
        if tok.isdigit():
            nums.append(int(tok))
        elif tok in _WORDS:
            rank = _WORDS[tok]
            rest = tokens[i + 1:]
            number = int(rest[0]) if rest and rest[0].isdigit() else 0
            break
        elif nums and len(tok) == 1 and not tokens[i + 1:]:
            number = ord(tok)  # openssl 1.0.2k: a letter patch level
            rank = 1
            break
        else:
            break
    while nums and nums[-1] == 0:
        nums.pop()
    return nums, rank, number


def comparable(v: str) -> bool:
    """A concrete version: not empty, a placeholder or a range."""
    return bool(re.match(r"^[vV=]?\d", v or "")) and not re.search(r"[${}\[\](),*]", v)


def _cmp(a: str, b: str) -> int:
    ka, kb = _ver_key(a), _ver_key(b)
    return (ka > kb) - (ka < kb)


def _version_in_range(version: str, cpe_match: dict) -> bool:
    for field, outside in (("versionEndExcluding", lambda c: c >= 0), ("versionEndIncluding", lambda c: c > 0),
                           ("versionStartIncluding", lambda c: c < 0), ("versionStartExcluding", lambda c: c <= 0)):
        if field in cpe_match and outside(_cmp(version, cpe_match[field])):
            return False
    parts = cpe_match.get("criteria", "").split(":")
    if len(parts) > 5 and parts[5] not in ("*", "-") and version:
        exact = parts[5]
        # 2.0:beta9 is not 2.0
        if len(parts) > 6 and parts[6] not in ("*", "-", ""):
            exact += f"-{parts[6]}"
        return _cmp(exact.replace("\\", ""), version) == 0
    return True


def _score(cve: dict) -> float | None:
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        got = [s for s in ((i.get("cvssData") or {}).get("baseScore")
                           for i in metrics.get(key) or []) if s is not None]
        if got:
            return max(got)
    return None


def _cpe_products(keyword: str) -> list[str]:
    """CPE product names to try. NVD is not consistent about separators:
    jackson-databind keeps its hyphen, commons_collections does not."""
    name = keyword.lower().strip()
    if name in _CPE_ALIAS:
        return [_CPE_ALIAS[name]]
    for prefix, product in _CPE_PREFIX:
        if name.startswith(prefix):
            return [product]
    # Go modules: github.com/gin-gonic/gin/v2 -> gin
    name = re.sub(r"/v\d+$", "", name).rsplit("/", 1)[-1]
    out = []
    for cand in (re.sub(r"[^a-z0-9]+", "_", name), re.sub(r"[^a-z0-9\-]+", "_", name)):
        cand = cand.strip("_-")
        if cand and cand not in out:
            out.append(cand)
    return out


def _resolve_vendors(product: str, group: str = "") -> list[str]:
    """CPE dictionary first: the vendor segment decides which CVE query is valid.
    A wildcard vendor in virtualMatchString returns unstable, unrelated sets."""
    doc = _get({"cpeMatchString": f"cpe:2.3:a:*:{product}:*:*:*:*:*:*:*:*",
                "resultsPerPage": CPE_PAGE}, base=CPE_BASE)
    if int(doc.get("totalResults") or 0) > CPE_PAGE:
        raise RuntimeError(f"CPE 字典返回 {doc['totalResults']} 条，超过单页上限，vendor 可能不全")
    vendors = []
    for p in doc.get("products", []):
        parts = (p.get("cpe") or {}).get("cpeName", "").split(":")
        if len(parts) > 3 and parts[3] not in ("*", "-") and parts[3] not in vendors:
            vendors.append(parts[3])
    # The Maven group usually contains the vendor (org.apache.* -> apache), so
    # put those first: the cap must not cut off the right one.
    vendors.sort(key=lambda v: v.lower() not in group.lower().replace("-", "."))
    return vendors


def _fetch_all(vendor: str, product: str, merged: dict[str, dict]) -> None:
    start = 0
    while True:
        # cpeName rejects wildcard versions (404); virtualMatchString with a
        # resolved vendor is the stable query.
        doc = _get({"virtualMatchString": f"cpe:2.3:a:{vendor}:{product}",
                    "resultsPerPage": PAGE, "startIndex": start})
        items = doc.get("vulnerabilities", [])
        for item in items:
            cid = (item.get("cve") or {}).get("id")
            if cid:
                merged[cid] = item
        start += len(items)
        if start >= int(doc.get("totalResults") or 0):
            return
        if not items:
            raise RuntimeError(f"NVD 分页中断：{start}/{doc.get('totalResults')}")


def _search(keyword: str, group: str = "") -> dict:
    products = _cpe_products(keyword)
    merged: dict[str, dict] = {}
    errors, found = [], []
    for product in products:
        try:
            vendors = _resolve_vendors(product, group)
        except Exception as exc:
            errors.append(f"CPE 字典 {product}: {exc}")
            continue
        if vendors:
            found.append(product)
        if len(vendors) > MAX_VENDORS:
            errors.append(f"{product} 有 {len(vendors)} 个 vendor，只查了前 {MAX_VENDORS} 个")
        for vendor in vendors[:MAX_VENDORS]:
            try:
                _fetch_all(vendor, product, merged)
            except Exception as exc:
                errors.append(f"{vendor}:{product}: {exc}")
    if not found and not errors:
        raise LookupError(f"CPE 字典中找不到产品: {' / '.join(products)}")
    if not merged and errors:
        raise RuntimeError("; ".join(errors))
    return {"vulnerabilities": list(merged.values()), "totalResults": len(merged),
            "errors": errors}


def _product_of(criteria: str) -> str:
    parts = criteria.split(":")
    return parts[4] if len(parts) > 4 else ""


def known(cve: str) -> str:
    """What the cached lookups say about a CVE; no request is made."""
    for f in sorted(CACHE_DIR.glob("v5*.json"), key=lambda f: -f.stat().st_mtime):
        try:
            rows = json.loads(f.read_text(encoding="utf-8")).get("cves", [])
        except (OSError, ValueError):
            continue
        for c in rows:
            if c.get("id") == cve:
                ranges = "; ".join(f"{x.get('start') or '*'} .. {x.get('end') or '*'}" for x in c.get("cpes", []))
                return f"{cve} CVSS {c.get('score')} {' '.join(c.get('cwes', []))}\n{c.get('summary', '')}\n受影响区间：{ranges}"
    return ""


def cached(keyword: str, version: str | None = None, group: str = "") -> bool:
    """Whether lookup() would answer without a request."""
    cp = _cache_path(f"v5:{group}:{keyword}@{version or '*'}")
    return cp.exists() and time.time() - cp.stat().st_mtime < CACHE_TTL_S


def lookup(keyword: str, version: str | None = None, group: str = "") -> dict:
    """CVEs for a product; with a version, only those whose CPE range covers it.

    `error` next to ok=True means the answer is partial: part of the query failed
    and more CVEs may apply. Partial answers are never cached.
    """
    cp = _cache_path(f"v5:{group}:{keyword}@{version or '*'}")
    if cp.exists() and time.time() - cp.stat().st_mtime < CACHE_TTL_S:
        try:
            return {**json.loads(cp.read_text(encoding="utf-8")), "cached": True}
        except json.JSONDecodeError:
            pass

    try:
        doc = _search(keyword, group)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "keyword": keyword}

    wanted = set(_cpe_products(keyword))
    out = []
    for item in doc.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("vulnStatus") == "Rejected":
            continue
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
                    if _product_of(criteria) not in wanted:
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
    if doc.get("errors"):
        return {**result, "error": "；".join(doc["errors"])}
    cp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    return result
