"""Software composition analysis.

OpenSCA gives the dependency tree (including transitive deps); it does not ship
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

from . import nvd

OPENSCA_BIN = os.environ.get("OPENSCA_BIN") or ""
if not OPENSCA_BIN:
    _here = pathlib.Path(__file__).resolve()
    for _base in (_here.parents[2], _here.parents[3]):
        for name in ("opensca-cli.exe", "opensca-cli"):
            cand = _base / ".work" / "opensca" / "bin" / name
            if cand.exists():
                OPENSCA_BIN = str(cand)
                break

_BUILD = ("pom.xml", "build.gradle", "requirements.txt")


def available() -> bool:
    return bool(OPENSCA_BIN) and pathlib.Path(OPENSCA_BIN).exists()


def _flatten(node: dict, depth: int = 0) -> list[dict]:
    out = [{
        "vendor": node.get("vendor", ""),
        "name": node.get("name", ""),
        "version": node.get("version", ""),
        "language": node.get("language", ""),
        # root is the project itself; its children are the declared deps
        "direct": depth <= 1,
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
        proc = subprocess.run(
            [OPENSCA_BIN, "-path", str(pathlib.Path(root).resolve()), "-out", out],
            capture_output=True, text=True, timeout=timeout_s,
            encoding="utf-8", errors="replace",
        )
        if not pathlib.Path(out).exists() or pathlib.Path(out).stat().st_size == 0:
            return {"ok": False, "error": "OpenSCA 未产出报告",
                    "stderr": (proc.stderr or "")[-800:]}
        doc = json.loads(pathlib.Path(out).read_text(encoding="utf-8", errors="replace"))
        comps = _flatten(doc)
        return {"ok": True, "components": comps, "task": doc.get("task_info", {}),
                "report": out}
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"OpenSCA 超时（{timeout_s}s）"}
    except Exception as exc:
        return {"ok": False, "error": str(exc)}


def builtin(root: str) -> dict:
    """Fallback: versions straight from build descriptors."""
    p = pathlib.Path(root)
    comps: list[dict] = []
    for anc in (p, p.parent):
        pom = anc / "pom.xml"
        if pom.exists():
            text = pom.read_text(encoding="utf-8", errors="replace")
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
                m = re.match(r"\s*([A-Za-z0-9_.\-]+)\s*==\s*([\w.\-]+)", line)
                if m:
                    comps.append({"vendor": "", "name": m.group(1), "version": m.group(2),
                                  "language": "Python", "direct": True, "paths": [str(req)]})
    return {"ok": True, "components": comps, "task": {"error": "builtin parser"}}


def components(root: str) -> dict:
    res = run_opensca(root)
    if res.get("ok") and res.get("components"):
        res["source"] = "opensca"
        return res
    fallback = builtin(root)
    fallback["source"] = "builtin"
    fallback["opensca_error"] = res.get("error")
    return fallback


def enrich(root: str, max_lookups: int = 12) -> dict:
    """Attach NVD CVEs to components that carry a version."""
    comps = components(root)
    if not comps.get("ok"):
        return comps
    seen, lookups = set(), 0
    for c in comps["components"]:
        key = (c["name"].lower(), c["version"])
        if not c["version"] or key in seen or lookups >= max_lookups:
            c["cves"] = []
            continue
        seen.add(key)
        lookups += 1
        r = nvd.lookup(c["name"], c["version"])
        c["cves"] = r.get("affected", []) if r.get("ok") else []
        c["nvd_error"] = r.get("error")
    return comps
