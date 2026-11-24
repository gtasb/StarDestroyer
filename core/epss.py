"""EPSS scores (FIRST.org), batched and cached.

EPSS answers "how likely is this to be exploited in the next 30 days"; CVSS
answers "how bad if it is". Triage needs both, and both must come from a source
that can be cited -- not from a model's memory.
"""

import hashlib
import json
import pathlib
import urllib.parse

from . import net

API = "https://api.first.org/data/v1/epss"
CACHE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "epss"


def scores(cve_ids: list[str]) -> dict[str, dict]:
    """{cve: {epss, percentile, date}}; unknown ids are simply absent."""
    ids = sorted({c for c in cve_ids if c})
    if not ids:
        return {}
    CACHE.mkdir(parents=True, exist_ok=True)
    key = CACHE / (hashlib.sha256(",".join(ids).encode()).hexdigest()[:16] + ".json")
    if key.exists():
        try:
            return json.loads(key.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass

    out: dict[str, dict] = {}
    for i in range(0, len(ids), 100):  # the API caps at 100 per request
        chunk = ids[i:i + 100]
        url = f"{API}?{urllib.parse.urlencode({'cve': ','.join(chunk)})}"
        try:
            doc = net.request_json(url, headers={"User-Agent": "stardestroyer/0.1"})
        except Exception:
            continue
        for row in doc.get("data", []):
            out[row["cve"]] = {
                "epss": float(row.get("epss") or 0),
                "percentile": float(row.get("percentile") or 0),
                "date": row.get("date"),
            }
    key.write_text(json.dumps(out, ensure_ascii=False), encoding="utf-8")
    return out
