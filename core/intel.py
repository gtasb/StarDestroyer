"""External intel.

Tavily fills the gap NVD leaves: the CVE text says what is broken, not which
API shape reaches it. Results are always returned with their URL so a finding
can cite them; nothing here is auto-merged into a report.
"""

import os

from . import net

API = "https://api.tavily.com/search"
KEY = os.environ.get("TAVILY_API_KEY", "")


def available() -> bool:
    return bool(KEY)


def search(query: str, max_results: int = 5, depth: str = "basic") -> dict:
    if not KEY:
        return {"ok": False, "error": "TAVILY_API_KEY 未设置",
                "hint": "也可由宿主挂载 Tavily MCP 提供同名能力"}
    payload = {"api_key": KEY, "query": query, "max_results": max_results,
               "search_depth": depth, "include_answer": False}
    try:
        doc = net.post_json(API, payload)
    except Exception as exc:
        return {"ok": False, "error": str(exc), "query": query}
    return {
        "ok": True,
        "query": query,
        "results": [{"title": r.get("title"), "url": r.get("url"),
                     "score": r.get("score"), "content": (r.get("content") or "")[:800]}
                    for r in doc.get("results", [])],
    }


def n_day_context(cve_id: str, product: str = "") -> dict:
    """What an N-day is actually reachable through: gadget, sink, exploit path."""
    q = f"{cve_id} {product} exploit gadget sink 调用链".strip()
    res = search(q, max_results=5)
    res["cve"] = cve_id
    return res
