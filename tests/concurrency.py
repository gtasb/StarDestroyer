"""Concurrency gate: 50 parallel query agents must not exceed the pool.

Mirrors the spec's "50 agent 并行 / Neo4j 不 OOM" check against the embedded
graph instead of a server.
"""

import asyncio
import pathlib
import sys
import threading

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))
__import__("os").environ["SCA_OSV"] = "0"  # offline

import _env  # noqa: F401
from core import graph, pools

DB = pathlib.Path(__file__).resolve().parents[1] / ".work" / "tabby" / "gadget" / "cpg.db"
_LOCK = threading.Lock()
_peak = 0
_live = 0


def _count(conn):
    # The lock lives inside the worker thread: holding a threading.Lock across
    # an await blocks the event loop and deadlocks every other task.
    with _LOCK:
        rows = graph.query(conn, "MATCH (m:Method) RETURN count(m) AS n")
    return rows[0]["n"]


async def one(conn, i):
    global _peak, _live
    async with pools.acquire("neo4j_query"):
        _live += 1
        _peak = max(_peak, _live)
        try:
            return await asyncio.to_thread(_count, conn)
        finally:
            _live -= 1


def main() -> int:
    if not DB.exists():
        print("SKIP: no graph at", DB)
        return 0
    conn = graph.open_db(str(DB))
    results = asyncio.run(_run(conn))
    limit = int(__import__("os").environ.get("AUDIT_POOL_NEO4J_QUERY", "3"))
    print(f"tasks={len(results)} peak_concurrency={_peak} limit={limit}")
    ok = _peak <= limit and len(results) == 50
    print("PASS" if ok else "FAIL")
    return 0 if ok else 1


async def _run(conn):
    return await asyncio.gather(*[one(conn, i) for i in range(50)])


if __name__ == "__main__":
    raise SystemExit(main())
