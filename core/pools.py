"""Resource pools.

Agents are unbounded; resources are not. Semaphores are acquired for a single
operation and released immediately -- never held across an agent's lifetime
(holding neo4j_query while a 20-minute tabby job runs is the failure mode this
module exists to prevent).
"""

import asyncio
import os
from contextlib import asynccontextmanager

_DEFAULT_LIMITS = {
    "neo4j_query": 3,   # variable-length path queries; heap is the hard ceiling
    "tabby_ingest": 1,  # Soot builds the graph in one JVM: must be serial
    "opengrep": 4,      # OCaml multicore; do not match core count
    "llm": 8,           # sized to TPM quota
}


def _limit(name: str) -> int:
    override = os.environ.get(f"AUDIT_POOL_{name.upper()}")
    return int(override) if override else _DEFAULT_LIMITS[name]


POOLS: dict[str, asyncio.Semaphore] = {
    name: asyncio.Semaphore(_limit(name)) for name in _DEFAULT_LIMITS
}


def stats() -> dict:
    """Free slots per pool, for the console's health line."""
    return {
        name: {"limit": _DEFAULT_LIMITS[name], "free": sem._value}
        for name, sem in POOLS.items()
    }


@asynccontextmanager
async def acquire(*resources):
    # Sorted fixed order: two callers asking for overlapping sets can never
    # deadlock on a different acquisition sequence.
    order = sorted(resources)
    unknown = [r for r in order if r not in POOLS]
    if unknown:
        raise KeyError(f"unknown pool(s): {unknown}")
    for r in order:
        await POOLS[r].acquire()
    try:
        yield
    finally:
        for r in reversed(order):
            POOLS[r].release()
