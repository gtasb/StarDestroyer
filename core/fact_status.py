"""Fact status, mirrored from Burp-AI-Analyzer's GraphTypes.FactStatus.

The rank ordering is the point: a fact never silently downgrades, and a rejected
inference is not resurrected by another guess. Only direct observation or an
explicit confirmation may override a rejection.
"""

from enum import Enum


class FactStatus(Enum):
    OBSERVED = 5
    CONFIRMED = 4
    DERIVED = 3
    INFERRED = 2
    REJECTED = 1


def promote(existing: str | None, incoming: str | None) -> str:
    if not existing:
        return incoming or FactStatus.INFERRED.name
    try:
        e, i = FactStatus[existing], FactStatus[incoming or "INFERRED"]
    except KeyError:
        return existing
    # A rejection overrides a guess, never an observation or a confirmation.
    if i is FactStatus.REJECTED:
        return i.name if e in (FactStatus.INFERRED, FactStatus.DERIVED) else e.name
    if e is FactStatus.REJECTED and i not in (FactStatus.OBSERVED, FactStatus.CONFIRMED):
        return existing
    return i.name if i.value > e.value else existing


DEFAULT_CONFIDENCE = {
    "OBSERVED": 0.9,
    "CONFIRMED": 0.8,
    "DERIVED": 0.7,
    "INFERRED": 0.5,
    "REJECTED": 0.1,
}
