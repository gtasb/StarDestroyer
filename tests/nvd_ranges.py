"""Offline checks for NVD version matching.

Uses the real cpeMatch block returned by NVD for CVE-2015-6420, so the range
logic is verified without depending on the API being reachable.
"""

import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import _env  # noqa: F401
from core import nvd

CVE_2015_6420 = [
    {"criteria": "cpe:2.3:a:apache:commons_collections:*:*:*:*:*:*:*:*",
     "versionStartIncluding": "3.0", "versionEndExcluding": "3.2.2", "vulnerable": True},
    {"criteria": "cpe:2.3:a:apache:commons_collections:4.0:*:*:*:*:*:*:*",
     "vulnerable": True},
]


def main() -> int:
    cases = [("3.2.1", True), ("3.0", True), ("3.2.2", False),
             ("2.1", False), ("4.0", True), ("4.1", False)]
    failures = []
    for version, expected in cases:
        got = any(nvd._version_in_range(version, cm) for cm in CVE_2015_6420)
        if got != expected:
            failures.append(f"{version}: expected {expected}, got {got}")
    print("cpe product of 'commons-collections' ->", nvd._cpe_products("commons-collections"))
    if failures:
        print("FAIL:", "; ".join(failures))
        return 1
    print(f"PASS: {len(cases)} version cases")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
