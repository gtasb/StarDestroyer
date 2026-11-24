"""Offline checks for the SCA triage gate.

No network: EPSS is stubbed. The cases that matter are the three ways a row can
land -- dropped for being both low-score and unused, kept because the score is
high, and kept because there was no source to judge reachability from.
"""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from core import sca_triage


def _comp(cves):
    return {"ok": True, "components": [
        {"name": "some-lib", "version": "1.0", "vendor": "com.example", "cves": cves},
    ]}


def main() -> int:
    sca_triage.epss.scores = lambda ids: {}  # offline

    with tempfile.TemporaryDirectory() as d:
        pathlib.Path(d, "App.java").write_text("import java.util.List;\nclass App {}\n",
                                               encoding="utf-8")

        low = sca_triage.triage(_comp([{
            "id": "CVE-LOW", "score": 5.0, "cwes": [], "summary": "minor",
            "cpes": [], "matched_version": True}]), app_root=d)
        high_cvss = sca_triage.triage(_comp([{
            "id": "CVE-HIGH", "score": 9.8, "cwes": ["CWE-502"], "summary": "rce",
            "cpes": [], "matched_version": True}]), app_root=d)
        no_source = sca_triage.triage(_comp([{
            "id": "CVE-LOW", "score": 5.0, "cwes": [], "summary": "minor",
            "cpes": [], "matched_version": True}]), app_root=str(pathlib.Path(d) / "missing"))

    checks = [
        ("low score + unused -> ignored", len(low["ignored"]) == 1 and not low["kept"]),
        ("high cvss -> kept", len(high_cvss["kept"]) == 1),
        ("high cvss maps to a sink family", high_cvss["kept"][0]["family"] == "deserialization"),
        ("no source -> kept, not ignored", len(no_source["kept"]) == 1),
        ("no source is reported", no_source["kept"][0]["source_scanned"] == 0),
    ]
    failed = [name for name, ok in checks if not ok]
    for name, ok in checks:
        print(("PASS " if ok else "FAIL ") + name)
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
