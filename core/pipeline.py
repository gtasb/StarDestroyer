"""Cascade orchestration.

Phase 1 runs Opengrep only; Tabby slots in beside it at step 3. Every artifact
is derived from one records list, so the report can never drift from the JSON.
"""

import json
import pathlib
import time

from . import agent, ledger, records, report, sarif, verdict
from .engines import opengrep

RULES = {
    "java": "java-taint.yaml",
    "python": "python-taint.yaml",
    "go": "go-taint.yaml",
}
TEMPLATES = pathlib.Path(__file__).resolve().parent / "templates" / "opengrep"
SCANS_DIR = pathlib.Path(__file__).resolve().parents[1] / ".work" / "scans"


def rules_for(lang: str) -> str:
    try:
        return str(TEMPLATES / RULES[lang])
    except KeyError:
        raise ValueError(f"unsupported language: {lang} (have {sorted(RULES)})")


def scan(src: str, lang: str = "java", ai: bool = False, verify: bool = False,
         extra_rules: str | None = None) -> dict:
    if not pathlib.Path(src).exists():
        return {"ok": False, "error": f"路径不存在: {src}"}
    if lang not in RULES:
        return {"ok": False, "error": f"暂不支持语言: {lang}，可选 {sorted(RULES)}"}

    started = time.time()
    res = opengrep.run_scan(src, rules=rules_for(lang),
                            extra_rules=[extra_rules] if extra_rules else None)

    recs: list[dict] = []
    for f in res["findings"]:
        v = verdict.judge(f, None, src)
        recs.append(records.make(f, v, src))

    recs, prior_rejected = agent.filter_rejected(recs)
    reportable = [r for r in recs if verdict.is_reportable({"status": r["status"]})]

    verification = None
    if verify:
        verification = agent.run(reportable)
        reportable = [r for r in reportable if r["status"] != "rejected"]
    ledger_doc = ledger.build(src, lang, res["findings"], ledger.EXTENSIONS)

    scan_dir = SCANS_DIR / time.strftime("%Y%m%d-%H%M%S")
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "findings.json").write_text(
        json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")
    (scan_dir / "ledger.json").write_text(
        json.dumps(ledger_doc, ensure_ascii=False, indent=2), encoding="utf-8")

    out = report.write(reportable, str(scan_dir), title=f"audit-{lang}")
    out["sarif"] = sarif.write_sarif(reportable, str(scan_dir / "findings.sarif"))
    out["findings_json"] = str(scan_dir / "findings.json")
    out["ledger_json"] = str(scan_dir / "ledger.json")

    ai_notes = []
    if ai:
        from . import llm
        if llm.available():
            for rec in reportable[:report.TOP_N]:
                r = llm.explain({"rule": rec["rule_id"], "file": rec["file"],
                                 "line": rec["line"], "trace": rec["trace"],
                                 "status": rec["status"], "reason": rec["reason"]})
                if r.get("ok"):
                    rec["ai_note"] = r["text"]
                    ai_notes.append(rec["file"])
            (scan_dir / "findings.json").write_text(
                json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")
            report.write(reportable, str(scan_dir), title=f"audit-{lang}")

    return {
        "ok": True,
        "engine": "opengrep",
        "unsupported_flags": res["unsupported_flags"],
        "interfile_languages": res.get("interfile_languages", []),
        "engine_errors": res.get("errors", []),
        "elapsed_s": round(time.time() - started, 2),
        "raw_hits": res["total"],
        "reportable": len(reportable),
        "status_counts": _counts(reportable),
        "top": reportable[:report.TOP_N],
        "coverage": {k: ledger_doc[k] for k in
                     ("files", "units_total", "units_covered", "units_candidate")},
        "verification": verification,
        "previously_rejected": len(prior_rejected),
        "artifacts": out,
        "ai_notes": ai_notes,
    }


TABBY_WORK = SCANS_DIR.parent / "tabby"


def _counts(records: list[dict]) -> dict:
    out = {"confirmed": 0, "needs_review": 0, "needs_dynamic": 0, "rejected": 0}
    for r in records:
        st = r.get("status")
        if st in out:
            out[st] += 1
    return out


def tabby_audit(target_jar: str, workdir: str | None = None, mode: str = "gadget",
                heap: str = "4g", limit: int = 30, wait_s: int = 60) -> dict:
    """Recall pass over compiled Java. Build is a job; nothing blocks > wait_s."""
    from . import jobs
    from .engines import tabby

    if not tabby.available():
        return {"ok": False, "error": "Tabby 未安装：设置 TABBY_JAR 或放到 .work/tabby/dist/tabby.jar"}
    jar = pathlib.Path(target_jar)
    if not jar.exists():
        return {"ok": False, "error": f"目标不存在: {target_jar}"}

    workdir = workdir or str(TABBY_WORK / jar.stem)
    tabby.prepare_workspace(workdir, target=str(jar.resolve()), mode=mode)
    job = tabby.submit_build(workdir, heap=heap)
    st = jobs.wait(job["job_id"], timeout_s=wait_s)
    if st.get("state") == "running":
        return {"ok": True, "pending": job["job_id"],
                "hint": "构建仍在进行；完成后再次调用即可（图会重新生成）"}
    if st.get("exit") not in (None, "0"):
        return {"ok": False, "error": "Tabby 构建失败", "tail": st.get("tail")}

    out_dir = pathlib.Path(workdir) / "output" / "dev"
    db_path = pathlib.Path(workdir) / "cpg.db"
    if db_path.exists():
        db_path.unlink()  # a stale graph would answer for the previous jar
    g = tabby.load_graph(str(out_dir), str(db_path))
    chains = tabby.find_gadget_chains(g["conn"], limit=limit)
    recs = tabby.to_records(chains)
    reportable = [r for r in recs if verdict.is_reportable({"status": r["status"]})]

    scan_dir = SCANS_DIR / f"tabby-{time.strftime('%Y%m%d-%H%M%S')}"
    scan_dir.mkdir(parents=True, exist_ok=True)
    (scan_dir / "findings.json").write_text(
        json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")
    out = report.write(reportable, str(scan_dir), title=f"tabby-{jar.stem}")
    out["sarif"] = sarif.write_sarif(reportable, str(scan_dir / "findings.sarif"))

    return {
        "ok": True,
        "engine": "tabby",
        "mode": mode,
        "graph": {k: v for k, v in g.items() if k != "conn"},
        "chains": len(chains),
        "reportable": len(reportable),
        "status_counts": _counts(reportable),
        "top": reportable[:report.TOP_N],
        "artifacts": out,
    }
