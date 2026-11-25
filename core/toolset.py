"""Tool registry.

The MCP adapter and the web console both register from here; neither holds
logic of its own. Everything returns JSON-able dicts.
"""

import asyncio
import json
import ntpath
import os
import pathlib

from . import (asset_graph, audit, codeintel, config, intel, jobs, kb, nvd, pipeline, pools, proc, profile, review,
               rulegen, sca)
from . import logging
from . import sca_triage


config.apply()  # every entry point (web, MCP, CLI) goes through this module


def _prepare_rules(src: str) -> dict:
    """Profile the project, propose rules from its dependencies, prove them."""
    prof = profile.profile(src)
    if not prof.get("ok"):
        return {"ok": False, "error": prof.get("error")}
    props = rulegen.propose(prof)
    if not props:
        return {"ok": True, "profile": prof, "rules": [], "files": [], "failed": [],
                "note": "未从依赖中识别出可生成规则的框架"}
    proc.stage("生成并验证项目规则")
    written = rulegen.write(props, src)
    bad = {f["id"] for f in written["failed"]}
    return {"ok": True, "profile": prof, "rules": [p for p in props if p["id"] not in bad],
            "dir": written["dir"], "files": written["files"], "failed": written["failed"]}


def auto_scan(path: str, lang: str = "auto", verify: bool = False) -> dict:
    """Profile -> generate -> validate -> scan, one call."""
    prep = _prepare_rules(path)
    if not prep.get("ok"):
        return {"ok": False, "error": prep.get("error"), "detail": prep}
    from . import airules
    res = pipeline.scan(path, lang, verify, extra_rules=prep["files"] + airules.files(path))
    if res.get("ok"):
        # A generated rule that fails its proof is dropped, never the whole scan.
        res["rules_failed"] = prep["failed"]
        for f in prep["failed"]:
            res["incomplete_reasons"].append(f"生成的规则 {f['id']} 未通过验证，未启用：{f['error']}")
        res["complete"] = not res["incomplete_reasons"]
        res["generated_rules"] = [{"id": p["id"], "reason": p["reason"]}
                                  for p in prep["rules"]]
        res["rules_applied"] = bool(prep["files"])
        res["profile"] = {"language": prep["profile"].get("language"),
                          "frameworks": prep["profile"].get("frameworks", []),
                          "dependencies": prep["profile"].get("dependencies", [])[:8]}
    return res


async def audit_scan(path: str, lang: str = "auto", verify: bool = False, auto: bool = True) -> dict:
    """Taint scan. auto=True lets the agent write rules for this project first.

    lang=auto covers every supported language present. Read `complete`: when it is
    False, `incomplete_reasons` says what was not covered and 0 hits is not clean.
    """
    async with pools.acquire("opengrep"):
        if auto:
            return await asyncio.to_thread(auto_scan, path, lang, verify)
        return await asyncio.to_thread(pipeline.scan, path, lang, verify)


def secrets_scan(path: str) -> dict:
    """Hardcoded credentials (gitleaks + built-in rules). Values are masked everywhere."""
    from . import hardcoded
    return hardcoded.scan(path)


def java_build(path: str) -> dict:
    """Compile a Maven/Gradle project for audit_jar. Runs the project's build scripts:
    only for code you would run on this machine."""
    from . import build
    return build.run(path)


async def audit_jar(target_jar: str, mode: str = "gadget", heap: str = "4g",
                    limit: int = 30) -> dict:
    """Tabby recall pass over a compiled jar; serialised by tabby_ingest."""
    async with pools.acquire("tabby_ingest"):
        return await asyncio.to_thread(pipeline.tabby_audit,
                                       target_jar, None, mode, heap, limit)


def project_profile(path: str) -> dict:
    """Detected language, build files, dependencies and frameworks."""
    return profile.profile(path)


def propose_rules(path: str, apply: bool = False) -> dict:
    """Rules generated from this project's dependencies. apply=True validates
    and writes them for use by the next scan."""
    prep = _prepare_rules(path) if apply else None
    if prep is not None:
        return prep
    prof = profile.profile(path)
    return {"ok": prof.get("ok"), "profile": prof,
            "rules": [{"id": p["id"], "reason": p["reason"], "yaml": p["yaml"]}
                      for p in rulegen.propose(prof)]}


def list_generated_rules() -> dict:
    return {"dir": str(rulegen.OUT_DIR), "manifest": rulegen.load_manifest()}


def kb_ingest(path: str) -> dict:
    """Index a folder of .md/.txt documents for retrieval."""
    return kb.ingest_dir(path)


def kb_search(query: str, k: int = 5) -> dict:
    """Retrieve the top-k chunks. The caller cites them; nothing is injected."""
    return {"query": query, "hits": kb.search(query, k)}


def kb_list() -> dict:
    return {"docs": kb.list_docs()}


def rag_preview(query: str, k: int = 5) -> dict:
    """Exact chunks retrieval would return, with size. Nothing is injected."""
    return kb.preview(query, k)


def sca_scan(path: str, max_lookups: int = 12) -> dict:
    """Dependencies (OpenSCA tree, indirect ones by setting) mapped to NVD CVEs."""
    return sca.enrich(path, max_lookups)


def nvd_lookup(product: str, version: str = "") -> dict:
    """CVEs whose CPE range actually covers this version."""
    return nvd.lookup(product, version or None)


def web_search(query: str, max_results: int = 5) -> dict:
    """Tavily search; results carry URLs for citation."""
    return intel.search(query, max_results)


def n_day_context(cve_id: str, product: str = "") -> dict:
    """Search for how an N-day is reached: gadget, sink, exploit path."""
    return intel.n_day_context(cve_id, product)


def sca_triage_scan(path: str, cvss_min: float = 7.0, epss_pct_min: float = 0.95,
                    max_lookups: int = 12, indirect: bool | None = None) -> dict:
    """Deterministic gate over dependency CVEs, plus the questions an agent must answer.

    The gate keeps a CVE when CVSS >= cvss_min OR EPSS percentile >= epss_pct_min,
    and never drops one for "unused" when there was no source to check. What is
    left is handed over as `candidates` with explicit read/grep steps: deciding
    reachability needs a reader with tools, not a blind model call.
    """
    comps = sca.enrich(path, max_lookups=max_lookups, indirect=indirect)
    t = sca_triage.triage(comps, app_root=path, cvss_min=cvss_min,
                          epss_pct_min=epss_pct_min)
    if not t.get("ok"):
        return t
    t = sca_triage.apply_verdicts(t, sca_triage.load_verdicts(path))
    t["sinks"] = sca_triage.sink_report(t, path)
    t["candidates"] = sca_triage.candidates(t, path)
    t["sca"] = {"source": comps.get("source"), "lookups": comps.get("lookups"),
                "skipped": comps.get("skipped"), "osv": comps.get("osv"), "explained": comps.get("explained") or [],
                "maven": {k: (comps.get("maven") or {}).get(k) for k in ("missing", "modules", "complete")} if comps.get("maven") else None}
    return t


def sca_record_verdicts(path: str, verdicts: list[dict]) -> dict:
    """Persist an agent's keep/ignore decisions; ignore requires file:line evidence."""
    return sca_triage.record_verdicts(path, verdicts)


def review_candidates(path: str, max_items: int = 10) -> dict:
    """Findings of the last scan for you to refute by reading the code with your own tools."""
    return review.candidates(path, max_items)


def review_record(path: str, verdicts: list[dict]) -> dict:
    """Record reviews: {key, verdict: uphold|refute|uncertain, reason, evidence:[{file,line,quote}]}.

    Each quote must be found at its line. A refute lowers the finding for a person
    to confirm; it never removes it.
    """
    return review.record(path, verdicts)


def audit_run(path: str, scope: list[str] | None = None, max_units: int = 50) -> dict:
    """Run the agent audit (dsh sessions over the full source). Resumable.

    scope: any of chain, dependency, sink, endpoint, secret, review (leads from the engines) and
    hunt (the open round that follows them); default all.
    """
    return audit.run(path, scope, max_units)


def audit_status(path: str) -> dict:
    """Progress of the agent audit, its brief of the application and its findings."""
    return {"ok": True, **audit.progress(path), "findings": audit.findings(path)}


def audit_next(path: str, max_items: int = 1) -> dict:
    """Units of the audit for you to work on with your own tools over the full source."""
    return audit.next_units(path, max_items)


def audit_submit(path: str, unit_id: str, answer: dict) -> dict:
    """Submit a unit's answer. Every file:line quote is checked; errors say what to fix."""
    return audit.submit(path, unit_id, answer)


def code_navigate(path: str, what: str, name: str, owner: str = "") -> dict:
    """Code navigation. what: symbol | callers | implementations."""
    idx = codeintel.index(path)
    if what == "symbol":
        return {"ok": True, **idx.symbol(name)}
    if what == "callers":
        return {"ok": True, "callers": idx.callers(name, owner)}
    if what == "implementations":
        return {"ok": True, "types": idx.implementations(name)}
    return {"ok": False, "error": "what 应为 symbol / callers / implementations"}


def asset_graph_build(path: str, lookup_cves: bool = True, with_scan: bool = True,
                      findings: list[dict] | None = None) -> dict:
    """Build the asset graph. with_scan folds the audit findings into it."""
    gaps = []
    if with_scan:
        res = auto_scan(path)
        gaps = list(res.get("incomplete_reasons") or [])
        if res.get("ok") and res.get("artifacts", {}).get("findings_json"):
            try:
                findings = json.loads(pathlib.Path(res["artifacts"]["findings_json"])
                                      .read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                gaps.append(f"扫描结果读取失败: {exc}")
        else:
            gaps.append(f"源码扫描未完成: {res.get('error')}")
    out = asset_graph.build(path, findings=findings, lookup_cves=lookup_cves)
    if out.get("ok"):
        out["incomplete_reasons"] = gaps + out.get("incomplete_reasons", [])
        out["complete"] = not out["incomplete_reasons"]
    return out


def asset_graph_summary(db_path: str) -> dict:
    """Counts, risky dependencies and exposed endpoints."""
    # Opening a path creates a database there, and a UNC path connects to a host:
    # only an existing graph of ours may be opened. abspath does no I/O.
    db = asset_graph.DB_DIR / ntpath.basename(db_path)
    same = os.path.normcase(os.path.abspath(db_path)) == os.path.normcase(os.path.abspath(db))
    if not same or db.suffix != ".db" or not db.is_file():
        return {"ok": False, "error": "图谱不存在，或不在资产图谱目录内"}
    return asset_graph.summary(str(db))


def submit_job(command: str, label: str = "") -> dict:
    return jobs.submit(command, label=label)


def job_status(job_id: str, tail: int = 40) -> dict:
    return jobs.status(job_id, tail=tail)


def logs_tail(n: int = 200, level: str = "") -> dict:
    """Recent lines from the shared log file (.work/logs/stardestroyer.log)."""
    return logging.tail(n, level or None)


def pool_stats() -> dict:
    return pools.stats()


TOOLS = [
    ("audit_scan", audit_scan, "Taint scan; auto=True writes project-specific rules first."),
    ("secrets_scan", secrets_scan, "Hardcoded credentials: gitleaks plus rules for passwords and crypto keys; values masked."),
    ("java_build", java_build, "Compile a Maven/Gradle project (runs its build scripts) for audit_jar."),
    ("audit_jar", audit_jar, "Tabby recall pass over a compiled jar."),
    ("audit_run", audit_run, "Agent audit over the full source: entry points, sinks, broken chains, CVE reachability."),
    ("audit_status", audit_status, "Progress, application brief and findings of the agent audit."),
    ("audit_next", audit_next, "Audit units for you to work on with your own tools."),
    ("audit_submit", audit_submit, "Submit a unit's answer; citations are checked."),
    ("code_navigate", code_navigate, "Definitions, callers, implementations, MyBatis statements."),
    ("review_candidates", review_candidates, "Findings to review by reading the code; returns keys and instructions."),
    ("review_record", review_record, "Record reviews with quoted file:line evidence, checked on arrival."),
    ("project_profile", project_profile, "Language, build files, dependencies, frameworks."),
    ("propose_rules", propose_rules, "Rules generated from project dependencies."),
    ("list_generated_rules", list_generated_rules, "Generated rules and their manifest."),
    ("sca_scan", sca_scan, "Dependency tree mapped to NVD CVEs by version range."),
    ("sca_triage", sca_triage_scan, "CVSS/EPSS gate + sink mapping + open questions for the agent."),
    ("sca_record_verdicts", sca_record_verdicts, "Record keep/ignore decisions from source review."),
    ("nvd_lookup", nvd_lookup, "CVEs for a product/version."),
    ("web_search", web_search, "Tavily search with citable URLs."),
    ("n_day_context", n_day_context, "How an N-day is reached: gadget, sink, path."),
    ("asset_graph_build", asset_graph_build, "Build the asset graph for a project."),
    ("asset_graph_summary", asset_graph_summary, "Graph counts, risky deps, endpoints."),
    ("kb_search", kb_search, "Retrieve knowledge-base chunks with citations."),
    ("rag_preview", rag_preview, "Exact chunks retrieval would return, with size."),
    ("kb_ingest", kb_ingest, "Index a folder of documents."),
    ("kb_list", kb_list, "Indexed documents."),
    ("submit_job", submit_job, "Run a long command detached."),
    ("job_status", job_status, "State, exit code and log tail."),
    ("logs_tail", logs_tail, "Recent log lines from the shared log file."),
    ("pool_stats", pool_stats, "Free resource slots."),
]
