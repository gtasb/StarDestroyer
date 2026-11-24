"""Tool registry.

The MCP adapter and the web console both register from here; neither holds
logic of its own. Everything returns JSON-able dicts.
"""

import asyncio
import json
import pathlib

from . import asset_graph, intel, jobs, kb, nvd, pipeline, pools, profile, rulegen, sca
from . import logging
from . import sca_triage


def _prepare_rules(src: str) -> dict:
    """Profile the project, propose rules from its dependencies, prove them."""
    prof = profile.profile(src)
    if not prof.get("ok"):
        return {"ok": False, "error": prof.get("error")}
    props = rulegen.propose(prof)
    if not props:
        return {"ok": True, "profile": prof, "rules": [], "dir": None,
                "note": "未从依赖中识别出可生成规则的框架"}
    written = rulegen.write(props)
    check = rulegen.validate(written["dir"])
    return {"ok": check["ok"], "profile": prof, "rules": props,
            "dir": written["dir"] if check["ok"] else None,
            "validation": check}


def auto_scan(path: str, lang: str = "java", ai: bool = False,
              verify: bool = False) -> dict:
    """Profile -> generate -> validate -> scan, one call."""
    prep = _prepare_rules(path)
    if not prep.get("ok"):
        return {"ok": False, "error": prep.get("error"), "detail": prep}
    res = pipeline.scan(path, lang, ai, verify, extra_rules=prep.get("dir"))
    if res.get("ok"):
        res["generated_rules"] = [{"id": p["id"], "reason": p["reason"]}
                                  for p in prep["rules"]]
        res["rules_applied"] = bool(prep.get("dir"))
        res["profile"] = {"language": prep["profile"].get("language"),
                          "frameworks": prep["profile"].get("frameworks", []),
                          "dependencies": prep["profile"].get("dependencies", [])[:8]}
    return res


async def audit_scan(path: str, lang: str = "java", ai: bool = False,
                     verify: bool = False, auto: bool = True) -> dict:
    """Taint scan. auto=True lets the agent write rules for this project first."""
    async with pools.acquire("opengrep"):
        if auto:
            return await asyncio.to_thread(auto_scan, path, lang, ai, verify)
        return await asyncio.to_thread(pipeline.scan, path, lang, ai, verify)


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
    """Dependencies (OpenSCA tree, transitive included) mapped to NVD CVEs."""
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
                    max_lookups: int = 12) -> dict:
    """Deterministic gate over dependency CVEs, plus the questions an agent must answer.

    The gate keeps a CVE when CVSS >= cvss_min OR EPSS percentile >= epss_pct_min,
    and never drops one for "unused" when there was no source to check. What is
    left is handed over as `candidates` with explicit read/grep steps: deciding
    reachability needs a reader with tools, not a blind model call.
    """
    comps = sca.enrich(path, max_lookups=max_lookups)
    t = sca_triage.triage(comps, app_root=path, cvss_min=cvss_min,
                          epss_pct_min=epss_pct_min)
    if not t.get("ok"):
        return t
    t = sca_triage.apply_verdicts(t, sca_triage.load_verdicts(path))
    t["sinks"] = sca_triage.sink_report(t, path)
    t["candidates"] = sca_triage.candidates(t, path)
    t["sca"] = {"source": comps.get("source"), "lookups": comps.get("lookups"),
                "skipped": comps.get("skipped")}
    return t


def sca_record_verdicts(path: str, verdicts: list[dict]) -> dict:
    """Persist an agent's keep/ignore decisions; ignore requires file:line evidence."""
    return sca_triage.record_verdicts(path, verdicts)


def asset_graph_build(path: str, lookup_cves: bool = True, with_scan: bool = True) -> dict:
    """Build the asset graph. with_scan folds the audit findings into it."""
    findings = None
    if with_scan:
        res = auto_scan(path)
        if res.get("ok") and res.get("artifacts", {}).get("findings_json"):
            try:
                findings = json.loads(pathlib.Path(res["artifacts"]["findings_json"])
                                      .read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                findings = None
    return asset_graph.build(path, findings=findings, lookup_cves=lookup_cves)


def asset_graph_summary(db_path: str) -> dict:
    """Counts, risky dependencies and exposed endpoints."""
    return asset_graph.summary(db_path)


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
    ("audit_jar", audit_jar, "Tabby recall pass over a compiled jar."),
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
