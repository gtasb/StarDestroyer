"""Cascade orchestration.

Phase 1 runs Opengrep only; Tabby slots in beside it at step 3. Every artifact
is derived from one records list, so the report can never drift from the JSON.
"""

import hashlib
import json
import os
import pathlib
import tempfile
import time
import uuid

from . import (checkpoint, decisions, ledger, logging, proc, profile, records, report, review, rulebase, sarif, sfc, store,
               verdict)
from .engines import opengrep

RULES = {
    "java": "java-taint.yaml",
    "python": "python-taint.yaml",
    "go": "go-taint.yaml",
    "js": "js-taint.yaml",
}
TEMPLATES = pathlib.Path(__file__).resolve().parent / "templates" / "opengrep"
SCANS_DIR = pathlib.Path(__file__).resolve().parents[1] / ".work" / "scans"


def new_scan_dir(prefix: str = "") -> pathlib.Path:
    """Unique per run: two scans in the same second must not share a directory."""
    d = SCANS_DIR / f"{prefix}{time.strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    d.mkdir(parents=True)
    return d


def rules_for(lang: str) -> str:
    try:
        return str(TEMPLATES / RULES[lang])
    except KeyError:
        raise ValueError(f"unsupported language: {lang} (have {sorted(RULES)})")


def detect_languages(src: str) -> dict[str, int]:
    """Supported languages present under src, most files first."""
    if pathlib.Path(src).is_file():
        counts = {lg: len(ledger.source_files(src, lg)) for lg in RULES}
    else:
        counts = profile.profile(src).get("file_counts", {})
    found = {lg: n for lg, n in counts.items() if lg in RULES and n}
    return dict(sorted(found.items(), key=lambda kv: -kv[1]))


BIG, RULES_PER_PART = 1500, 4  # files in one language; rules in one part of it


def _parts(langs: list[str], src: str, extra: list[str], tmp: pathlib.Path) -> list[tuple[str, list[str]]]:
    """(name, rule files). A language is one part -- flows do not cross languages -- and a
    large one several, a few rules each: that is what can be lost when a scan is stopped."""
    out = []
    for lg in langs:
        mine = [r for r in rulebase.RULES if r["lang"] == lg]
        if len(ledger.source_files(src, lg)) <= BIG or len(mine) <= RULES_PER_PART:
            out.append((lg, [rules_for(lg)]))
            continue
        for i in range(0, len(mine), RULES_PER_PART):
            f = tmp / f"{lg}-{i // RULES_PER_PART}.yaml"
            f.write_text(rulebase.document(mine[i:i + RULES_PER_PART]), encoding="utf-8")
            out.append((f"{lg} {i // RULES_PER_PART + 1}/{-(-len(mine) // RULES_PER_PART)}", [str(f)]))
    if extra:
        out.append(("项目规则", extra))
    return out


def _engine(src: str, langs: list[str], extra: list[str]) -> dict:
    """The engine over every part, taking finished parts from the checkpoint."""
    comps = [f for f in ledger.source_files(src, "js") if f.suffix.lower() in sfc.EXTENSIONS] if "js" in langs else []
    total: dict = {}
    with tempfile.TemporaryDirectory(prefix="sd-parts-", ignore_cleanup_errors=True) as d, sfc.Shadow(comps) as shadow:
        parts = _parts(langs, src, extra, pathlib.Path(d))
        text = [pathlib.Path(f).read_bytes() for _, fs in parts for f in fs]
        both = sum(len(ledger.source_files(src, lg)) for lg in langs) <= BIG
        saved = checkpoint.Checkpoint(src, "sast", checkpoint.fingerprint(src), langs, hashlib.sha256(b"".join(text)).hexdigest(), opengrep.binary(), os.environ.get("AUDIT_INTERFILE_DEPTH") or opengrep.DEPTH, both)
        saved.total = len(parts)
        for i, (name, rules) in enumerate(parts, 1):
            got = saved.get(name)
            if got is None:
                proc.stage(f"污点扫描 {i}/{len(parts)}（{name}）" + (f"，接着上次的 {saved.resumed} 段" if saved.resumed else ""))
                got = _deep(both, lambda at: opengrep.run_scan(src, rules=rules[0], also=[shadow.dir] if shadow.dir else [], extra_rules=rules[1:],
                                                               exclude=["/" + x for x in ledger.excluded(src)] if "js" in langs else [], at=at))
                got = shadow.restore(got)
                total.setdefault("raw", {})[name] = got.pop("raw", None)
                if got.get("ok"):
                    saved.put(name, {k: got.get(k) for k in _KEEP})
            total = _merge(total, got)
        total["resumed"] = saved.resumed
        if total["ok"]:
            saved.done()
    return total


SHALLOW = "3"


def _deep(both: bool, run) -> dict:
    """A deeper search is not a superset: on a large call graph it drops a few of the flows
    a shallow one finds. Where a second run is cheap, the result is the union."""
    got = run(None)
    if not both or not got.get("ok") or int(os.environ.get("AUDIT_INTERFILE_DEPTH") or opengrep.DEPTH) <= int(SHALLOW):
        return got
    more = run(SHALLOW)
    if not more.get("ok"):
        return {**got, "error_items": [*(got.get("error_items") or []), {"path": "", "rule_id": "", "level": "warn", "message": f"浅层补扫没有完成：{more.get('error')}"[:300]}]}
    have = {(f["rule_id"], f["file"], f["line"]) for f in got["findings"]}
    extra = [f for f in more["findings"] if (f["rule_id"], f["file"], f["line"]) not in have]
    if extra:
        got = {**got, "findings": got["findings"] + extra, "total": len(got["findings"]) + len(extra)}
    return got


_KEEP = ("ok", "error", "findings", "total", "errors", "error_items", "scanned", "unsupported_flags", "interfile_languages", "stderr_tail")


def _merge(a: dict, b: dict) -> dict:
    if "ok" not in a:
        return {**{k: b.get(k) for k in _KEEP}, "raw": a.get("raw") or {}}
    uniq = lambda k: list(dict.fromkeys((a.get(k) or []) + (b.get(k) or [])))
    return {**a, "ok": a["ok"] and b["ok"], "error": a["error"] or b.get("error"), "findings": a["findings"] + b["findings"], "total": a["total"] + b["total"],
            "errors": uniq("errors"), "error_items": a["error_items"] + (b.get("error_items") or []), "scanned": uniq("scanned"), "unsupported_flags": uniq("unsupported_flags"),
            "interfile_languages": uniq("interfile_languages"), "stderr_tail": (a.get("stderr_tail") or []) + (b.get("stderr_tail") or [])}


def scan(src: str, lang: str = "auto", verify: bool = False,
         extra_rules: list[str] | None = None) -> dict:
    if not pathlib.Path(src).exists():
        return {"ok": False, "error": f"路径不存在: {src}"}
    lang = lang or "auto"
    if lang != "auto" and lang not in RULES:
        return {"ok": False, "error": f"暂不支持语言: {lang}，可选 auto / {sorted(RULES)}"}

    present = detect_languages(src)
    # auto covers every supported language: one engine run dispatches rules by file.
    langs = list(present) if lang == "auto" else [lang]
    # Zero source files is "nothing was audited", not "nothing was found".
    if not any(ledger.source_files(src, lg) for lg in langs):
        have = "、".join(f"{k} {n} 个" for k, n in present.items()) or "无"
        what = "受支持语言" if lang == "auto" else lang
        return {"ok": False, "complete": False, "languages": present,
                "error": f"没有可扫描的 {what} 源文件（检测到：{have}）"}
    lang = "+".join(langs)

    started = time.time()
    logging.info("pipeline", "scan start", path=src, lang=lang,
                 project_rules=bool(extra_rules))
    res = _engine(src, langs, extra_rules or [])
    # Partial output from a failed engine is still worth reporting; no output is
    # a failure and must not be rendered as a clean result.
    if not res.get("ok") and not res["findings"]:
        return {"ok": False, "complete": False, "engine": "opengrep", "language": lang,
                "error": res.get("error") or "opengrep 执行失败",
                "engine_errors": res.get("errors", []),
                "stderr_tail": res.get("stderr_tail", [])}

    recs: list[dict] = []
    for f in res["findings"]:
        v = verdict.judge(f, None, src)
        if f["rule_id"].startswith("ai-"):  # a rule no person has read confirms nothing by itself
            v = {**v, "status": verdict.NEEDS_REVIEW, "reason": "AI 写的规则命中，等 agent 追链和复核"}
        recs.append(records.make(f, v, src))
    recs = _merge_in_method(_merge_duplicates(recs), src)

    prior_rejected = decisions.apply(recs)
    reportable = [r for r in recs if verdict.is_reportable({"status": r["status"]})]

    verification = None
    if verify:
        verification = review.run(recs, src)
        reportable = [r for r in recs if verdict.is_reportable({"status": r["status"]})]
    ledger_doc = ledger.build(src, langs, res["findings"], res.get("scanned", []),
                              res.get("error_items"))
    gaps = _gaps(res, ledger_doc)
    if verification and verification["skipped"]:
        gaps.append(f"二次复核有上限，{verification['skipped']} 条未复核")
    if verification and verification["unavailable"]:
        gaps.append(f"{verification['unavailable']} 条复核没有完成：{verification['error'][:120]}")

    logging.info("pipeline", "scan done", path=src, raw=res["total"],
                 reportable=len(reportable), elapsed=round(time.time() - started, 2),
                 engine_errors=len(res.get("errors", [])))
    scan_dir = new_scan_dir()
    (scan_dir / "findings.json").write_text(
        json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")
    (scan_dir / "engine.json").write_text(
        json.dumps(res.get("raw"), ensure_ascii=False), encoding="utf-8")
    (scan_dir / "ledger.json").write_text(
        json.dumps(ledger_doc, ensure_ascii=False, indent=2), encoding="utf-8")

    with store.update(SCANS_DIR / "latest.json", {}) as idx:
        idx[str(pathlib.Path(src).resolve())] = str(scan_dir / "findings.json")

    out = report.write(reportable, str(scan_dir), title=f"audit-{lang}", gaps=gaps)
    out["sarif"] = sarif.write_sarif(reportable, str(scan_dir / "findings.sarif"), gaps)
    out["findings_json"] = str(scan_dir / "findings.json")
    out["ledger_json"] = str(scan_dir / "ledger.json")

    return {
        "ok": True,
        "complete": not gaps,
        "incomplete_reasons": gaps,
        "engine": "opengrep",
        "language": lang,
        "languages": present,
        "unsupported_flags": res["unsupported_flags"],
        "interfile_languages": res.get("interfile_languages", []),
        "engine_errors": res.get("errors", []),
        "elapsed_s": round(time.time() - started, 2),
        "raw_hits": res["total"],
        "reportable": len(reportable),
        "status_counts": _counts(recs),
        "severity_counts": _severities(reportable),
        "root": str(pathlib.Path(src).resolve()),
        "top": reportable[:report.TOP_N],
        "coverage": {k: ledger_doc[k] for k in
                     ("files", "units_total", "units_covered", "units_candidate",
                      "units_blocked", "units_skipped")} | {"excluded": len(ledger_doc["files_excluded"])},
        "verification": verification,
        "previously_rejected": len(prior_rejected),
        "artifacts": out,
    }


def last_findings(src: str) -> list[dict] | None:
    """Records of the most recent scan of exactly this path."""
    name = store.read(SCANS_DIR / "latest.json", {}).get(str(pathlib.Path(src).resolve()))
    return store.read(pathlib.Path(name), None) if name else None


def _gaps(res: dict, ledger_doc: dict) -> list[str]:
    """Why "nothing reported" would not mean "nothing there". Empty = complete."""
    out = []
    if not res.get("ok"):
        out.append(res.get("error") or "引擎执行失败，结果不完整")
    skipped, failed = ledger_doc["files_unscanned"], ledger_doc["files_failed"]
    if skipped:
        out.append(f"{len(skipped)} 个源文件引擎未扫描，如 {'、'.join(skipped[:3])}")
    if failed:
        out.append(f"{len(failed)} 个源文件解析失败或超时，如 {'、'.join(list(failed)[:3])}")
    depth = set()
    for e in res.get("error_items", []):
        if "interfile search stopped" in e["message"]:
            depth.add(e.get("rule_id") or e["message"][:90])
        elif not e["path"]:
            out.append(f"引擎告警：{e['message'][:120]}")
    if depth:
        out.append(f"跨文件分析到达深度上限（{len(depth)} 条规则），更深的链要靠 agent 续追")
    return out


def _merge_duplicates(recs: list[dict]) -> list[dict]:
    """One flow reported by a built-in and a generated rule is one finding. The
    flow must match end to end; the other rule ids are kept on the record."""
    out: dict[tuple, dict] = {}
    for r in recs:
        ends = tuple((s["file"], s["line"], s["text"]) for s in (r["trace"][:1] + r["trace"][-1:]))
        key = (r["file"], r["line"], ledger.class_of(r["rule_id"]), ends)
        if ledger.class_of(r["rule_id"]) == "other" or not ends:
            key = (id(r),)
        kept = out.setdefault(key, r)
        if kept is not r:
            kept.setdefault("also", []).append(r["rule_id"])
    return list(out.values())


def _merge_in_method(recs: list[dict], src: str) -> list[dict]:
    """A pattern an agent wrote often matches several lines of one method: one place to look
    at, not several findings. The other lines stay on the record."""
    if not any(r["rule_id"].startswith("ai-") for r in recs):
        return recs
    from . import codeintel
    files = codeintel.index(src).files
    out, kept = [], {}
    for r in recs:
        f = files.get(r["file"]) if r["rule_id"].startswith("ai-") else None
        m = f.method_at(r["line"]) if f else None
        if not m:
            out.append(r)
            continue
        start = next((s for s in r["trace"] if s["kind"] == "source"), r["trace"][0] if r["trace"] else {})
        key = (r["rule_id"], r["file"], m["owner"], m["name"], m.get("line") or m.get("start"), start.get("file") if start.get("file") != r["file"] else "")
        if key in kept:
            kept[key].setdefault("lines", []).append(r["line"])
        else:
            kept[key] = r
            out.append(r)
    return out


def _severities(recs: list[dict]) -> dict:
    out: dict[str, int] = {}
    for r in recs:
        sev = r.get("severity") or "unknown"
        out[sev] = out.get(sev, 0) + 1
    return out


TABBY_WORK = SCANS_DIR.parent / "tabby"


def _counts(records: list[dict]) -> dict:
    out = {"confirmed": 0, "needs_review": 0, "needs_dynamic": 0, "rejected": 0}
    for r in records:
        st = r.get("status")
        if st in out:
            out[st] += 1
    return out


def refuted(rec: dict) -> bool:
    """Judged not to hold, and nobody has decided otherwise. Kept for a person, not counted as open risk."""
    return (rec.get("review") or {}).get("verdict") == "refute" and not rec.get("decision") and rec["status"] == verdict.NEEDS_REVIEW


def standing(recs: list[dict]) -> dict:
    live = [r for r in recs if r["status"] != "rejected" and not refuted(r)]
    return {"severity": _severities(live), "refuted": sum(map(refuted, recs)), "causes": len({records.cause(r) for r in live})}


def tabby_audit(target_jar: str, workdir: str | None = None, mode: str = "gadget",
                heap: str = "4g", limit: int = 30, wait_s: int = 60) -> dict:
    """Recall pass over compiled Java. Build is a job; nothing blocks > wait_s."""
    from .engines import tabby

    bad = tabby.invalid_options(heap, mode)
    if bad:
        return {"ok": False, "error": bad}
    if not str(target_jar).strip():
        return {"ok": False, "error": "请指定 jar 路径"}
    if not tabby.available():
        return {"ok": False, "error": "Tabby 未安装：设置 TABBY_JAR 或放到 .work/tabby/dist/tabby.jar"}
    jar = pathlib.Path(target_jar)
    if not jar.exists():
        return {"ok": False, "error": f"目标不存在: {target_jar}"}

    key = tabby.content_key(target_jar)
    work = pathlib.Path(workdir or TABBY_WORK / f"{jar.stem[:40]}-{key}-{mode}")
    logging.info("tabby", "audit start", jar=jar.name, mode=mode, heap=heap, key=key)

    proc.stage("构建调用图")
    built = _tabby_build(work, jar, mode, heap, wait_s)
    if built:
        return built

    proc.stage("载入调用图并查链")
    from . import graph
    # Held across load and query: the embedded store allows one process at a time.
    with store.lock(work / "graph.json"):
        marker, db_path = work / "graph.json", work / "cpg.db"
        g = store.read(marker, None) if db_path.exists() else None
        if g:
            conn = graph.open_db(str(db_path))
        else:
            # A killed load leaves a WAL that makes the next open fail; drop all.
            for suffix in ("", ".wal", ".lock"):
                pathlib.Path(str(db_path) + suffix).unlink(missing_ok=True)
            loaded = tabby.load_graph(str(work / "output" / "dev"), str(db_path))
            conn = loaded.pop("conn")
            g = loaded
            if g["methods"] and g["calls"]:
                store.write(marker, g)
        try:
            # An empty graph is a broken build, not a jar without gadgets.
            if not g["methods"] or not g["calls"]:
                (work / "build.json").unlink(missing_ok=True)
                return {"ok": False, "complete": False,
                        "error": f"调用图为空（方法 {g['methods']}、调用边 {g['calls']}），"
                                 "Tabby 产物缺失或不完整"}
            found = tabby.find_gadget_chains(conn, limit=limit, mode=mode)
        finally:
            graph.close(conn)
    chains = found["chains"]
    gaps = []
    if not g["aliases"]:
        gaps.append("图中没有 ALIAS 边，经接口/父类分派的调用链查不到")
    if found["truncated"]:
        gaps.append(f"共找到 {found['total']} 条链，只返回 {len(chains)} 条；调大 limit 可看全部")
    recs = tabby.to_records(chains, key=key, mode=mode)
    decisions.apply(recs)
    reportable = [r for r in recs if verdict.is_reportable({"status": r["status"]})]

    scan_dir = new_scan_dir("tabby-")
    (scan_dir / "findings.json").write_text(
        json.dumps(recs, ensure_ascii=False, indent=2), encoding="utf-8")
    out = report.write(reportable, str(scan_dir), title=f"tabby-{jar.stem}", gaps=gaps)
    out["sarif"] = sarif.write_sarif(reportable, str(scan_dir / "findings.sarif"), gaps)
    out["findings_json"] = str(scan_dir / "findings.json")

    return {
        "ok": True,
        "complete": not gaps,
        "incomplete_reasons": gaps,
        "engine": "tabby",
        "mode": mode,
        "max_depth": tabby.MAX_DEPTH,
        "target": str(jar.resolve()),
        "workdir": str(work),
        "graph": g,
        "chains": len(chains),
        "chains_total": found["total"],
        "reportable": len(reportable),
        "status_counts": _counts(recs),
        "severity_counts": _severities(reportable),
        "top": reportable[:report.TOP_N],
        "artifacts": out,
    }


def _tabby_build(work: pathlib.Path, jar: pathlib.Path, mode: str, heap: str,
                 wait_s: float) -> dict | None:
    """None once a finished build is on disk, otherwise the answer to return.

    build.json is the only proof of completion: CSV files on disk may belong to a
    build that is still writing them or that died halfway.
    """
    import shutil

    from . import jobs
    from .engines import tabby
    state, out_dir = work / "build.json", work / "output" / "dev"

    def has_csv() -> bool:
        return all((out_dir / tabby.CSV_NAMES[k]).exists() for k in ("METHODS", "CALL"))

    with store.lock(work / "build"):
        b = store.read(state, {})
        if b.get("state") == "done" and has_csv():
            logging.info("tabby", "reusing build", workdir=str(work))
            return None
        if b.get("state") == "running":
            jid = b["job_id"]  # ours or another caller's: never start a second JVM here
        else:
            shutil.rmtree(work / "output", ignore_errors=True)
            (work / "graph.json").unlink(missing_ok=True)
            tabby.prepare_workspace(str(work), target=str(jar.resolve()), mode=mode)
            jid = tabby.submit_build(str(work), heap=heap)["job_id"]
            store.write(state, {"state": "running", "job_id": jid, "target": str(jar.resolve()),
                                "mode": mode})
    try:
        st = jobs.wait(jid, timeout_s=wait_s, stop=proc.check)
    except proc.Cancelled:
        jobs.cancel(jid)
        store.write(state, {"state": "cancelled", "job_id": jid})
        raise
    if st.get("state") == "running":
        logging.warn("tabby", "build still running", job=jid, wait_s=wait_s)
        return {"ok": True, "pending": jid,
                "hint": "建图超过等待窗口。再次调用本工具会接上同一个任务",
                "poll": f"job_status('{jid}')"}
    ok = st.get("exit") == "0" and has_csv()
    store.write(state, {"state": "done" if ok else "failed", "job_id": jid})
    if ok:
        return None
    why = "未产出 CSV" if st.get("exit") == "0" else f"exit={st.get('exit')}，状态 {st.get('state')}"
    return {"ok": False, "complete": False, "tail": st.get("tail"),
            "error": f"Tabby 构建失败（{why}）"}
