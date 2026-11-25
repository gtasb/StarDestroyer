"""Tabby adapter: recall layer. Java only.

Verified against tabby-sec/tabby v2.0.1 source, not documentation:

- It remembers analysed jars in rules/ignores.json and silently skips them later
  ("Total analyse 0 targets"), so a second run of the same jar yields an empty graph.
- The CLI takes no arguments; it reads ./config/settings.properties from the
  working directory (run.sh: `java -Xmx16g -jar target/tabby.jar`).
- The build stage writes into an H2 in-memory database, not Neo4j. CSV export is
  a first-class path (RelationshipsService.save*ToCsv), so the graph can be
  reconstructed without a server.
- Edge types are CALL, ALIAS, EXTEND, HAS, INTERFACES.
- ALIAS points from the declaring method (interface / superclass) to the override.
  Without it every interface call is a dead end: commons-collections'
  Transformer.transform never reaches InvokerTransformer.transform.

Ingest is serialised by the tabby_ingest pool: one Soot/JVM build at a time.
"""

import csv
import hashlib
import re
import shutil
import sys
import os
import pathlib

from .. import jobs

def jar() -> str:
    env = os.environ.get("TABBY_JAR")
    if env:
        return env
    here = pathlib.Path(__file__).resolve()
    for base in (here.parents[2], here.parents[3]):
        cand = base / ".work" / "tabby" / "dist" / "tabby.jar"
        if cand.exists():
            return str(cand)
    return ""

SETTINGS_TEMPLATE = """\
tabby.build.target                        = {target}
tabby.build.libraries                     = {libraries}
tabby.build.mode                          = {mode}
tabby.output.directory                    = ./output/dev
tabby.build.rules.directory               = {rules}
tabby.build.thread.size                   = max
tabby.build.useSettingJRE                 = false
tabby.build.isJRE9Module                  = false
tabby.build.javaHome                      = {java_home}
tabby.debug.details                       = false
tabby.build.isJDKProcess                  = false
tabby.build.withAllJDK                    = false
tabby.build.isJDKOnly                     = false
tabby.build.checkFatJar                   = true
tabby.build.removeNotPollutedCallSite     = false
tabby.build.interProcedural               = true
tabby.build.onDemandDrive                 = false
tabby.build.analysis.everything           = true
tabby.build.thread.timeout                = 2
tabby.build.method.timeout                = 5
tabby.build.method.maxDepth               = 500
tabby.build.object.maxTriggerTimes        = 300
tabby.build.with.cache.enable             = false
tabby.build.timeout.forceStop             = true
tabby.build.isNeedToProcessXml            = true
tabby.build.isNeedToCreateIgnoreList      = false
"""


def available() -> bool:
    return bool(jar()) and pathlib.Path(jar()).exists()


def prepare_workspace(workdir: str, target: str, libraries: str = "",
                      mode: str = "web", java_home: str | None = None,
                      rules_dir: str | None = None) -> pathlib.Path:
    d = pathlib.Path(workdir)
    (d / "config").mkdir(parents=True, exist_ok=True)
    (d / "output").mkdir(parents=True, exist_ok=True)
    rules = (rules_dir or os.environ.get("TABBY_RULES")
             or str(pathlib.Path(jar()).parent / "rules"))
    # Tabby appends the MD5 of every jar it has analysed to rules/ignores.json and
    # skips those jars from then on -- in this project and in every other one. Each
    # build gets its own copy of the rules, without that list.
    private = d / "rules"
    shutil.rmtree(private, ignore_errors=True)
    shutil.copytree(rules, private, ignore=shutil.ignore_patterns("ignores.json"))
    rules = str(private.resolve())
    # Java .properties treat backslash as an escape character; a Windows path
    # written raw loses its separators ("D:\a\b" -> "D:ab").
    def posix(p: str) -> str:
        return p.replace("\\", "/")

    (d / "config" / "settings.properties").write_text(
        SETTINGS_TEMPLATE.format(
            target=posix(str(pathlib.Path(target).resolve())),
            libraries=posix(libraries),
            mode=mode,
            rules=posix(rules),
            java_home=posix(java_home or os.environ.get("JAVA_HOME", "")),
        ),
        encoding="utf-8",
    )
    return d


MODES = ("gadget", "web")


def content_key(target: str) -> str:
    """Identity of what is being analysed: same name is not same code, and a
    copied jar keeps an old mtime."""
    p = pathlib.Path(target)
    h = hashlib.sha256()
    files = [p] if p.is_file() else sorted(f for f in p.rglob("*") if f.is_file())
    for f in files:
        if p.is_dir():
            h.update(f.relative_to(p).as_posix().encode() + b"\0")
        with f.open("rb") as fh:
            while block := fh.read(1 << 20):
                h.update(block)
        h.update(b"\0")
    return h.hexdigest()[:12]


def invalid_options(heap: str, mode: str) -> str | None:
    """Both values reach a process or its config file; only known shapes pass."""
    if not re.fullmatch(r"[1-9]\d{0,5}[mMgG]", str(heap)):
        return "heap 格式无效，应为数字加 m/g，如 4g"
    if mode not in MODES:
        return f"mode 无效，可选 {' / '.join(MODES)}"
    return None


def build_command(heap: str = "8g") -> list[str]:
    err = invalid_options(heap, MODES[0])
    if err:
        raise ValueError(err)
    return [shutil.which("java") or "java", f"-Xmx{heap}", "-jar", jar()]


def submit_build(workdir: str, heap: str = "8g") -> dict:
    if not available():
        return {"error": "TABBY_JAR 未设置或不存在"}
    return jobs.submit(build_command(heap), cwd=workdir, label="tabby-build")


def outputs(workdir: str) -> list[str]:
    out = pathlib.Path(workdir) / "output"
    if not out.exists():
        return []
    return sorted(str(p) for p in out.rglob("*.csv"))


CSV_NAMES = {
    "METHODS": "GRAPHDB_PUBLIC_METHODS.csv",
    "CLASSES": "GRAPHDB_PUBLIC_CLASSES.csv",
    "CALL": "GRAPHDB_PUBLIC_CALL.csv",
    "ALIAS": "GRAPHDB_PUBLIC_ALIAS.csv",
}
MAX_DEPTH = 12     # keep in step with templates/cypher/gadget-chain.cypher
MAX_PATHS = 20000  # rows pulled before per-pair dedup; hitting it is reported
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "templates" / "cypher"

GADGET_ENTRIES = ["readObject", "readResolve", "readExternal", "readObjectNoData"]


def _iter_rows(output_dir: str, key: str):
    """Stream rows: a 400k-row CSV becomes a list that never fits comfortably."""
    p = pathlib.Path(output_dir) / CSV_NAMES[key]
    if not p.exists():
        return
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with p.open(newline="", encoding="utf-8", errors="replace") as fh:
        for row in csv.DictReader(fh):
            yield row


def _rows(output_dir: str, key: str) -> list[dict]:
    p = pathlib.Path(output_dir) / CSV_NAMES[key]
    if not p.exists():
        return []
    # Large projects emit signature/annotation fields past the 128 KiB default.
    csv.field_size_limit(min(sys.maxsize, 2**31 - 1))
    with p.open(newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))


def load_graph(output_dir: str, db_path: str) -> dict:
    """Import Tabby's CSV export into a fresh embedded graph."""
    from .. import graph, logging, proc

    conn = graph.open_db(db_path)
    try:
        return {"conn": conn, **_load(conn, output_dir, graph, logging, proc)}
    except BaseException:
        graph.close(conn)  # an open handle would block deleting the half-loaded file
        raise


def _load(conn, output_dir, graph, logging, proc) -> dict:
    graph.ensure_node_table(conn, "Method", {
        "id": "STRING", "name": "STRING", "cls": "STRING", "sig": "STRING",
        "vul": "STRING", "is_sink": "STRING", "serial": "STRING", "is_endpoint": "STRING",
    })
    graph.ensure_node_table(conn, "Class", {
        "id": "STRING", "name": "STRING", "serial": "STRING", "super": "STRING",
    })
    graph.ensure_rel_table(conn, "CALL", "Method", "Method", {"line": "INT64"})
    graph.ensure_rel_table(conn, "ALIAS", "Method", "Method")

    ids: set[str] = set()

    def fresh(rows, seen):
        for i, row in enumerate(rows):
            if i % 20000 == 0:
                proc.check()
            if row[0] not in seen:
                seen.add(row[0])
                yield row

    def edges(key):
        seen: set[tuple] = set()
        for i, r in enumerate(_iter_rows(output_dir, key)):
            if i % 20000 == 0:
                proc.check()
            pair = (r["SOURCE"], r["TARGET"])
            # COPY fails on an edge whose endpoint is absent.
            if pair[0] == pair[1] or pair in seen or pair[0] not in ids or pair[1] not in ids:
                continue
            seen.add(pair)
            if key == "CALL":
                line = r.get("LINE_NUM") or ""
                yield (*pair, int(line) if line.isdigit() else 0)
            else:
                yield pair

    n_methods = graph.copy_rows(conn, "Method", fresh((
        (r["ID"], r.get("NAME", ""), r.get("CLASSNAME", ""), r.get("SIGNATURE", ""),
         r.get("VUL") or "", r.get("IS_SINK", ""), r.get("IS_SERIALIZABLE", ""),
         r.get("IS_ENDPOINT", "")) for r in _iter_rows(output_dir, "METHODS")), ids))
    n_classes = graph.copy_rows(conn, "Class", fresh((
        (r["ID"], r.get("NAME", ""), r.get("IS_SERIALIZABLE", ""), r.get("SUPER_CLASS", ""))
        for r in _iter_rows(output_dir, "CLASSES")), set()))
    n_calls = graph.copy_rows(conn, "CALL", edges("CALL"))
    n_alias = graph.copy_rows(conn, "ALIAS", edges("ALIAS"))
    logging.info("tabby", "graph loaded", methods=n_methods, classes=n_classes,
                 calls=n_calls, aliases=n_alias)
    return {"methods": n_methods, "classes": n_classes, "calls": n_calls, "aliases": n_alias}


def find_gadget_chains(conn, limit: int = 20, entries: list[str] | None = None,
                       mode: str = "gadget") -> dict:
    """{chains, total, truncated}. One shortest path per entry/sink method pair;
    `limit` applies after dedup, so duplicates never push a real chain out."""
    from .. import graph

    cypher = (TEMPLATES / f"{mode}-chain.cypher").read_text(encoding="utf-8")
    params = {"limit": MAX_PATHS}
    if mode == "gadget":
        params["entries"] = entries or GADGET_ENTRIES
    rows = graph.query(conn, cypher, params)
    out, seen = [], set()
    for r in rows:
        trace = graph.render_path(r)
        # One finding per entry/sink pair: overload edges produce the same
        # semantic chain several times at different depths.
        key = (r["entry_cls"], r["entry_name"], r["sink_cls"], r["sink_name"], r["vul"])
        if key in seen:
            continue
        seen.add(key)
        out.append({
            "entry": f"{r['entry_cls']}.{r['entry_name']}",
            "sink": f"{r['sink_cls']}.{r['sink_name']}",
            "vul": r["vul"],
            "depth": r["depth"],
            "trace": trace,
        })
    # JDK-internal chains exist in every jar and are short; the limit must cut
    # those, never a chain that starts in the audited code.
    order = {"project": 0, "mixed": 1, "library": 2}
    out.sort(key=lambda c: (order[chain_scope(c)], c["depth"]))
    return {"chains": out[:limit], "total": len(out),
            "truncated": len(out) > limit or len(rows) >= MAX_PATHS}


# Anything under these prefixes is not the audited project's own code.
LIBRARY_PREFIXES = ("java.", "javax.", "jdk.", "sun.", "com.sun.", "kotlin.",
                    "org.springframework.", "org.apache.", "com.fasterxml.")


def chain_scope(chain: dict) -> str:
    """project | mixed | library -- decides needs_review vs needs_dynamic.

    A sink in the JDK is normal; a chain whose *middle* leaves the project for
    a third-party library is not statically provable.
    """
    classes = [s["text"].rsplit(".", 1)[0] for s in chain["trace"] if s.get("text")]
    if not classes:
        return "library"
    if any(c.startswith(LIBRARY_PREFIXES) for c in classes[:-1]):
        return "mixed"
    if classes[0].startswith(LIBRARY_PREFIXES):
        return "library"
    return "project"


def to_records(chains: list[dict], key: str = "", mode: str = "gadget") -> list[dict]:
    from .. import records, verdict

    out = []
    for ch in chains:
        scope = chain_scope(ch)
        if scope == "project":
            v = {"status": verdict.NEEDS_REVIEW,
                 "reason": "图有路径但污点未验证，可能参数不可控",
                 "missing": "参数可控性证明", "source": "tabby"}
        else:
            v = {"status": verdict.NEEDS_DYNAMIC,
                 "reason": "链经过库边界，静态不可验" if scope == "mixed" else "入口在库内，非本项目代码",
                 "missing": "运行时验证", "source": "tabby"}
        finding = {
            "rule_id": f"tabby-{mode}-{ch['vul'].lower()}",
            "file": ch["entry"].rsplit(".", 1)[0],
            "line": None,
            "message": f"{ch['entry']} → {ch['sink']} ({ch['vul']})",
            "trace": [{"kind": "entrypoint" if i == 0 else "sink" if i == len(ch["trace"]) - 1 else "propagation",
                       "file": s.get("file", ""), "line": s.get("line"),
                       "text": s.get("text", "")} for i, s in enumerate(ch["trace"])],
        }
        rec = records.make(finding, v, "")
        # No source file to pin, but the analysed bytes are: key is their hash.
        rec["suppress_key"] = f"tabby-{key}-{mode}-{rec['fingerprint']}" if key else ""
        # A chain inside the JDK exists in every jar; one that starts here is ours.
        rec["severity"] = {"project": "high", "mixed": "medium"}.get(scope, "low")
        out.append(rec)
    return out
