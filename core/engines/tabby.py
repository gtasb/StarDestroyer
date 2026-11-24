"""Tabby adapter: recall layer. Java only.

Verified against tabby-sec/tabby v2.0.1 source, not documentation:

- The CLI takes no arguments; it reads ./config/settings.properties from the
  working directory (run.sh: `java -Xmx16g -jar target/tabby.jar`).
- The build stage writes into an H2 in-memory database, not Neo4j. CSV export is
  a first-class path (RelationshipsService.save*ToCsv), so the graph can be
  reconstructed without a server.
- Edge types are CALL, ALIAS, EXTEND, HAS, INTERFACES.

Ingest is serialised by the tabby_ingest pool: one Soot/JVM build at a time.
"""

import csv
import os
import pathlib

from .. import jobs

JAR = os.environ.get("TABBY_JAR") or ""
if not JAR:
    _here = pathlib.Path(__file__).resolve()
    for _base in (_here.parents[2], _here.parents[3]):
        _cand = _base / ".work" / "tabby" / "dist" / "tabby.jar"
        if _cand.exists():
            JAR = str(_cand)
            break

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
"""


def available() -> bool:
    return bool(JAR) and pathlib.Path(JAR).exists()


def prepare_workspace(workdir: str, target: str, libraries: str = "",
                      mode: str = "web", java_home: str | None = None,
                      rules_dir: str | None = None) -> pathlib.Path:
    d = pathlib.Path(workdir)
    (d / "config").mkdir(parents=True, exist_ok=True)
    (d / "output").mkdir(parents=True, exist_ok=True)
    rules = (rules_dir or os.environ.get("TABBY_RULES")
             or str(pathlib.Path(JAR).parent / "rules"))
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


def build_command(heap: str = "8g") -> str:
    return f'java -Xmx{heap} -jar "{JAR}"'


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
}
TEMPLATES = pathlib.Path(__file__).resolve().parents[1] / "templates" / "cypher"

GADGET_ENTRIES = ["readObject", "readResolve", "readExternal", "readObjectNoData"]


def _rows(output_dir: str, key: str) -> list[dict]:
    p = pathlib.Path(output_dir) / CSV_NAMES[key]
    if not p.exists():
        return []
    with p.open(newline="", encoding="utf-8", errors="replace") as fh:
        return list(csv.DictReader(fh))


def load_graph(output_dir: str, db_path: str) -> dict:
    """Import Tabby's CSV export into the embedded graph."""
    from .. import graph

    conn = graph.open_db(db_path)
    graph.ensure_node_table(conn, "Method", {
        "id": "STRING", "name": "STRING", "cls": "STRING", "sig": "STRING",
        "vul": "STRING", "is_sink": "STRING", "serial": "STRING",
    })
    graph.ensure_node_table(conn, "Class", {
        "id": "STRING", "name": "STRING", "serial": "STRING", "super": "STRING",
    })
    graph.ensure_rel_table(conn, "CALL", "Method", "Method", {"line": "INT64"})

    methods = [{
        "id": r["ID"], "name": r.get("NAME", ""), "cls": r.get("CLASSNAME", ""),
        "sig": r.get("SIGNATURE", ""), "vul": r.get("VUL", "") or "",
        "is_sink": r.get("IS_SINK", ""), "serial": r.get("IS_SERIALIZABLE", ""),
    } for r in _rows(output_dir, "METHODS")]
    classes = [{
        "id": r["ID"], "name": r.get("NAME", ""),
        "serial": r.get("IS_SERIALIZABLE", ""), "super": r.get("SUPER_CLASS", ""),
    } for r in _rows(output_dir, "CLASSES")]
    calls = [{
        "src": r["SOURCE"], "dst": r["TARGET"],
        "line": int(r["LINE_NUM"]) if r.get("LINE_NUM", "").isdigit() else 0,
    } for r in _rows(output_dir, "CALL") if r["SOURCE"] != r["TARGET"]]

    n_methods = graph.upsert_nodes_batch(conn, "Method", methods,
                                         ["name", "cls", "sig", "vul", "is_sink", "serial"])
    n_classes = graph.upsert_nodes_batch(conn, "Class", classes, ["name", "serial", "super"])
    n_calls = graph.insert_edges_batch(conn, "CALL", calls, "Method", "Method", props=["line"])
    return {"conn": conn, "methods": n_methods, "classes": n_classes, "calls": n_calls}


def find_gadget_chains(conn, limit: int = 20, entries: list[str] | None = None) -> list[dict]:
    from .. import graph

    cypher = (TEMPLATES / "gadget-chain.cypher").read_text(encoding="utf-8")
    rows = graph.query(conn, cypher, {"entries": entries or GADGET_ENTRIES, "limit": limit})
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
    return out


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


def to_records(chains: list[dict]) -> list[dict]:
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
            "rule_id": f"tabby-gadget-{ch['vul'].lower()}",
            "file": ch["entry"].rsplit(".", 1)[0],
            "line": None,
            "message": f"{ch['entry']} → {ch['sink']} ({ch['vul']})",
            "trace": [{"kind": "entrypoint" if i == 0 else "propagation",
                       "file": s.get("file", ""), "line": s.get("line"),
                       "text": s.get("text", "")} for i, s in enumerate(ch["trace"])],
        }
        out.append(records.make(finding, v, ""))
    return out
