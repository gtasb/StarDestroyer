"""Application asset graph.

Ontology and fact-status semantics come from the user's Burp-AI-Analyzer
project (src/com/ai/analyzer/graph/GraphTypes.java): every node carries a
FactStatus and a confidence, and a fact never silently downgrades.

Extensions for white-box work: DEPENDENCY and NDAY nodes, so supply-chain risk
is reachable from the same App root as the endpoints.
"""

import hashlib
import pathlib
import time

from . import endpoints, graph, proc, profile, sca
from .fact_status import DEFAULT_CONFIDENCE, promote

NO_CVE = "本次未查询 CVE（lookup_cves=false）"
DB_DIR = pathlib.Path(__file__).resolve().parents[1] / ".work" / "asset-graph"

_BASE = {"status": "STRING", "confidence": "DOUBLE"}

NODES = {
    "App": {"id": "STRING", "name": "STRING", "origin": "STRING", "kind": "STRING", **_BASE},
    "Technology": {"id": "STRING", "name": "STRING", "category": "STRING", **_BASE},
    "Version": {"id": "STRING", "name": "STRING", "tech_id": "STRING", **_BASE},
    "Dependency": {"id": "STRING", "name": "STRING", "version": "STRING",
                   "ecosystem": "STRING", "direct": "STRING", **_BASE},
    "NDay": {"id": "STRING", "name": "STRING", "score": "DOUBLE", "summary": "STRING", **_BASE},
    "Endpoint": {"id": "STRING", "name": "STRING", "method": "STRING", "path": "STRING",
                 "file": "STRING", "line": "INT64", **_BASE},
    "Feature": {"id": "STRING", "name": "STRING", **_BASE},
    "VulnClass": {"id": "STRING", "name": "STRING", "category": "STRING", **_BASE},
    "Finding": {"id": "STRING", "name": "STRING", "status_finding": "STRING",
                "rule_id": "STRING", "file": "STRING", "line": "INT64", **_BASE},
    "Evidence": {"id": "STRING", "name": "STRING", "kind": "STRING",
                 "source": "STRING", "summary": "STRING", **_BASE},
}

EDGES = [
    ("USES_TECHNOLOGY", "App", "Technology", []),
    ("HAS_VERSION", "Technology", "Version", []),
    ("DEPENDS_ON", "App", "Dependency", []),
    ("AFFECTED_BY", "Dependency", "NDay", ["matched"]),
    ("HAS_INTERFACE", "App", "Endpoint", []),
    ("EXPOSES", "Endpoint", "Feature", []),
    ("COVERS", "Finding", "Endpoint", []),
    ("SUGGESTS_NDAY", "NDay", "VulnClass", []),
    ("SUGGESTS_FINDING", "Finding", "VulnClass", []),
    ("INDICATES", "Evidence", "Technology", []),
    ("EVIDENCES_DEP", "Evidence", "Dependency", []),
    ("EVIDENCES_NDAY", "Evidence", "NDay", []),
    ("EVIDENCES_ENDPOINT", "Evidence", "Endpoint", []),
]

VULN_KEYWORDS = [
    ("deserializ", "反序列化"), ("serializ", "反序列化"),
    ("sql injection", "SQL 注入"),
    ("command injection", "命令注入"), ("os command", "命令注入"),
    ("execute arbitrary", "命令注入"),
    ("ssrf", "SSRF"), ("cross-site scripting", "XSS"), ("xss", "XSS"),
    ("path traversal", "路径穿越"), ("directory traversal", "路径穿越"),
    ("xml external entity", "XXE"), ("xxe", "XXE"),
    ("remote code execution", "代码执行"), ("code execution", "代码执行"),
    ("authentication bypass", "认证绕过"), ("authorization", "越权"),
]

RULE_CLASS = [("sqli", "SQL 注入"), ("cmd", "命令注入"), ("command", "命令注入"),
              ("deser", "反序列化"), ("ssrf", "SSRF"), ("spel", "表达式注入"),
              ("code-injection", "代码执行"), ("path-traversal", "路径穿越"), ("xxe", "XXE"),
              ("xss", "XSS"), ("ssti", "模板注入"), ("redirect", "开放重定向"), ("exec", "命令注入")]


def _h(*parts: str) -> str:
    return hashlib.sha256("|".join(parts).encode()).hexdigest()[:16]


def _node(table: dict, status: str, **props) -> dict:
    return {**props, "status": status, "confidence": props.pop("confidence", DEFAULT_CONFIDENCE[status])}


def _merge_class(classes: dict, node: dict) -> None:
    """Same node reached from two sources: keep the stronger fact, not the later one."""
    existing = classes.get(node["id"])
    if not existing:
        classes[node["id"]] = node
        return
    merged = promote(existing["status"], node["status"])
    existing["status"] = merged
    existing["confidence"] = max(existing.get("confidence", 0), node.get("confidence", 0))


def _vuln_class(text: str) -> str | None:
    low = text.lower()
    for token, label in VULN_KEYWORDS:
        if token in low:
            return label
    return None


def _rule_class(rule_id: str) -> str | None:
    low = rule_id.lower()
    for token, label in RULE_CLASS:
        if token in low:
            return label
    return None


def _conn(db_path: pathlib.Path):
    conn = graph.open_db(str(db_path))
    for label, props in NODES.items():
        graph.ensure_node_table(conn, label, props)
    for rel, src, dst, props in EDGES:
        graph.ensure_rel_table(conn, rel, src, dst, {p: "STRING" for p in props} or None)
    return conn


def build(project_root: str, findings: list[dict] | None = None,
          db_path: str | None = None, lookup_cves: bool = True) -> dict:
    root = pathlib.Path(project_root)
    if not root.exists():
        return {"ok": False, "error": f"路径不存在: {project_root}"}

    slug = _h(str(root.resolve()))[:8]
    db = pathlib.Path(db_path) if db_path else DB_DIR / f"{root.name}-{slug}.db"
    if db.exists():
        try:
            for suffix in ("", ".wal", ".lock"):
                side = pathlib.Path(str(db) + suffix)
                if side.exists():
                    side.unlink()
        except OSError:
            db = db.with_name(f"{db.stem}-{int(time.time())}{db.suffix}")
    conn = _conn(db)

    app_id = _h("app", str(root.resolve()))
    graph.upsert_nodes_batch(conn, "App", [_node(
        NODES["App"], "DERIVED", id=app_id, name=root.name,
        origin=str(root.resolve()), kind="project")], ["name", "origin", "kind", "status", "confidence"])

    # ---- technology / version / dependency / n-day ----------------------
    prof = profile.profile(str(root))
    tech_nodes, tech_edges = [], []
    for fam in prof.get("frameworks", []):
        tid = _h("tech", fam)
        tech_nodes.append(_node(NODES["Technology"], "DERIVED", id=tid, name=fam, category="framework"))
        tech_edges.append({"src": app_id, "dst": tid})

    comps = sca.enrich(str(root)) if lookup_cves else sca.components(str(root))
    dep_status = "OBSERVED" if comps.get("source") == "opensca" else "DERIVED"
    dep_nodes, dep_edges, nday_nodes, affected, evidences = [], [], [], [], []
    ev_nday_edges, ev_dep_edges = [], []
    for c in comps.get("components", []):
        if not c.get("name") or c.get("root"):
            continue
        did = _h("dep", c["name"], c.get("version", ""))
        dep_nodes.append(_node(NODES["Dependency"], dep_status, id=did, name=c["name"],
                               version=c.get("version", ""), ecosystem=c.get("language", ""),
                               direct="true" if c.get("direct") else "false"))
        dep_edges.append({"src": app_id, "dst": did})
        ev_id = _h("ev", "dep", did)
        evidences.append(_node(NODES["Evidence"], "OBSERVED", id=ev_id,
                               name=f"{c['name']}@{c.get('version','?')}", kind="dependency",
                               source=comps.get("source", "unknown"),
                               summary=", ".join(c.get("paths", [])[:2])))
        ev_dep_edges.append({"src": ev_id, "dst": did})
        for cve in c.get("cves") or []:
            nid = cve["id"]
            nday_nodes.append(_node(NODES["NDay"], "OBSERVED", id=nid, name=nid,
                                    score=float(cve.get("score") or 0),
                                    summary=(cve.get("summary") or "")[:400], confidence=0.9))
            affected.append({"src": did, "dst": nid, "matched": "true"})
            ev_nday_edges.append({"src": ev_id, "dst": nid})

    tech_by_fam = {t["name"]: t["id"] for t in tech_nodes}
    ver_nodes: dict[str, dict] = {}
    ver_edges: list[dict] = []
    for c in comps.get("components", []):
        if not c.get("version"):
            continue
        for fam, tid in tech_by_fam.items():
            if fam.lower() in f"{c.get('vendor','')} {c.get('name','')}".lower():
                vid = _h("ver", fam, c["version"])
                ver_nodes[vid] = _node(NODES["Version"], "DERIVED", id=vid,
                                       name=f"{fam} {c['version']}", tech_id=tid)
                ver_edges.append({"src": tid, "dst": vid})

    # N-day -> vulnerability class, inferred from the advisory text
    vc_nodes: dict[str, dict] = {}
    nday_class_edges: list[dict] = []
    for n in nday_nodes:
        label = _vuln_class(f"{n['name']} {n.get('summary', '')}")
        if label:
            cid = _h("vc", label)
            _merge_class(vc_nodes, _node(NODES["VulnClass"], "INFERRED", id=cid,
                                         name=label, category="web"))
            nday_class_edges.append({"src": n["id"], "dst": cid})

    common = ["name", "status", "confidence"]
    graph.upsert_nodes_batch(conn, "Technology", tech_nodes, common + ["category"])
    graph.upsert_nodes_batch(conn, "Version", list(ver_nodes.values()), common + ["tech_id"])
    graph.upsert_nodes_batch(conn, "Dependency", dep_nodes, common + ["version", "ecosystem", "direct"])
    graph.upsert_nodes_batch(conn, "NDay", nday_nodes, common + ["score", "summary"])
    graph.upsert_nodes_batch(conn, "VulnClass", list(vc_nodes.values()), common + ["category"])
    graph.upsert_nodes_batch(conn, "Evidence", evidences, common + ["kind", "source", "summary"])
    graph.insert_edges_batch(conn, "USES_TECHNOLOGY", tech_edges, "App", "Technology")
    graph.insert_edges_batch(conn, "HAS_VERSION", ver_edges, "Technology", "Version")
    graph.insert_edges_batch(conn, "DEPENDS_ON", dep_edges, "App", "Dependency")
    graph.insert_edges_batch(conn, "AFFECTED_BY", affected, "Dependency", "NDay", props=["matched"])
    graph.insert_edges_batch(conn, "EVIDENCES_DEP", ev_dep_edges, "Evidence", "Dependency")
    graph.insert_edges_batch(conn, "EVIDENCES_NDAY", ev_nday_edges, "Evidence", "NDay")
    graph.insert_edges_batch(conn, "SUGGESTS_NDAY", nday_class_edges, "NDay", "VulnClass")

    # ---- endpoints / capabilities --------------------------------------
    proc.stage("提取端点")
    found = endpoints.scan(str(root))
    eps = found["endpoints"]
    ep_nodes, ep_edges, feat, exposes, ep_ev, ev_ep_edges = [], [], {}, [], [], []
    for e in eps:
        eid = _h("ep", e["method"], e["path"], e["file"], str(e["line"]))
        ep_nodes.append(_node(NODES["Endpoint"], "DERIVED", id=eid,
                              name=f"{e['method']} {e['path']}", method=e["method"],
                              path=e["path"], file=e["file"], line=e["line"]))
        ep_edges.append({"src": app_id, "dst": eid})
        ev_id = _h("ev", "ep", eid)
        ep_ev.append(_node(NODES["Evidence"], "OBSERVED", id=ev_id,
                           name=f"{e['file']}:{e['line']}", kind="endpoint",
                           source="source-scan", summary=f"{e['method']} {e['path']}"))
        ev_ep_edges.append({"src": ev_id, "dst": eid})
        for label in e.get("features", []):
            fid = _h("feat", label)
            feat[fid] = _node(NODES["Feature"], "INFERRED", id=fid, name=label)
            exposes.append({"src": eid, "dst": fid})

    graph.upsert_nodes_batch(conn, "Endpoint", ep_nodes,
                             common + ["method", "path", "file", "line"])
    graph.upsert_nodes_batch(conn, "Feature", list(feat.values()), common)
    graph.upsert_nodes_batch(conn, "Evidence", ep_ev, common + ["kind", "source", "summary"])
    graph.insert_edges_batch(conn, "HAS_INTERFACE", ep_edges, "App", "Endpoint")
    graph.insert_edges_batch(conn, "EXPOSES", exposes, "Endpoint", "Feature")
    graph.insert_edges_batch(conn, "EVIDENCES_ENDPOINT", ev_ep_edges, "Evidence", "Endpoint")

    # ---- findings -------------------------------------------------------
    find_nodes, covers, find_class_edges = [], [], []
    ep_by_file = [(e["file"], _h("ep", e["method"], e["path"], e["file"], str(e["line"])))
                  for e in eps]
    for f in findings or []:
        if f.get("status") == "rejected":
            continue
        fid = f.get("fingerprint") or _h("finding", f.get("rule_id", ""), f.get("file", ""))
        status = "CONFIRMED" if f.get("status") == "confirmed" else "INFERRED"
        find_nodes.append(_node(NODES["Finding"], status, id=fid, name=f.get("rule_id", ""),
                                status_finding=f.get("status", ""), rule_id=f.get("rule_id", ""),
                                file=f.get("file", ""), line=f.get("line") or 0))
        for ep_file, eid in ep_by_file:
            if f.get("file") and ep_file == f["file"]:
                covers.append({"src": fid, "dst": eid})
        label = _rule_class(f.get("rule_id", ""))
        if label:
            cid = _h("vc", label)
            _merge_class(vc_nodes, _node(NODES["VulnClass"], status, id=cid,
                                         name=label, category="web"))
            find_class_edges.append({"src": fid, "dst": cid})

    if find_nodes:
        graph.upsert_nodes_batch(conn, "Finding", find_nodes,
                                 common + ["status_finding", "rule_id", "file", "line"])
        graph.insert_edges_batch(conn, "COVERS", covers, "Finding", "Endpoint")
        graph.upsert_nodes_batch(conn, "VulnClass", list(vc_nodes.values()), common + ["category"])
        graph.insert_edges_batch(conn, "SUGGESTS_FINDING", find_class_edges, "Finding", "VulnClass")

    graph.close(conn)
    by_file: dict[str, int] = {}
    for f in findings or []:
        if f.get("status") != "rejected":
            by_file[f.get("file", "")] = by_file.get(f.get("file", ""), 0) + 1

    return {
        "ok": True,
        "db": str(db),
        "app": {"id": app_id, "name": root.name},
        "counts": {
            "technologies": len(tech_nodes),
            "versions": len(ver_nodes),
            "dependencies": len(dep_nodes),
            "ndays": len({n["id"] for n in nday_nodes}),
            "vuln_classes": len(vc_nodes),
            "endpoints": len(ep_nodes),
            "features": len(feat),
            "findings": len(find_nodes),
        },
        "sca_source": comps.get("source"),
        "sca_error": comps.get("opensca_error"),
        "nvd_lookups": comps.get("lookups"),
        "nvd_skipped": comps.get("skipped"),
        "unresolved": comps.get("unresolved") or [],
        "incomplete_reasons": (list(comps.get("incomplete_reasons") or []) if lookup_cves
                               else [NO_CVE])
        + (["源文件过多，端点提取不完整"] if found["truncated"] else []),
        # What the console shows, so it never has to open the database.
        "endpoints": [{**e, "findings": by_file.get(e["file"], 0)} for e in eps],
        "dependencies": [{"group": c.get("vendor", ""), "name": c["name"], "version": c.get("version", ""),
                          "direct": bool(c.get("direct")), "language": c.get("language", ""),
                          "cves": [{"id": v["id"], "score": v.get("score")} for v in c.get("cves") or []]}
                         for c in comps.get("components", []) if c.get("name") and not c.get("root")],
        "technologies": prof.get("frameworks", []),
    }


def summary(db_path: str, limit: int = 40) -> dict:
    conn = graph.open_db(db_path)
    counts = {}
    for label in NODES:
        try:
            rows = graph.query(conn, f"MATCH (n:{label}) RETURN count(n) AS n")
            counts[label] = rows[0]["n"] if rows else 0
        except Exception:
            counts[label] = 0
    risky, eps, classes = [], [], []
    try:
        risky = graph.query(conn, (
            "MATCH (d:Dependency)-[r:AFFECTED_BY]->(c:NDay) "
            "RETURN d.name AS dependency, d.version AS version, c.id AS cve, "
            "c.score AS score, c.summary AS summary, c.status AS status "
            "ORDER BY c.score DESC LIMIT $limit"), {"limit": limit})
    except Exception:
        pass
    try:
        eps = graph.query(conn, (
            "MATCH (a:App)-[:HAS_INTERFACE]->(e:Endpoint) "
            "RETURN e.name AS endpoint, e.file AS file, e.line AS line, e.status AS status "
            "LIMIT $limit"), {"limit": limit})
    except Exception:
        pass
    try:
        classes = graph.query(conn, (
            "MATCH (v:VulnClass) RETURN v.name AS name, v.status AS status, "
            "v.confidence AS confidence LIMIT $limit"), {"limit": limit})
    except Exception:
        pass
    graph.close(conn)
    return {"db": db_path, "counts": counts, "ndays": risky,
            "endpoints": eps, "vuln_classes": classes}
