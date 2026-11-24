"""Embedded Cypher graph store.

Neo4j's own distribution is unreachable from this environment (CloudFront 403)
and Docker is out of scope, so the code property graph lands in Kùzu: embedded,
no server, and still Cypher -- including variable-length path patterns, which is
the only thing the recursion here needs.

What this store cannot do is run `tabby.algo.*` procedures. Path search is done
with plain Cypher instead; templates live in core/templates/cypher/.
"""

import pathlib

import kuzu


def open_db(path: str) -> kuzu.Connection:
    p = pathlib.Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    db = kuzu.Database(str(p))
    conn = kuzu.Connection(db)
    conn._db = db  # keep the Database alive: dropping it releases the file lock
    return conn


def close(conn: kuzu.Connection) -> None:
    db = getattr(conn, "_db", None)
    for obj in (conn, db):
        try:
            if obj is not None:
                obj.close()
        except Exception:
            pass


def has_table(conn: kuzu.Connection, name: str) -> bool:
    r = conn.execute("CALL show_tables() RETURN name")
    while r.has_next():
        if r.get_next()[0] == name:
            return True
    return False


def ensure_node_table(conn: kuzu.Connection, label: str, props: dict[str, str],
                      pk: str = "id") -> None:
    if has_table(conn, label):
        return
    cols = ", ".join(f"{k} {v}" for k, v in props.items())
    conn.execute(f"CREATE NODE TABLE {label}({cols}, PRIMARY KEY({pk}))")


def ensure_rel_table(conn: kuzu.Connection, rel: str, src: str, dst: str,
                     props: dict[str, str] | None = None) -> None:
    if has_table(conn, rel):
        return
    cols = "".join(f", {k} {v}" for k, v in (props or {}).items())
    conn.execute(f"CREATE REL TABLE {rel}(FROM {src} TO {dst}{cols})")


def upsert_nodes(conn: kuzu.Connection, label: str, rows: list[dict],
                 props: list[str], pk: str = "id") -> int:
    if not rows:
        return 0
    names = [pk] + [p for p in props if p != pk]
    sets = ", ".join(f"n.{p} = ${p}" for p in names if p != pk)
    q = f"MERGE (n:{label} {{{pk}: ${pk}}})"
    if sets:
        q += f" SET {sets}"
    for row in rows:
        params = {p: row.get(p) for p in names}
        conn.execute(q, params)
    return len(rows)


def insert_edges(conn: kuzu.Connection, rel: str, edges: list[dict],
                 src_label: str, dst_label: str, src_key: str = "src",
                 dst_key: str = "dst", props: list[str] | None = None) -> int:
    if not edges:
        return 0
    props = props or []
    sets = "".join(f" SET r.{p} = ${p}" for p in props)
    q = (f"MATCH (a:{src_label} {{id: ${src_key}}}), (b:{dst_label} {{id: ${dst_key}}}) "
         f"MERGE (a)-[r:{rel}]->(b){sets}")
    n = 0
    for e in edges:
        params = {src_key: e[src_key], dst_key: e[dst_key]}
        params.update({p: e.get(p) for p in props})
        conn.execute(q, params)
        n += 1
    return n


def upsert_nodes_batch(conn: kuzu.Connection, label: str, rows: list[dict],
                       props: list[str], pk: str = "id") -> int:
    """One statement for the whole batch; per-row MERGE costs ~15x on 6k nodes."""
    if not rows:
        return 0
    sets = ", ".join(f"n.{p} = row.{p}" for p in props if p != pk)
    q = f"UNWIND $rows AS row MERGE (n:{label} {{{pk}: row.{pk}}})"
    if sets:
        q += f" SET {sets}"
    # One statement for 400k rows blows the parameter buffer and the heap; a
    # few thousand at a time keeps memory flat.
    for i in range(0, len(rows), 4000):
        conn.execute(q, {"rows": rows[i:i + 4000]})
    return len(rows)


def insert_edges_batch(conn: kuzu.Connection, rel: str, edges: list[dict],
                       src_label: str, dst_label: str, props: list[str] | None = None,
                       src_key: str = "src", dst_key: str = "dst") -> int:
    if not edges:
        return 0
    sets = "".join(f" SET r.{p} = e.{p}" for p in (props or []))
    q = (f"UNWIND $edges AS e "
         f"MATCH (a:{src_label} {{id: e.{src_key}}}), (b:{dst_label} {{id: e.{dst_key}}}) "
         f"MERGE (a)-[r:{rel}]->(b){sets}")
    for i in range(0, len(edges), 4000):
        conn.execute(q, {"edges": edges[i:i + 4000]})
    return len(edges)


def query(conn: kuzu.Connection, cypher: str, params: dict | None = None) -> list[dict]:
    r = conn.execute(cypher, params or {})
    cols = r.get_column_names()
    out = []
    while r.has_next():
        out.append(dict(zip(cols, r.get_next())))
    return out


def render_path(row: dict) -> list[dict]:
    """Flatten a Kùzu path value into ordered trace steps.

    Kùzu returns a path as {'_nodes': [...], '_rels': [...]}; each node is a
    plain dict of the node's properties.
    """
    path = row.get("p") or row.get("path")
    if not path:
        return []
    nodes = path.get("_nodes") if isinstance(path, dict) else getattr(path, "_nodes", None)
    if not nodes:
        return []
    steps = []
    for n in nodes:
        cls = n.get("cls") or n.get("classname") or ""
        name = n.get("name") or n.get("methodname") or n.get("id", "")
        steps.append({
            "kind": "propagation",
            "file": n.get("file") or "",
            "line": n.get("line") or n.get("start_line"),
            "text": f"{cls}.{name}" if cls else str(name),
            "id": n.get("id", ""),
        })
    return steps
