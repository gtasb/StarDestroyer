"""Non-injection knowledge base.

Documents are indexed here and *retrieved on demand*. Nothing in this module is
concatenated into a prompt automatically: callers ask for the top-k chunks and
carry the citations themselves. That is the difference between a knowledge base
and prompt stuffing.

CJK has no word boundaries, so text is indexed as overlapping bigrams. Without
that, a Chinese document is one unsearchable token.
"""

import contextlib
import hashlib
import pathlib
import re
import sqlite3
import time

DB_PATH = pathlib.Path(__file__).resolve().parents[1] / ".work" / "kb" / "kb.db"

_CJK = re.compile(r"[一-鿿]")
_WORD = re.compile(r"[A-Za-z0-9_]+")


def _connect() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("CREATE TABLE IF NOT EXISTS docs("
                 "id TEXT PRIMARY KEY, title TEXT, path TEXT, added_at TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS chunks("
                 "id INTEGER PRIMARY KEY, doc_id TEXT, ord INTEGER, text TEXT)")
    # The first version was contentless, which cannot delete: re-ingesting any
    # document failed. Rebuild it once from the chunks that are still there.
    row = conn.execute("SELECT sql FROM sqlite_master WHERE name = 'chunks_fts'").fetchone()
    if row is None or "content=''" in row[0]:
        with conn:
            conn.execute("DROP TABLE IF EXISTS chunks_fts")
            conn.execute("CREATE VIRTUAL TABLE chunks_fts USING fts5(tokens)")
            conn.executemany("INSERT INTO chunks_fts(rowid, tokens) VALUES (?,?)",
                             [(i, tokenize(t)) for i, t in conn.execute("SELECT id, text FROM chunks")])
    return conn


def tokenize(text: str) -> str:
    """ASCII words kept whole; CJK runs become overlapping bigrams."""
    out: list[str] = []
    for m in _WORD.finditer(text):
        out.append(m.group(0).lower())
    for seq in re.findall(r"[一-鿿]+", text):
        if len(seq) == 1:
            out.append(seq)
        for i in range(len(seq) - 1):
            out.append(seq[i:i + 2])
    return " ".join(out)


def _chunk(text: str, size: int = 900, overlap: int = 120) -> list[str]:
    paras = [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]
    chunks, buf = [], ""
    for p in paras:
        if len(buf) + len(p) + 1 <= size:
            buf = (buf + "\n\n" + p).strip()
        else:
            if buf:
                chunks.append(buf)
            while len(p) > size:
                chunks.append(p[:size])
                p = p[size - overlap:]
            buf = p
    if buf:
        chunks.append(buf)
    return chunks or ([text.strip()] if text.strip() else [])


def ingest_text(title: str, text: str, path: str = "") -> dict:
    with contextlib.closing(_connect()) as conn, conn:
        return _ingest(conn, title, text, path)


def _ingest(conn, title: str, text: str, path: str) -> dict:
    doc_id = hashlib.sha256((path or title).encode()).hexdigest()[:16]
    conn.execute("INSERT OR REPLACE INTO docs VALUES (?,?,?,?)",
                 (doc_id, title, path, time.strftime("%Y-%m-%d %H:%M")))
    conn.execute("DELETE FROM chunks_fts WHERE rowid IN "
                 "(SELECT id FROM chunks WHERE doc_id = ?)", (doc_id,))
    conn.execute("DELETE FROM chunks WHERE doc_id = ?", (doc_id,))
    n = 0
    for i, ch in enumerate(_chunk(text)):
        cur = conn.execute("INSERT INTO chunks(doc_id, ord, text) VALUES (?,?,?)",
                           (doc_id, i, ch))
        conn.execute("INSERT INTO chunks_fts(rowid, tokens) VALUES (?,?)",
                     (cur.lastrowid, tokenize(ch)))
        n += 1
    return {"doc_id": doc_id, "title": title, "chunks": n}


def ingest_dir(root: str, exts: tuple[str, ...] = (".md", ".txt", ".markdown")) -> dict:
    p = pathlib.Path(root)
    if not str(root).strip() or not p.exists():
        return {"ok": False, "error": f"目录不存在: {root}"}
    docs, failed = [], []
    for f in [p] if p.is_file() else sorted(p.rglob("*")):
        if f.is_file() and f.suffix.lower() in exts:
            try:
                docs.append(ingest_text(f.stem, f.read_text(encoding="utf-8", errors="replace"),
                                        str(f.resolve())))
            except (OSError, sqlite3.Error) as exc:
                failed.append({"path": str(f), "error": str(exc)})
    return {"ok": True, "docs": len(docs), "detail": docs, "failed": failed}


def remove(doc_id: str) -> dict:
    with contextlib.closing(_connect()) as conn, conn:
        conn.execute("DELETE FROM chunks_fts WHERE rowid IN "
                     "(SELECT id FROM chunks WHERE doc_id = ?)", (doc_id,))
        conn.execute("DELETE FROM chunks WHERE doc_id = ?", (doc_id,))
        n = conn.execute("DELETE FROM docs WHERE id = ?", (doc_id,)).rowcount
    return {"ok": bool(n)}


def _match(query: str) -> str:
    """OR over quoted tokens: a question shares some words with its answer, rarely
    all of them. bm25 puts the chunk sharing the most rare ones first."""
    tokens = dict.fromkeys(tokenize(query).split())
    return " OR ".join(f'"{t}"*' if len(t) == 1 and _CJK.match(t) else f'"{t}"' for t in tokens)


def search(query: str, k: int = 5) -> list[dict]:
    q = _match(query)
    if not q:
        return []
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT d.title, d.path, c.text, bm25(chunks_fts) AS score "
            "FROM chunks_fts JOIN chunks c ON c.id = chunks_fts.rowid "
            "JOIN docs d ON d.id = c.doc_id "
            "WHERE chunks_fts MATCH ? ORDER BY score LIMIT ?", (q, k)).fetchall()
    return [{"title": r[0], "path": r[1], "text": r[2], "score": round(-r[3], 3)}
            for r in rows]


def preview(query: str, k: int = 5) -> dict:
    """What retrieval would hand back, and how much text that is.

    Makes the non-injection contract visible: the caller sees the exact chunks
    and their size before anything is used.
    """
    hits = search(query, k)
    return {
        "query": query,
        "hits": hits,
        "count": len(hits),
        "total_chars": sum(len(h["text"]) for h in hits),
        "sources": sorted({h["path"] or h["title"] for h in hits}),
        "injected": False,
    }


def list_docs() -> list[dict]:
    with contextlib.closing(_connect()) as conn:
        rows = conn.execute(
            "SELECT d.id, d.title, d.path, d.added_at, COUNT(c.id) "
            "FROM docs d LEFT JOIN chunks c ON c.doc_id = d.id "
            "GROUP BY d.id ORDER BY d.added_at DESC").fetchall()
    return [{"id": r[0], "title": r[1], "path": r[2], "added_at": r[3], "chunks": r[4]}
            for r in rows]
