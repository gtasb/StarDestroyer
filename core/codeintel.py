"""Code navigation for the audit agent: definitions, callers, implementations,
mapper statements and sink sites over the whole source tree.

Textual, on comment- and string-blanked source. It answers "where should I read
next", never "is this vulnerable": an agent confirms everything by reading.
"""

import bisect
import os
import pathlib
import re
import threading
import time

from . import ledger, sfc, testcode
from .profile import BUILT, _EXT, _walk

SOURCE = _EXT
TEXT = set(SOURCE) | {".xml", ".yml", ".yaml", ".properties", ".ftl", ".html", ".jsp", ".vm", ".sql", ".gradle",
                      ".json", ".toml", ".js", ".ts"}
MAX_BYTES = 2_000_000

_C_BLANK = re.compile(r'"(?:\\.|[^"\\\n])*"|`[^`]*`|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*', re.S)
_PY_BLANK = re.compile(r'"""(?:.|\n)*?"""|\'\'\'(?:.|\n)*?\'\'\'|"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|#[^\n]*')


# A regex literal may hold quotes; a template literal may hold calls, so ${...} stays.
_JS_BLANK = re.compile(r'(?:(?<=[=(,:;!&|?{}\[\n])|(?<=return))[ \t]*/(?![*/])(?:\\.|\[(?:\\.|[^\]\\\n])*\]|[^/\\\n])+/[a-z]*|'
                       r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|(?<!:)//[^\n]*', re.S)


# PHP: # comments too, but #[...] is an attribute.
_PHP_BLANK = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*|#(?!\[)[^\n]*', re.S)


def blank(text: str, lang: str) -> str:
    """Comments and string bodies become spaces; offsets and lines survive."""
    return {"python": _PY_BLANK, "js": _JS_BLANK, "php": _PHP_BLANK}.get(lang, _C_BLANK).sub(lambda m: re.sub(r"[^\n]", " ", m.group(0)), text)


_JAVA_TYPE = re.compile(r"\b(class|interface|enum|record|object)\s+(\w+)([^{;]*)\{")
_JAVA_METHOD = re.compile(
    r"^[ \t]*(?:(?:public|protected|private|static|final|synchronized|abstract|default|native|override|suspend|open)\s+)*"
    r"(?:<[^>{};]+>\s+)?(?:fun\s+|[\w.]+(?:<[^;{}()]*>)?(?:\[\])*\s+)(\w+)\s*\(([^;{}]*)\)\s*"
    r"(?:throws\s+[\w., ]+)?\s*(?::\s*[\w<>?., ]+)?\s*([{;])", re.M)
_NOT_METHOD = {"if", "for", "while", "switch", "catch", "return", "new", "else", "throw", "synchronized", "try", "do"}
_PY_DEF = re.compile(r"^([ \t]*)(?:async\s+)?(def|class)\s+(\w+)([^\n]*)", re.M)
_GO_FUNC = re.compile(r"^func\s+(?:\(\s*\w*\s*\*?([\w.]+)[^)]*\)\s*)?(\w+)\s*\(([^)]*)\)[^{\n]*\{", re.M)
_JS_TYPE = re.compile(r"\b(class|interface)\s+(\w+)([^{;()]*)\{")
_JS_FUNC = re.compile(r"\bfunction\s*\*?\s*(\w+)\s*(?:<[^>()]*>)?\(|"                                  # function f(
                      r"\b(?:const|let|var)\s+(\w+)\s*(?::[^=;\n]+)?=\s*(?:async\s+)?function\b[^(]*\(|"  # const f = function(
                      r"\b(?:const|let|var)\s+(\w+)\s*(?::[^=;\n]+)?=\s*(?:async\s*)?(?:<[^>()]*>)?\(|"     # const f = (..) =>
                      r"\b(?:const|let|var)\s+(\w+)\s*=\s*(?:async\s+)?\w+\s*=>|"                           # const f = x =>
                      r"(?:\bexports|\bmodule\.exports|\bprototype)\.(\w+)\s*=\s*(?:async\s*)?(?:function\b[^(]*)?\(|"
                      r"^[ \t]*(?:(?:public|private|protected|static|async|get|set|override|readonly)\s+)*[*#]?(\w+)\s*(?:<[^>()]*>)?\(|"  # method(
                      r"(?:^|(?<=[{,]))[ \t]*(\w+)\s*:\s*(?:async\s*)?(?:function\b[^(]*)?\(", re.M)                         # name: (..) =>
_JS_NOT = _NOT_METHOD | {"function", "constructor", "super", "await", "typeof", "delete", "void", "import", "require", "with", "of", "in"}
_PHP_TYPE = re.compile(r"\b(class|interface|trait|enum)\s+(\w+)([^{;]*)\{")
_PHP_FUNC = re.compile(r"\bfunction\s+&?(\w+)\s*\(")
_GO_TYPE = re.compile(r"^type\s+(\w+)\s+(struct|interface)\s*\{", re.M)


def _close(text: str, start: int) -> int:
    """Offset after the brace that closes the one at start."""
    depth = 0
    for m in re.compile(r"[{}]").finditer(text, start):
        depth += 1 if m.group(0) == "{" else -1
        if depth == 0:
            return m.end()
    return len(text)


def _paren(text: str, start: int) -> int:
    """Offset after the parenthesis that closes the one at start."""
    depth = 0
    for m in re.compile(r"[()]").finditer(text, start):
        depth += 1 if m.group(0) == "(" else -1
        if depth == 0:
            return m.end()
    return len(text)


def _statement(text: str, start: int) -> int:
    """Where an expression body ends: its semicolon, or a line end outside brackets."""
    depth = 0
    for m in re.compile(r"[()\[\]{};\n]").finditer(text, start):
        c = m.group(0)
        if c in "([{":
            depth += 1
        elif c in ")]}":
            depth -= 1
            if depth < 0:
                return m.start()
        elif depth == 0 and (c == ";" or text[start:m.start()].strip()):
            return m.start()
    return len(text)


class File:
    """One parsed source file."""

    def __init__(self, path: pathlib.Path, rel: str):
        self.rel = rel
        self.lang = SOURCE.get(path.suffix.lower(), "")
        self.text = path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n")
        self.starts = [0] + [m.end() for m in re.finditer("\n", self.text)]
        self.lines = self.text.split("\n")
        self.types: list[dict] = []
        self.methods: list[dict] = []
        self.statements: list[dict] = []
        # A component's template is markup; only its script is code.
        body = sfc.script(self.text) if path.suffix.lower() in sfc.EXTENSIONS else self.text
        self.code = blank(body, self.lang) if self.lang else self.text
        if self.lang == "java":
            self._java()
        elif self.lang == "python":
            self._python()
        elif self.lang == "go":
            self._go()
        elif self.lang == "js":
            self._js()
        elif self.lang == "php":
            self._php()
        elif path.suffix.lower() == ".xml" and "<mapper" in self.text:
            self._mapper()

    def line(self, offset: int) -> int:
        return bisect.bisect_right(self.starts, offset)

    def _java(self) -> None:
        for m in _JAVA_TYPE.finditer(self.code):
            end = _close(self.code, m.end() - 1)
            # Generic arguments are kept: ServiceImpl<UserMapper, User> names the mapper.
            supers = re.findall(r"\b([A-Z]\w+)", m.group(3))
            self.types.append({"name": m.group(2), "kind": m.group(1), "supers": supers, "file": self.rel,
                               "start": self.line(m.start()), "end": self.line(end - 1)})
        for m in _JAVA_METHOD.finditer(self.code):
            name = m.group(1)
            if name in _NOT_METHOD or re.match(r"\s*(return|new|throw|else)\b", m.group(0)):
                continue
            end = _close(self.code, m.end() - 1) if m.group(3) == "{" else m.end()
            start = self.line(m.start() + len(m.group(0)) - len(m.group(0).lstrip()))
            first = start  # annotations above belong to the method
            while first > 1 and re.match(r"\s*@\w", self.lines[first - 2]):
                first -= 1
            self._method(name, self._owner(start), m.group(2), first, start, self.line(end - 1), m.group(3) == "{")

    def _owner(self, line: int) -> str:
        inside = [t for t in self.types if t["start"] <= line <= t["end"]]
        return max(inside, key=lambda t: t["start"])["name"] if inside else ""

    def _method(self, name, owner, params, first, start, end, body) -> None:
        self.methods.append({"name": name, "owner": owner, "params": " ".join(params.split())[:200], "file": self.rel,
                             "first": first, "start": start, "end": end, "body": body})

    def _python(self) -> None:
        defs = list(_PY_DEF.finditer(self.code))
        for i, m in enumerate(defs):
            indent, start = len(m.group(1).expandtabs()), self.line(m.start(2))
            end = len(self.lines)
            for later in defs[i + 1:]:
                if len(later.group(1).expandtabs()) <= indent:
                    end = self.line(later.start()) - 1
                    break
            if m.group(2) == "class":
                self.types.append({"name": m.group(3), "kind": "class", "file": self.rel, "start": start, "end": end,
                                   "supers": re.findall(r"\b([A-Za-z_]\w+)", m.group(4))})
            else:
                first = start
                while first > 1 and re.match(r"\s*@", self.lines[first - 2]):
                    first -= 1
                self._method(m.group(3), self._owner(start), m.group(4).strip("(): "), first, start, end, True)

    def _go(self) -> None:
        for m in _GO_TYPE.finditer(self.code):
            self.types.append({"name": m.group(1), "kind": m.group(2), "supers": [], "file": self.rel,
                               "start": self.line(m.start()), "end": self.line(_close(self.code, m.end() - 1) - 1)})
        for m in _GO_FUNC.finditer(self.code):
            start = self.line(m.start())
            self._method(m.group(2), (m.group(1) or "").split(".")[-1], m.group(3), start, start,
                         self.line(_close(self.code, m.end() - 1) - 1), True)

    def _js(self) -> None:
        for m in _JS_TYPE.finditer(self.code):
            self.types.append({"name": m.group(2), "kind": m.group(1), "supers": re.findall(r"\b([A-Z]\w+)", m.group(3)), "file": self.rel,
                               "start": self.line(m.start()), "end": self.line(_close(self.code, m.end() - 1) - 1)})
        seen = set()
        for m in _JS_FUNC.finditer(self.code):
            name = next(g for g in m.groups() if g)
            if name in _JS_NOT:
                continue
            at, params, pos = m.start() + len(m.group(0)) - len(m.group(0).lstrip()), "", m.end()
            if m.group(0).endswith("("):
                pos = _paren(self.code, m.end() - 1)
                params = self.code[m.end():pos - 1]
            # What follows tells a definition from a call: `{`, a return type, or `=>`.
            tail = re.compile(r"\s*(?::\s*[^={;\n]+?)?\s*(=>\s*)?(\{)?").match(self.code, pos)
            arrow, brace = tail.group(1) or m.group(0).endswith("=>"), tail.group(2)
            if not brace and not arrow:
                continue
            if m.group(6) and not brace:  # call(x) => is not a method
                continue
            start = self.line(at)
            if (name, start) in seen:
                continue
            seen.add((name, start))
            end = self.line(_close(self.code, tail.end() - 1) - 1) if brace else self.line(_statement(self.code, tail.end()))
            first = start
            while first > 1 and re.match(r"\s*@\w", self.lines[first - 2]):
                first -= 1
            self._method(name, self._owner(start), params, first, start, end, True)

    def _php(self) -> None:
        for m in _PHP_TYPE.finditer(self.code):
            self.types.append({"name": m.group(2), "kind": m.group(1), "supers": re.findall(r"\b([A-Z]\w+)", m.group(3)), "file": self.rel,
                               "start": self.line(m.start()), "end": self.line(_close(self.code, m.end() - 1) - 1)})
        for m in _PHP_FUNC.finditer(self.code):
            end = _paren(self.code, m.end() - 1)
            tail = re.compile(r"\s*(?::\s*\??[\w\\|]+)?\s*([{;])").match(self.code, end)
            if not tail:
                continue
            start = self.line(m.start())
            first = start
            while first > 1 and re.match(r"\s*(#\[|/\*\*|\*)", self.lines[first - 2]):
                first -= 1
            body = tail.group(1) == "{"
            last = self.line(_close(self.code, tail.end() - 1) - 1) if body else self.line(tail.end())
            self._method(m.group(1), self._owner(start), self.code[m.end():end - 1], first, start, last, body)

    def _mapper(self) -> None:
        ns = re.search(r"<mapper\b[^>]*namespace\s*=\s*[\"']([^\"']+)", self.text)
        space = ns.group(1) if ns else ""
        for m in re.finditer(r"<(select|insert|update|delete|sql)\b[^>]*?\bid\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</\1>",
                             re.sub(r"<!--.*?-->", lambda c: re.sub(r"[^\n]", " ", c.group(0)), self.text, flags=re.S), re.S):
            raw = [{"expr": x.group(0), "line": self.line(m.start(3) + x.start())} for x in re.finditer(r"\$\{[^}]*\}", m.group(3))]
            self.statements.append({"namespace": space, "id": m.group(2), "kind": m.group(1), "file": self.rel,
                                    "start": self.line(m.start()), "end": self.line(m.end() - 1), "raw": raw,
                                    "includes": re.findall(r"<include\b[^>]*refid\s*=\s*[\"']([^\"']+)", m.group(3))})

    def method_at(self, line: int) -> dict | None:
        inside = [m for m in self.methods if m["first"] <= line <= m["end"]]
        return max(inside, key=lambda m: m["start"]) if inside else None


class Index:
    def __init__(self, root: str):
        p = pathlib.Path(root).resolve()
        self.root = p if p.is_dir() else p.parent
        self.files: dict[str, File] = {}
        for f in ([p] if p.is_file() else _walk(p)):
            if (f.suffix.lower() not in SOURCE and f.suffix.lower() != ".xml") or BUILT.search(f.name):
                continue
            try:
                if f.stat().st_size <= MAX_BYTES and not (SOURCE.get(f.suffix.lower()) == "js" and ledger._minified(f)):
                    self.files[f.relative_to(self.root).as_posix()] = File(f, f.relative_to(self.root).as_posix())
            except OSError:
                continue
        self.types: dict[str, list[dict]] = {}
        self.methods: dict[str, list[dict]] = {}
        self.statements: dict[str, list[dict]] = {}
        for f in self.files.values():
            for t in f.types:
                self.types.setdefault(t["name"], []).append(t)
            for m in f.methods:
                self.methods.setdefault(m["name"], []).append(m)
            for s in f.statements:
                self.statements.setdefault(s["id"], []).append(s)

    # ---- navigation ----
    def symbol(self, name: str) -> dict:
        """Definitions of a class, method or mapper statement; Owner.method is fine."""
        owner, _, short = name.rpartition(".")
        owner = owner.rsplit(".", 1)[-1]
        methods = [m for m in self.methods.get(short, []) if not owner or m["owner"] == owner]
        stmts = [s for s in self.statements.get(short, []) if not owner or s["namespace"].rsplit(".", 1)[-1] == owner]
        return {"types": self.types.get(short, [])[:20], "methods": methods[:40], "statements": stmts[:20]}

    def implementations(self, name: str) -> list[dict]:
        """Types that extend or implement name, transitively."""
        out, todo, seen = [], [name], {name}
        while todo:
            base = todo.pop()
            for ts in self.types.values():
                for t in ts:
                    if base in t["supers"] and t["name"] not in seen:
                        seen.add(t["name"])
                        out.append(t)
                        todo.append(t["name"])
        return out[:60]

    def callers(self, method: str, owner: str = "", limit: int = 60) -> list[dict]:
        """Call sites of method, with the method that contains each one.

        Owner narrows by what the receiver could be: the type itself, its interfaces
        or its implementations, as named by the fields and variables of the file.
        """
        near: set[str] = set()
        if owner:
            near = {owner} | {t["name"] for t in self.implementations(owner)}
            for t in self.types.get(owner, []):
                near |= set(t["supers"])
        call = re.compile(r"(?:\.|::|\b)" + re.escape(method) + r"\s*(?:\(|\b(?=\s*[;,)]))" if method else r"$^")
        out, skipped = [], 0
        for f in self.files.values():
            if not f.lang:
                continue
            # A caller mentions the type somewhere (field, import, parameter) or is the type.
            related = not near or any(re.search(rf"\b{re.escape(n)}\b", f.code) for n in near)
            for m in call.finditer(f.code):
                line = f.line(m.start())
                here = f.method_at(line)
                if here and here["name"] == method and here["start"] == line and m.group()[0] not in ".:":
                    continue  # the definition itself
                tail = f.code[m.start():m.end()]
                if not tail.rstrip().endswith("(") and "::" not in tail:
                    continue
                if not related:
                    skipped += 1
                    continue
                out.append({"file": f.rel, "line": line, "code": f.lines[line - 1].strip()[:200],
                            "in": f"{here['owner']}.{here['name']}" if here else "", "unrelated_skipped": 0})
                if len(out) >= limit:
                    out[-1]["truncated"] = True
                    return out
        if out and skipped:
            out[0]["unrelated_skipped"] = skipped
        return out

    def method_source(self, file: str, line: int) -> dict | None:
        f = self.files.get(file)
        m = f.method_at(line) if f else None
        if not m:
            return None
        return {**m, "source": "\n".join(f"{i}\t{f.lines[i - 1][:300]}" for i in range(m["first"], min(m["end"], m["first"] + 300) + 1))}


_CACHE: dict[str, tuple[float, Index]] = {}
_LOCK = threading.Lock()


def index(root: str, max_age: float = 120) -> Index:
    key = str(pathlib.Path(root).resolve())
    with _LOCK:
        at, idx = _CACHE.get(key, (0, None))
        if idx is None or time.monotonic() - at > max_age:
            idx = Index(root)
            _CACHE[key] = (time.monotonic(), idx)
            for old in sorted(_CACHE, key=lambda k: _CACHE[k][0])[:-4]:
                del _CACHE[old]
        return idx


# ---- sink sites -----------------------------------------------------------
# (class, cwe, language, regex over blanked code). Calls only, with a boundary:
# "eval(" must not match multiLikeval, "start(" must not match startsWith.
SINKS = [
    ("sqli", "CWE-89", "java", r"\.(?:executeQuery|executeUpdate|executeLargeUpdate|addBatch|prepareStatement|prepareCall|createNativeQuery|createQuery|createSQLQuery)\s*\(|"
                               r"\b(?:jdbcTemplate|namedParameterJdbcTemplate)\w*\.(?:query\w*|update|batchUpdate|execute)\s*\(|"
                               r"\.(?:last|apply|orderBy\w*|inSql|notInSql|having|exists|select)\s*\(\s*[^\")\s]"),
    ("cmd", "CWE-78", "java", r"\.getRuntime\s*\(\s*\)\s*\.exec\s*\(|\bnew\s+ProcessBuilder\s*\("),
    ("expression", "CWE-917", "java", r"\.parseExpression\s*\(|\bOgnl\.\w+\s*\(|\bMVEL\.eval\s*\(|\b(?:engine|scriptEngine|se)\.eval\s*\(|\bnew\s+GroovyShell\s*\(|\bAviatorEvaluator\.\w+\s*\("),
    ("deserialization", "CWE-502", "java", r"\bnew\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)|\.readUnshared\s*\(|\.fromXML\s*\(|\bnew\s+XMLDecoder\s*\(|\.(?:parseObject|parse)\s*\([^;]*(?:Feature\.SupportAutoType|Object\.class)|enableDefaultTyping|activateDefaultTyping"),
    ("ssrf", "CWE-918", "java", r"\.openConnection\s*\(|\.openStream\s*\(|\bnew\s+Http(?:Get|Post|Put|Delete)\s*\(|\b(?:restTemplate|RT|httpClient)\w*\.(?:getFor\w+|postFor\w+|exchange|execute)\s*\(|\bJsoup\.connect\s*\(|\bHttpUtil\.\w+\s*\(|\bHttpRequest\.(?:get|post)\s*\("),
    ("path_traversal", "CWE-22", "java", r"\bnew\s+File(?:InputStream|OutputStream|Reader|Writer)?\s*\(|\bPaths\.get\s*\(|\bFiles\.(?:newInputStream|newOutputStream|copy|write\w*|read\w*|delete\w*)\s*\(|\.transferTo\s*\(|\bFileCopyUtils\.\w+\s*\("),
    ("xxe", "CWE-611", "java", r"\b\w*[bB]uilder\w*\.parse\s*\(|\bnew\s+SAXReader\s*\(|\bnew\s+SAXBuilder\s*\(|\bXMLInputFactory\.\w+\s*\(|\bSAXParserFactory\.\w+\s*\(|\bDocumentHelper\.parseText\s*\("),
    ("code_injection", "CWE-470", "java", r"\bClass\.forName\s*\(|\.loadClass\s*\(|\.getMethod\s*\([^)]*\)\s*\.invoke|\bmethod\.invoke\s*\("),
    ("ssti", "CWE-1336", "java", r"\bnew\s+Template\s*\(|\bVelocity\.evaluate\s*\(|\.process\s*\([^)]*\bout|\bStringTemplateLoader\b|\bFreemarkerParseFactory\.\w+\s*\("),
    ("sqli", "CWE-89", "python", r"\.(?:execute|executemany|executescript|raw|extra)\s*\(|\btext\s*\("),
    ("cmd", "CWE-78", "python", r"\bos\.(?:system|popen)\s*\(|\bsubprocess\.\w+\s*\("),
    ("code_injection", "CWE-94", "python", r"(?<![\w.])(?:eval|exec)\s*\(|\bimportlib\.import_module\s*\("),
    ("deserialization", "CWE-502", "python", r"\b(?:pickle|cPickle|dill|marshal)\.loads?\s*\(|\byaml\.(?:load|unsafe_load|full_load)\s*\("),
    ("ssrf", "CWE-918", "python", r"\b(?:requests|httpx)\.\w+\s*\(|\burlopen\s*\("),
    ("ssti", "CWE-1336", "python", r"\brender_template_string\s*\(|\.from_string\s*\("),
    ("path_traversal", "CWE-22", "python", r"(?<![\w.])open\s*\(|\bsend_file\s*\(|\bshutil\.\w+\s*\("),
    ("sqli", "CWE-89", "go", r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext|Raw|Where|Order)\s*\("),
    ("cmd", "CWE-78", "go", r"\bexec\.Command(?:Context)?\s*\("),
    ("ssrf", "CWE-918", "go", r"\bhttp\.(?:Get|Post|PostForm|Head|NewRequest\w*)\s*\("),
    ("sqli", "CWE-89", "js", r"\.(?:query|execute|raw|whereRaw|orderByRaw|havingRaw|joinRaw|\$queryRawUnsafe|\$executeRawUnsafe)\s*\(|\b[sS]equelize\.literal\s*\("),
    ("nosqli", "CWE-943", "js", r"\.(?:findOne|findOneAndUpdate|updateOne|updateMany|deleteOne|deleteMany|\$where|aggregate)\s*\("),
    ("cmd", "CWE-78", "js", r"(?<![\w.])(?:exec|execSync|spawn|spawnSync|execFile|execFileSync|execa|execaCommand)\s*\(|\b(?:child_process|childProcess|cp|shell|shelljs)\.(?:exec|spawn|fork)\w*\s*\("),
    ("code_injection", "CWE-94", "js", r"(?<![\w.])eval\s*\(|\bnew\s+Function\s*\(|\bvm\.(?:runIn\w+|Script)\s*\(|(?<![\w.])set(?:Timeout|Interval)\s*\(\s*[`\w]+\s*[,+]"),
    ("deserialization", "CWE-502", "js", r"\bunserialize\s*\(|\b(?:yaml|jsyaml)\.load\s*\(|\bv8\.deserialize\s*\("),
    ("ssrf", "CWE-918", "js", r"(?<![\w.])(?:fetch|got|request)\s*\(\s*[^\s'\"]|\b(?:axios|got|needle|superagent)(?:\.\w+)?\s*\(\s*[^\s'\"]|\bhttps?\.(?:get|request)\s*\("),
    ("ssti", "CWE-1336", "js", r"\b(?:ejs|pug|jade)\.(?:render|compile)\s*\(|\b[hH]andlebars\.compile\s*\(|\bnunjucks\.renderString\s*\(|\b(?:_|lodash)\.template\s*\("),
    ("path_traversal", "CWE-22", "js", r"\b(?:fs|fsp|fs\.promises|fsPromises)\.(?:read|write|unlink|rm|create|append|copy|readdir|open)\w*\s*\(|\.(?:sendFile|sendfile|download)\s*\("),
    ("prototype_pollution", "CWE-1321", "js", r"\b(?:_|lodash)\.(?:merge|mergeWith|defaultsDeep|set|setWith)\s*\(|\b(?:\$|jQuery)\.extend\s*\(\s*true\b|\bdeepmerge\s*\("),
    ("dom_xss", "CWE-79", "js", r"\.(?:innerHTML|outerHTML|srcdoc)\s*\+?=(?!=)|\bdocument\.write(?:ln)?\s*\(|\.insertAdjacentHTML\s*\(|\bdangerouslySetInnerHTML\b|\.createContextualFragment\s*\(|\bbypassSecurityTrust\w+\s*\(|\.html\s*\(\s*[^\s)'\"]"),
    ("postmessage", "CWE-346", "js", r"\.postMessage\s*\(|\bonmessage\s*="),
    ("sqli", "CWE-89", "php", r"\b(?:mysqli?_query|mysqli_multi_query|pg_query|sqlite_query)\s*\(|->(?:query|exec|prepare|multi_query|whereRaw|orWhereRaw|havingRaw|orderByRaw|selectRaw|groupByRaw|createCommand)\s*\(|"
                               r"\b(?:DB|Db)::(?:select|insert|update|delete|statement|unprepared|raw|query|execute)\s*\(|::(?:whereRaw|selectRaw|orderByRaw)\s*\("),
    ("cmd", "CWE-78", "php", r"(?<![\w>:$])(?:system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\s*\(|`[^`\n]*\$"),
    ("code_injection", "CWE-94", "php", r"(?<![\w>:$])(?:eval|assert|create_function|call_user_func(?:_array)?)\s*\(|\bpreg_replace\s*\(\s*['\"][^'\"]*/\w*e\w*['\"]|"
                                        r"\b(?:include|require)(?:_once)?\s*\(?\s*\$"),
    ("deserialization", "CWE-502", "php", r"(?<![\w>:$])(?:unserialize|yaml_parse|igbinary_unserialize)\s*\(|phar://"),
    ("ssrf", "CWE-918", "php", r"\bcurl_(?:init|setopt)\s*\(|(?<![\w>:$])(?:file_get_contents|fopen|fsockopen|get_headers)\s*\(\s*\$|\bHttp::(?:get|post|put|send)\s*\("),
    ("path_traversal", "CWE-22", "php", r"(?<![\w>:$])(?:file_put_contents|readfile|unlink|rmdir|copy|rename|move_uploaded_file|mkdir|file)\s*\(\s*[^)'\"]|->(?:download|extractTo)\s*\("),
    ("ssti", "CWE-1336", "php", r"->createTemplate\s*\(|['\"]string:|\bBlade::render\s*\("),
    ("path_traversal", "CWE-22", "go", r"\bos\.(?:Open|OpenFile|ReadFile|Create|Remove\w*|WriteFile)\s*\(|\bhttp\.ServeFile\s*\("),
]
_SINK_RX = [(c, w, lang, re.compile(rx)) for c, w, lang, rx in SINKS]


def sink_sites(root: str, classes: set[str] | None = None) -> list[dict]:
    """Every place dangerous APIs are used, mapper ${} included. Leads, not findings."""
    idx, out, test = index(root), [], testcode.skip(root)
    for f in idx.files.values():
        if test(f.rel):
            continue
        for s in f.statements:
            if classes is None or "sqli" in classes:
                out += [{"class": "sqli", "cwe": "CWE-89", "file": f.rel, "line": r["line"],
                         "code": f.lines[r["line"] - 1].strip()[:200], "in": f"{s['namespace'].rsplit('.', 1)[-1]}.{s['id']}",
                         "kind": "mybatis"} for r in s["raw"]]
        if f.lang == "java" and (classes is None or "sqli" in classes):  # annotation SQL: the string is blanked in code
            out += [{"class": "sqli", "cwe": "CWE-89", "file": f.rel, "line": f.line(m.start()),
                     "code": f.lines[f.line(m.start()) - 1].strip()[:200], "in": "", "kind": "mybatis"}
                    for m in re.finditer(r"@(?:Select|Update|Insert|Delete)\s*\([^;]*?\$\{", f.text)]
        if f.lang == "js" and (classes is None or "dom_xss" in classes):  # markup, not code
            out += [{"class": "dom_xss", "cwe": "CWE-79", "file": f.rel, "line": f.line(m.start()),
                     "code": f.lines[f.line(m.start()) - 1].strip()[:200], "in": "", "kind": "template"}
                    for m in re.finditer(r"\sv-html\s*=|\{@html\s|\[innerHTML\]\s*=", f.text)]
        for cls, cwe, lang, rx in _SINK_RX:
            if lang != f.lang or (classes is not None and cls not in classes):
                continue
            for m in rx.finditer(f.code):
                n = f.line(m.start())
                here = f.method_at(n)
                out.append({"class": cls, "cwe": cwe, "file": f.rel, "line": n, "code": f.lines[n - 1].strip()[:200],
                            "in": f"{here['owner']}.{here['name']}" if here else "", "kind": "call"})
    seen, uniq = set(), []
    for s in out:
        k = (s["file"], s["line"], s["class"])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq


def counts(root: str) -> dict:
    idx = index(root)
    return {"files": len(idx.files), "types": sum(map(len, idx.types.values())),
            "methods": sum(map(len, idx.methods.values())), "statements": sum(map(len, idx.statements.values()))}
