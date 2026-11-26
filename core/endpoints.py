"""Endpoint extraction and capability inference.

Endpoints are what makes an n-day reachable: a vulnerable library matters more
when the endpoint in front of it is a file upload than when it is a health check.

Textual, not a parser: comments are blanked, then annotations are read with
balanced parentheses so attributes may come in any order and span lines.
"""

import bisect
import pathlib
import re
import time

from . import testcode
from .profile import BUILT, _walk

CAPABILITIES = [
    ("admin", "管理后台"), ("upload", "文件上传"), ("download", "文件下载"),
    ("export", "数据导出"), ("import", "数据导入"), ("login", "认证"),
    ("auth", "认证"), ("payment", "支付"), ("order", "订单"),
    ("user", "用户管理"), ("exec", "命令执行面"), ("debug", "调试接口"),
    ("preview", "预览/渲染"), ("proxy", "代理/转发"), ("url", "外链访问"),
    ("sql", "数据查询"), ("api", "开放接口"),
]


def infer_features(path: str) -> list[str]:
    low = path.lower()
    return list(dict.fromkeys(label for token, label in CAPABILITIES if token in low))


_C_COMMENT = re.compile(r'"(?:\\.|[^"\\\n])*"|`[^`]*`|\'(?:\\.|[^\'\\\n])*\'|/\*.*?\*/|//[^\n]*', re.S)
_PY_COMMENT = re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|\#[^\n]*')


def _blank_comments(text: str, rx: re.Pattern) -> str:
    """Comments become spaces, so offsets and line numbers survive."""
    def keep(m):
        s = m.group(0)
        return s if s[0] in "\"'`" else re.sub(r"[^\n]", " ", s)
    return rx.sub(keep, text)


def _args(text: str, start: int) -> tuple[str, int]:
    """Balanced (...) starting at or after start; ("", start) when there is none."""
    i = start
    while i < len(text) and text[i] in " \t\r\n":
        i += 1
    if i >= len(text) or text[i] != "(":
        return "", start
    depth, j, quote = 0, i, ""
    while j < len(text):
        c = text[j]
        if quote:
            if c == "\\":
                j += 1
            elif c == quote:
                quote = ""
        elif c in "\"'`":
            quote = c
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if not depth:
                return text[i + 1:j], j + 1
        j += 1
    return "", start


_STR = r'"((?:\\.|[^"\\])*)"|\'((?:\\.|[^\'\\])*)\'|`([^`]*)`'


def _strings(s: str) -> list[str]:
    return [a or b or c for a, b, c in re.findall(_STR, s)]


def _join(prefix: str, path: str) -> str:
    out = "/".join(x.strip("/") for x in (prefix, path) if x.strip("/"))
    return "/" + out


# ---- Java ---------------------------------------------------------------
_MAPPING = re.compile(r"@(Get|Post|Put|Delete|Patch|Request)Mapping\b")
_CLASS = re.compile(r"\b(?:class|interface|@interface|record|enum)\s+\w+")
_JAXRS_PATH = re.compile(r"@Path\b")
_JAXRS_VERB = re.compile(r"@(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b(?!\s*\()")
_SERVLET = re.compile(r"@WebServlet\b")
_METHOD_ATTR = re.compile(r"RequestMethod\.(\w+)|\bmethod\s*=\s*\{?\s*(GET|POST|PUT|DELETE|PATCH)\b")


def _paths(args: str) -> list[str]:
    """value/path attribute, or the positional argument; arrays allowed."""
    m = re.search(r"\b(?:value|path|urlPatterns)\s*=\s*(\{[^}]*\}|%s)" % _STR, args)
    if m:
        return _strings(m.group(1))
    head = args.strip()
    if head.startswith("{"):
        return _strings(head[:head.index("}") + 1] if "}" in head else head)
    return _strings(head)[:1] if head[:1] in "\"'" else []


def _next_is_class(text: str, pos: int) -> bool:
    """Does this annotation sit on a type? Skip over further annotations first."""
    while True:
        m = re.compile(r"\s*@\w[\w.]*").match(text, pos)
        if not m:
            break
        _, pos = _args(text, m.end())
    m = re.compile(r"\s*(?:(?:public|protected|private|abstract|final|static|sealed)\s+)*"
                   r"(?:class|interface|record)\s").match(text, pos)
    return bool(m)


def _java(text: str) -> list[tuple[str, str, int]]:
    text = _blank_comments(text, _C_COMMENT)
    out: list[tuple[str, str, int]] = []
    prefixes: list[tuple[int, list[str]]] = []  # (offset of class, prefixes)
    classes = [m.start() for m in _CLASS.finditer(text)]
    raw = []
    for m in list(_MAPPING.finditer(text)) + list(_JAXRS_PATH.finditer(text)):
        args, end = _args(text, m.end())
        (prefixes if _next_is_class(text, end) else raw).append((m.start(), _paths(args), args, m))
    prefixes.sort(key=lambda x: x[0])

    def prefix_at(pos: int) -> list[str]:
        own = bisect.bisect_right(classes, pos) - 1
        if own < 0:
            return [""]
        lo = classes[own - 1] if own else 0
        for start, paths, *_ in prefixes:
            if lo <= start < classes[own]:
                return paths or [""]
        return [""]

    for pos, paths, args, m in raw:
        if m.re is _JAXRS_PATH:
            near = text[max(0, text.rfind(";", 0, pos), text.rfind("}", 0, pos)):text.find("{", pos)]
            verbs = _JAXRS_VERB.findall(near) or ["ANY"]
        elif m.group(1) == "Request":
            verbs = [a or b for a, b in _METHOD_ATTR.findall(args)] or ["ANY"]
        else:
            verbs = [m.group(1).upper()]
        for pre in prefix_at(pos):
            for path in paths or [""]:
                out += [(v, _join(pre, path), pos) for v in verbs]
    # JAX-RS verb without its own @Path: the class path is the endpoint
    for m in _JAXRS_VERB.finditer(text):
        lo = max(text.rfind(";", 0, m.start()), text.rfind("}", 0, m.start()), text.rfind("{", 0, m.start()))
        if "@Path" not in text[lo:text.find("{", m.start())]:
            pre = prefix_at(m.start())
            if pre != [""]:
                out += [(m.group(1), _join(p, ""), m.start()) for p in pre]
    for m in _SERVLET.finditer(text):
        args, _ = _args(text, m.end())
        out += [("ANY", _join("", p), m.start()) for p in _paths(args)]
    return out


# ---- Python ---------------------------------------------------------------
_PY_DECO = re.compile(r"@(\w+)\.(get|post|put|delete|patch|head|options|route|api_route|websocket)\b")
_PY_PREFIX = re.compile(r"(\w+)\s*=\s*(?:\w+\.)?(?:Blueprint|APIRouter)\b")
_PY_ADD = re.compile(r"\.add_url_rule\b|\.add_api_route\b")
_DJANGO = re.compile(r"\b(?:re_)?path\s*(?=\()|\burl\s*(?=\()")


def _py(text: str) -> list[tuple[str, str, int]]:
    text = _blank_comments(text, _PY_COMMENT)
    out = []
    prefix = {}
    for m in _PY_PREFIX.finditer(text):
        args, _ = _args(text, m.end())
        p = re.search(r"\b(?:url_)?prefix\s*=\s*(%s)" % _STR, args)
        prefix[m.group(1)] = _strings(p.group(1))[0] if p else ""

    def add(verb, args, pos, pre=""):
        m = re.search(r"\b(?:path|rule)\s*=\s*(%s)" % _STR, args)
        found = _strings(m.group(1)) if m else (_strings(args)[:1] if args.strip()[:1] in "\"'" or
                                                args.strip()[:2] in ('r"', "r'") else [])
        methods = re.search(r"\bmethods\s*=\s*[\[({]([^\])}]*)", args)
        verbs = [v.upper() for v in _strings(methods.group(1))] if methods else [verb]
        for path in found[:1]:
            out.extend((v, _join(pre, path), pos) for v in verbs)

    for m in _PY_DECO.finditer(text):
        args, _ = _args(text, m.end())
        verb = {"route": "GET", "api_route": "GET", "websocket": "WS"}.get(m.group(2), m.group(2).upper())
        add(verb, args, m.start(), prefix.get(m.group(1), ""))
    for m in _PY_ADD.finditer(text):
        add("GET", _args(text, m.end())[0], m.start())
    if "urlpatterns" in text:
        for m in _DJANGO.finditer(text):
            args, _ = _args(text, m.end())
            if "include(" not in args:
                for s in _strings(args)[:1]:
                    out.append(("ANY", _join("", s.lstrip("^").rstrip("$")), m.start()))
    return out


# ---- Go ---------------------------------------------------------------------
_GO_ROUTE = re.compile(r"(\w+)\.(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|Any|Handle|HandleFunc|"
                       r"Get|Post|Put|Delete|Patch|All)\s*(?=\()")
_GO_GROUP = re.compile(r"(\w+)\s*:?=\s*(\w+)\.(?:Group|Route|PathPrefix)\s*(?=\()")
_GO_WEB = re.compile(r'net/http|gin-gonic|labstack/echo|gofiber|gorilla/mux|go-chi')


def _go(text: str) -> list[tuple[str, str, int]]:
    # x.Get("key") is a map or cache call far more often than a route. A web kit of one's
    # own copies gin's names, though: several "/path" routes in a file say enough.
    if not _GO_WEB.search(text) and len(re.findall(r'\.(?:GET|POST|PUT|DELETE|PATCH|Any|Handle|HandleFunc)\s*\(\s*"/', text)) < 2:
        return []
    text = _blank_comments(text, _C_COMMENT)
    groups: dict[str, str] = {}
    for m in _GO_GROUP.finditer(text):
        args, _ = _args(text, m.end())
        s = _strings(args)[:1]
        groups[m.group(1)] = _join(groups.get(m.group(2), ""), s[0]) if s else groups.get(m.group(2), "")
    out = []
    for m in _GO_ROUTE.finditer(text):
        args, end = _args(text, m.end())
        first = args.split(",", 1)
        strings = _strings(args)
        verb = m.group(2)
        if verb in ("Handle", "HandleFunc"):
            # gin: Handle("GET", "/x", h)   net/http: HandleFunc("GET /x", h)
            if len(strings) > 1 and strings[0].isupper() and strings[0].isalpha():
                verb, strings = strings[0], strings[1:]
            elif strings and " /" in strings[0]:
                verb, _, path = strings[0].partition(" ")
                strings = [path]
            else:
                methods = re.match(r"\s*\.Methods\(([^)]*)\)", text[end:])
                verb = (_strings(methods.group(1)) or ["ANY"])[0] if methods else "ANY"
        elif verb in ("Any", "All"):
            verb = "ANY"
        # title-case helpers exist on clients and maps too: require "/path", handler
        if not strings or not (strings[0].startswith("/") or strings[0] == "") or len(first) < 2:
            continue
        out.append((verb.upper(), _join(groups.get(m.group(1), ""), strings[0]), m.start()))
    return out


# ---- JavaScript / TypeScript ------------------------------------------------
_JS_WEB = re.compile(r"""['"](?:express|koa|@koa/router|koa-router|fastify|hono|restify|polka|@hapi/hapi|find-my-way)['"/]|\bRouter\s*\(""")
_JS_MAKE = re.compile(r"\b(?:const|let|var)\s+([\w$]+)\s*(?::[^=\n]+)?=\s*(?:await\s+)?(?:new\s+)?(?:[\w$]+\.)?(?:express|Router|fastify|Fastify|Hono|Koa|polka|restify\.createServer|require\([^)]*\))\s*\(")
_JS_ROUTE = re.compile(r"\b(?<![.\w$])([\w$]+)\s*\.\s*(get|post|put|delete|patch|head|options|all)\s*(?=\()")
_JS_CHAIN = re.compile(r"\.route\s*(?=\()")
_JS_USE = re.compile(r"\b(?:app|server|[\w$]*[rR]outer)\s*\.\s*(?:use|register|route)\s*(?=\()")
_JS_PREFIX = re.compile(r"\b(?:const|let|var)\s+([\w$]+)\s*=\s*new\s+Router\s*\(\s*\{[^}]*\bprefix\s*:\s*['\"`]([^'\"`]+)")
_JS_OBJ = re.compile(r"\bmethod\s*:\s*\[?\s*['\"](\w+)['\"]")
_NEST = re.compile(r"@(Get|Post|Put|Delete|Patch|All|Head|Options|Sse)\s*(?=\()")
_NEST_CTRL = re.compile(r"@Controller\s*(?=\()")
_NEXT_VERB = re.compile(r"\bexport\s+(?:async\s+)?(?:function|const)\s+(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b")


def _js(text: str, rel: str = "") -> list[tuple[str, str, int]]:
    text = _blank_comments(text, _C_COMMENT)
    out: list[tuple[str, str, int]] = []
    if _NEST_CTRL.search(text):
        bases = [(m.start(), (_strings(_args(text, m.end())[0]) or [""])[0]) for m in _NEST_CTRL.finditer(text)]
        for m in _NEST.finditer(text):
            own = [b for at, b in bases if at < m.start()]
            args, _ = _args(text, m.end())
            out += [(m.group(1).upper(), _join(own[-1] if own else "", p), m.start()) for p in _strings(args) or [""]]
    if _JS_WEB.search(text):
        prefix = dict(_JS_PREFIX.findall(text))
        # app.use('/api', router) in the same file; across files the agent reads it.
        for m in _JS_USE.finditer(text):
            args, _ = _args(text, m.end())
            s = re.match(r"\s*['\"`](/[^'\"`]*)['\"`]\s*,(.*)", args, re.S)
            if s and (names := re.findall(r"[\w$]+", s.group(2))):
                prefix.setdefault(names[-1], s.group(1))
        made = set(_JS_MAKE.findall(text)) | set(prefix)
        for m in _JS_ROUTE.finditer(text):
            if m.group(1) not in made and not re.fullmatch(r"app|server|fastify|routes?|[\w$]*[rR]outer", m.group(1)):
                continue  # axios.get, map.get
            args, _ = _args(text, m.end())
            s = re.match(r"\s*(?:['\"`]([^'\"`]*)['\"`]|\[([^\]]*)\])\s*,", args)  # app.get('name') reads a setting
            if s:
                paths = [s.group(1)] if s.group(1) is not None else _strings(s.group(2))
                out += [(m.group(2).upper().replace("ALL", "ANY"), _join(prefix.get(m.group(1), ""), p), m.start()) for p in paths]
        for m in _JS_CHAIN.finditer(text):
            args, end = _args(text, m.end())
            s = _strings(args)[:1]
            if not s:
                continue
            if "{" in args and (verbs := _JS_OBJ.findall(args)):  # fastify.route({ method, url, handler })
                url = re.search(r"\b(?:url|path)\s*:\s*['\"`]([^'\"`]+)", args)
                out += [(v.upper(), _join("", url.group(1)), m.start()) for v in verbs if url]
                continue
            while v := re.compile(r"\s*\.(get|post|put|delete|patch|all)\s*(?=\()").match(text, end):
                out.append((v.group(1).upper().replace("ALL", "ANY"), _join("", s[0]), v.start(1)))
                _, end = _args(text, v.end())
    # File-system routes: the path is the endpoint.
    path = "/" + rel
    if m := re.search(r"/app/((?:.*/)?)route\.[cm]?[jt]s$", path):
        where = "/".join(p for p in m.group(1).split("/") if p and not p.startswith(("(", "@")))
        out += [(v.group(1), "/" + where, v.start()) for v in _NEXT_VERB.finditer(text)]
    elif m := re.search(r"/(?:pages|server)/(api/.*?)(?:\.(get|post|put|delete|patch))?\.[cm]?[jt]s$", path):
        if re.search(r"\bexport\s+default\b|module\.exports", text):
            out.append(((m.group(2) or "any").upper(), "/" + re.sub(r"/index$", "", m.group(1)), 0))
    return out


# ---- PHP ----------------------------------------------------------------------
_PHP_ROUTE = re.compile(r"\b(?:Route|\$router|\$route|\$app|\$r|\$group|\$routes)\s*(?:::|->)\s*(get|post|put|patch|delete|options|any|match|rule|resource|apiResource|add|map)\s*(?=\()", re.I)
_PHP_PREFIX = re.compile(r"\b(?:Route|\$router)\s*(?:::|->)\s*(?:prefix|group)\s*(?=\()")
_PHP_ATTR = re.compile(r"#\[\s*Route\s*(?=\()|@Route\s*(?=\()")
_PHP_INPUT = re.compile(r"\$_(?:GET|POST|REQUEST|FILES|COOKIE)\b|php://input")


def _php(text: str, rel: str = "") -> list[tuple[str, str, int]]:
    """Laravel / Lumen / ThinkPHP / Slim routes, Symfony attributes, and plain scripts that read the request."""
    code = _blank_comments(text, re.compile(r'"(?:\\.|[^"\\\n])*"|\'(?:\\.|[^\'\\\n])*\'|/\*(?!\*\s*@Route).*?\*/|//[^\n]*', re.S))
    out, spans = [], []
    # Route::prefix('api')->group(function () { ... }): what is inside gets the prefix.
    for m in _PHP_PREFIX.finditer(code):
        args, end = _args(code, m.end())
        s = [x for x in _strings(args) if not x.startswith(("App\\", "\\"))]
        g = re.compile(r"\s*(?:->\s*\w+\s*\([^()]*\)\s*)*->\s*group\s*(?=\()").match(code, end)
        if s and g:
            _, close = _args(code, g.end())
            spans.append((g.end(), close, s[0]))
    prefix = lambda at: "/".join(x.strip("/") for st, en, x in spans if st <= at < en and x.strip("/"))
    for m in _PHP_ROUTE.finditer(code):
        args, _ = _args(code, m.end())
        s = _strings(args)
        verb = m.group(1).lower()
        if verb == "match" and len(s) >= 1:
            verbs = re.findall(r"['\"](\w+)['\"]", args.split("]", 1)[0])
            path = next((x for x in s if x not in verbs), "")
            verb = "/".join(v.upper() for v in verbs) or "ANY"
        elif verb in ("rule", "add", "map"):
            path = s[0] if s else ""
            verb = next((x.upper() for x in s[1:] if x.upper() in ("GET", "POST", "PUT", "DELETE", "PATCH")), "ANY")
        else:
            path = s[0] if s else ""
            verb = {"any": "ANY", "resource": "ANY", "apiresource": "ANY"}.get(verb, verb.upper())
        if s:
            out.append((verb, "/" + _join(prefix(m.start()), path).lstrip("/"), m.start()))
    for m in _PHP_ATTR.finditer(code):
        args, _ = _args(code, m.end())
        s = _strings(args)
        verbs = re.findall(r"['\"](GET|POST|PUT|DELETE|PATCH)['\"]", args)
        if s and s[0].startswith("/"):
            out.append(("/".join(verbs) or "ANY", s[0], m.start()))
    if not out and rel and (hit := _PHP_INPUT.search(code)):
        # No router: the file is the endpoint.
        out.append(("ANY", "/" + rel, hit.start()))
    return out


_EXTRACT = {".java": _java, ".kt": _java, ".py": _py, ".go": _go}
_JS_EXT = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts", ".jsx", ".tsx")


def scan(root: str, limit_files: int = 20000) -> dict:
    """{endpoints, files, truncated}."""
    p = pathlib.Path(root)
    out, seen, truncated = [], 0, False
    test = testcode.skip(root)
    for f in _walk(p) if p.is_dir() else ([p] if p.is_file() else []):
        if p.is_dir() and test(f.relative_to(p).as_posix()):
            continue
        extract_file = _EXTRACT.get(f.suffix.lower())
        if f.suffix.lower() in (".php", ".phtml"):
            rel = f.relative_to(p if p.is_dir() else p.parent).as_posix()
            extract_file = lambda text, rel=rel: _php(text, "" if rel.startswith(("vendor/", "routes/")) or "/vendor/" in rel else rel)
        elif f.suffix.lower() in _JS_EXT and not BUILT.search(f.name):
            rel = f.relative_to(p if p.is_dir() else p.parent).as_posix()
            extract_file = lambda text, rel=rel: _js(text, rel)
        if not extract_file:
            continue
        if seen >= limit_files:
            truncated = True
            break
        seen += 1
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        starts = [0] + [m.end() for m in re.finditer("\n", text)]
        base = p if p.is_dir() else p.parent
        for method, route, pos in sorted(set(extract_file(text)), key=lambda x: x[2]):
            out.append({
                "method": method,
                "path": route,
                "file": f.relative_to(base).as_posix(),
                "line": bisect.bisect_right(starts, pos),
                "features": infer_features(route),
            })
    return {"endpoints": out, "files": seen, "truncated": truncated}


_CACHE: dict[str, tuple[float, list]] = {}


def cached(root: str, max_age: float = 120) -> list[dict]:
    at, rows = _CACHE.get(root, (0, None))
    if rows is None or time.monotonic() - at > max_age:
        rows = extract(root)
        _CACHE[root] = (time.monotonic(), rows)
    return rows


def extract(root: str) -> list[dict]:
    return scan(root)["endpoints"]
