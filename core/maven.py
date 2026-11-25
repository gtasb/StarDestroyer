"""What a Maven project really depends on, worked out from POMs without running Maven.

A version is decided by the parent chain and by imported BOMs, for indirect dependencies
too. A tool that cannot read the parent takes whatever some library happens to declare,
and the result looks complete while being about other versions. So the POMs are fetched:
from the project, the local repository (~/.m2), checkouts beside the project, and Maven
Central. Maven itself is not run -- building somebody's project is running their code.

What cannot be fetched is reported; nothing below it is guessed.
"""

import concurrent.futures
import hashlib
import os
import pathlib
import re
import time
import xml.etree.ElementTree as ET

from . import logging, net, proc, store
from .profile import SKIP_DIRS, _walk

CACHE = pathlib.Path(__file__).resolve().parents[1] / ".work" / "poms"
CENTRAL = "https://repo1.maven.org/maven2"
MAX_POM, MAX_NODES, DEADLINE_S, INDEX_TTL_S = 2_000_000, 3000, 420, 24 * 3600
_SAFE = re.compile(r"[A-Za-z0-9_.\-]+")
_STRENGTH = {"test": 0, "provided": 1, "system": 1, "runtime": 2, "compile": 3}


def remote() -> str:
    """Where public POMs come from, "" when that is off. Coordinates are sent there."""
    v = os.environ.get("SCA_MAVEN") or CENTRAL
    return "" if v == "0" or not re.match(r"https://", v) else v.rstrip("/")


# ---- one POM ------------------------------------------------------------------------
class Pom:
    def __init__(self, text: str, path: str = ""):
        if len(text) > MAX_POM or "<!DOCTYPE" in text or "<!ENTITY" in text:
            raise ValueError("not a plain POM")
        root = ET.fromstring(re.sub(r"^\s*<\?xml[^>]*\?>", "", text))
        for e in root.iter():
            if isinstance(e.tag, str):
                e.tag = e.tag.rsplit("}", 1)[-1]
        if root.tag != "project":
            raise ValueError("not a POM")
        get = lambda el, tag: ((el.findtext(tag) if el is not None else "") or "").strip()
        parent = root.find("parent")
        self.path = path
        self.parent = {"group": get(parent, "groupId"), "artifact": get(parent, "artifactId"), "version": get(parent, "version"),
                       "relative": (parent.findtext("relativePath") if parent.find("relativePath") is not None else "../pom.xml") or ""} if parent is not None else None
        self.artifact, self.group, self.version = get(root, "artifactId"), get(root, "groupId"), get(root, "version")
        self.packaging = get(root, "packaging") or "jar"
        # On by default, or unless some property is given: what a plain build would use.
        parts = [root] + [p for p in root.findall("profiles/profile") if get(p.find("activation"), "activeByDefault") == "true"
                          or get(p.find("activation/property"), "name").startswith("!")]
        self.props, self.mgmt, self.deps = {}, [], []
        for p in parts:
            for e in p.findall("properties/*"):
                if isinstance(e.tag, str):
                    self.props[e.tag] = (e.text or "").strip()
            self.mgmt += [_dep(d, get) for d in p.findall("dependencyManagement/dependencies/dependency")]
            self.deps += [_dep(d, get) for d in p.findall("dependencies/dependency")]


def _dep(d, get) -> dict:
    return {"group": get(d, "groupId"), "artifact": get(d, "artifactId"), "version": get(d, "version"), "scope": get(d, "scope"), "type": get(d, "type") or "jar",
            "classifier": get(d, "classifier"), "optional": get(d, "optional") == "true",
            "exclusions": [(get(e, "groupId") or "*", get(e, "artifactId") or "*") for e in d.findall("exclusions/exclusion")]}


def _fill(text: str, props: dict) -> str:
    for _ in range(8):
        new = re.sub(r"\$\{([^}]+)\}", lambda m: props.get(m[1].strip(), m[0]), text)
        if new == text:
            break
        text = new[:400]
    return text


# ---- where POMs come from -----------------------------------------------------------
class Finder:
    def __init__(self, root: pathlib.Path):
        self.root = root
        self.mine: dict[tuple, list[Pom]] = {}
        self.sources: dict[str, str] = {}
        self._known: dict[tuple, Pom | None] = {}
        self._beside: dict[tuple, str] | None = None
        for f in sorted(_walk(root)) if root.is_dir() else []:
            if f.name == "pom.xml":
                try:
                    p = Pom(f.read_text(encoding="utf-8", errors="replace"), str(f))
                except (OSError, ValueError, ET.ParseError):
                    continue
                self.mine.setdefault((p.group or (p.parent or {}).get("group", ""), p.artifact), []).append(p)
        self.own = {".".join(g.split(".")[:2]) for g, _ in self.mine if g.count(".")} - {"com.github", "io.github", "org.apache", "org.springframework", "com.google", "com.alibaba"}
        m2 = os.environ.get("MAVEN_REPO_LOCAL") or pathlib.Path.home() / ".m2" / "repository"
        self.m2 = pathlib.Path(m2)

    def get(self, group: str, artifact: str, version: str) -> Pom | None:
        key = (group, artifact, version)
        if key not in self._known:
            self._known[key] = self._get(*key)
        return self._known[key]

    def _get(self, group, artifact, version) -> Pom | None:
        for p in self.mine.get((group, artifact), []):
            if version in (p.version, "") or not p.version or "${" in p.version:
                return p
        if not all(_SAFE.fullmatch(x or "") for x in (group, artifact, version)):
            return None
        name = f"{artifact}-{version}.pom"
        rel = pathlib.Path(*group.split("."), artifact, version, name)
        for base, label in ((self.m2, "本地仓库"), (CACHE, "Maven Central")):
            got = self._read(base / rel)
            if got:
                return self._note(got, group, artifact, version, label)
        private = ".".join(group.split(".")[:2]) in self.own
        if not private:
            got = self._fetch(group, artifact, version, name, rel)
            if got:
                return self._note(got, group, artifact, version, "Maven Central")
        near = self._index().get((group, artifact, version))
        got = self._read(pathlib.Path(near)) if near else None
        return self._note(got, group, artifact, version, near) if got else None

    def near(self, group: str, artifact: str) -> Pom | None:
        """Another version of it, from a checkout beside the project: only to know roughly
        what hangs under a private artifact whose own POM is out of reach."""
        if ".".join(group.split(".")[:2]) not in self.own:
            return None
        found = sorted((v, f) for (g, a, v), f in self._index().items() if (g, a) == (group, artifact))
        return self._read(pathlib.Path(found[-1][1])) if found else None

    def _note(self, pom, group, artifact, version, where) -> Pom:
        self.sources[f"{group}:{artifact}:{version}"] = str(where)
        return pom

    @staticmethod
    def _read(f: pathlib.Path) -> Pom | None:
        try:
            return Pom(f.read_text(encoding="utf-8", errors="replace"), str(f))
        except (OSError, ValueError, ET.ParseError):
            return None

    def _fetch(self, group, artifact, version, name, rel) -> Pom | None:
        base = remote()
        missing = CACHE / rel.with_suffix(".none")
        if not base or (missing.exists() and time.time() - missing.stat().st_mtime < INDEX_TTL_S):
            return None
        try:
            raw = net.get_bytes(f"{base}/{group.replace('.', '/')}/{artifact}/{version}/{name}", timeout=20, attempts=2, limit=MAX_POM)
            pom = Pom(raw.decode("utf-8", errors="replace"), str(CACHE / rel))
        except net.NotFound:
            try:
                missing.parent.mkdir(parents=True, exist_ok=True)
                missing.touch()
            except OSError:
                pass
            return None
        except Exception as exc:  # no network is "cannot be fetched", said as such by the caller
            logging.debug("maven", "fetch failed", gav=f"{group}:{artifact}:{version}", error=str(exc)[:160])
            return None
        try:
            (CACHE / rel).parent.mkdir(parents=True, exist_ok=True)
            (CACHE / rel).write_bytes(raw)
        except OSError:
            pass
        return pom

    def _index(self) -> dict[tuple, str]:
        """POMs of checkouts beside the project: where a private parent usually is."""
        if self._beside is None:
            self._beside = {}
            for base in _neighbourhood(self.root):
                for g, a, v, f in _poms_under(base):
                    self._beside.setdefault((g, a, v), f)
        return self._beside


def _neighbourhood(root: pathlib.Path) -> list[pathlib.Path]:
    out = [pathlib.Path(p) for p in os.environ.get("POM_ROOTS", "").split(os.pathsep) if p.strip()]
    home = pathlib.Path.home()
    for base in list(root.parents)[:2]:
        if len(base.parts) < 3 or base in (home, *home.parents) or base.name.lower() in ("desktop", "downloads", "documents", "temp", "tmp"):
            break
        out.append(base)
    return [b for b in dict.fromkeys(out) if not any(o != b and o in b.parents for o in out)]


def _poms_under(base: pathlib.Path) -> list[list[str]]:
    cache = CACHE / f"index-{hashlib.sha256(str(base).encode()).hexdigest()[:16]}.json"
    had = store.read(cache, {})
    if had.get("base") == str(base) and time.time() - had.get("at", 0) < INDEX_TTL_S:
        return had["poms"]
    proc.stage(f"在 {base} 里找私有父 POM")
    out, began, seen, whole = [], time.time(), 0, True
    for here, dirs, files in os.walk(base):
        deep = len(pathlib.Path(here).relative_to(base).parts)
        dirs[:] = [d for d in dirs if d not in SKIP_DIRS and d != "src" and not d.startswith(".")] if deep < 4 else []
        seen += 1
        if seen % 500 == 0:
            proc.check()
        if time.time() - began > 120 or seen > 60_000:
            whole = False
            break
        if "pom.xml" in files:
            f = pathlib.Path(here) / "pom.xml"
            p = Finder._read(f)
            if p:
                up, props = p.parent or {}, p.props
                out.append([_fill(p.group or up.get("group", ""), props), p.artifact, _fill(p.version or up.get("version", ""), props), str(f)])
    if whole:
        try:
            store.write(cache, {"base": str(base), "at": time.time(), "poms": out})
        except OSError:
            pass
    return out


# ---- effective model -------------------------------------------------------------------
class Model:
    """Parent chain applied: identity, managed versions, dependencies."""

    def __init__(self, pom: Pom, finder: Finder, seen=()):
        self.missing: list[str] = []
        chain, here = [pom], pom
        while here.parent and len(chain) < 12:
            up = self._parent(here, finder)
            if up is None or up in chain:
                g = here.parent
                self.missing.append(f"父 POM {g['group']}:{g['artifact']}:{g['version']}")
                break
            chain.append(up)
            here = up
        props: dict = {}
        for p in reversed(chain):
            props.update(p.props)
        up = pom.parent or {}
        self.group = _fill(next((p.group for p in chain if p.group), "") or up.get("group", ""), props)
        self.version = _fill(next((p.version for p in chain if p.version), "") or up.get("version", ""), props)
        self.artifact = pom.artifact
        for k, v in (("groupId", self.group), ("version", self.version), ("artifactId", self.artifact), ("parent.version", up.get("version", "")), ("parent.groupId", up.get("group", ""))):
            props[f"project.{k}"] = props[f"pom.{k}"] = v
        props.setdefault("version", self.version)
        self.props = props
        full = lambda d: {**d, **{k: _fill(d[k], props) for k in ("group", "artifact", "version", "scope", "type", "classifier")}}
        self.mgmt: dict[tuple, dict] = {}
        imports = []
        for p in chain:
            for d in map(full, p.mgmt):
                if d["scope"] == "import" and d["type"] == "pom":
                    imports.append(d)
                else:
                    self.mgmt.setdefault((d["group"], d["artifact"], d["type"], d["classifier"]), d)
        for d in imports:
            gav = (d["group"], d["artifact"], d["version"])
            bom = finder.get(*gav) if gav not in seen and len(seen) < 12 else None
            if bom is None:
                self.missing.append(f"BOM {':'.join(gav)}")
                continue
            m = model(bom, finder, (*seen, gav))
            self.missing += m.missing
            for k, v in m.mgmt.items():
                self.mgmt.setdefault(k, v)
        self.deps, have = [], set()
        for p in chain:
            for d in map(full, p.deps):
                k = (d["group"], d["artifact"], d["type"], d["classifier"])
                if k not in have:
                    have.add(k)
                    self.deps.append(d)
        self.missing = list(dict.fromkeys(self.missing))

    @staticmethod
    def _parent(pom: Pom, finder: Finder) -> Pom | None:
        want = pom.parent
        if want["relative"] and pom.path and not pom.path.startswith(str(CACHE)) and not pom.path.startswith(str(finder.m2)):
            f = pathlib.Path(os.path.normpath(os.path.join(os.path.dirname(pom.path), want["relative"])))
            f = f / "pom.xml" if not f.suffix else f
            for p in finder.mine.get((want["group"], want["artifact"]), []):
                if os.path.normcase(p.path) == os.path.normcase(str(f)):
                    return p
            # Outside the project only where the file really is that parent.
            if f.is_file():
                p = Finder._read(f)
                if p and p.artifact == want["artifact"] and want["version"] in (p.version, (p.parent or {}).get("version")):
                    return p
        return finder.get(want["group"], want["artifact"], _fill(want["version"], pom.props))


def model(pom: Pom, finder: Finder, seen=()) -> Model:
    cache = finder.__dict__.setdefault("_models", {})
    if id(pom) not in cache:
        cache[id(pom)] = (Model(pom, finder, seen), pom)  # the pom is kept so its id stays its own
    return cache[id(pom)][0]


# ---- the tree ---------------------------------------------------------------------------
def _scope(above: str, own: str) -> str:
    """Scope of a dependency reached through one of scope `above`; "" when it is left out."""
    own = own or "compile"
    if own in ("test", "provided", "system", "import"):
        return ""
    return above if above in ("test", "provided") else "runtime" if "runtime" in (above, own) else "compile"


def resolve(root: str) -> dict | None:
    """Components of every module, or None when this is not a Maven project."""
    base = pathlib.Path(root).resolve()
    finder = Finder(base)
    if not finder.mine:
        return None
    began = time.time()
    modules = [p for ps in finder.mine.values() for p in ps]
    own = {}
    for p in modules:
        m = model(p, finder)
        own[(m.group, m.artifact)] = p
    comps: dict[tuple, dict] = {}
    missing: dict[str, set] = {}
    unversioned: dict[tuple, dict] = {}
    complete = True
    for n, pom in enumerate(modules, 1):
        m = model(pom, finder)
        rel = pathlib.Path(pom.path).relative_to(base).as_posix()
        for x in m.missing:
            missing.setdefault(x, set()).add(rel)
        if pom.packaging == "pom" and len(modules) > 1:
            continue
        proc.stage(f"还原依赖树 {n}/{len(modules)}：{rel}")
        complete &= _tree(m, finder, own, rel, comps, unversioned, missing, began + DEADLINE_S)
    return {"components": list(comps.values()), "unversioned": list(unversioned.values()), "complete": complete and not missing and not unversioned,
            "missing": [{"what": k, "modules": sorted(v)} for k, v in sorted(missing.items())], "sources": finder.sources, "timed_out": not complete, "modules": len(modules)}


def _tree(top: Model, finder: Finder, own: dict, rel: str, comps: dict, unversioned: dict, missing: dict, deadline: float) -> bool:
    taken: set[tuple] = set()
    level = [(d, 1, d["scope"], frozenset(), "") for d in top.deps]
    count = 0
    while level:
        proc.check()
        if time.time() > deadline or count > MAX_NODES:
            return False
        todo = []
        for d, depth, above, cut, via in level:
            ga = (d["group"], d["artifact"])
            slot = (*ga, d["type"], d["classifier"])
            if any(g in ("*", ga[0]) and a in ("*", ga[1]) for g, a in cut):
                continue
            managed = top.mgmt.get(slot)
            version = d["version"] if depth == 1 and d["version"] else (managed or {}).get("version") or d["version"]
            scope = (d["scope"] or (managed or {}).get("scope") or "compile") if depth == 1 else above
            cut = cut | set(d["exclusions"]) | set((managed or {}).get("exclusions") or [])
            if slot in taken:
                continue
            taken.add(slot)
            count += 1
            mod = own.get(ga)
            where = f"{via} > {ga[1]}" if via else ga[1]
            if mod is None:
                # With the parent out of reach, what it would have said about this one is unknown.
                _add(comps, unversioned, ga, version, scope, depth, rel, where, bool(top.missing) and depth > 1 and not managed)
            todo.append((d, mod, ga, version, scope, depth, cut, where))
        ready = [x for x in todo if x[1] is not None or (x[3] and "${" not in x[3] and not re.search(r"[\[(,]", x[3]))]
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            poms = list(pool.map(lambda x: x[1] or finder.get(*x[2], x[3]), ready)) if ready else []
        nxt = []
        for (d, mod, ga, version, scope, depth, cut, where), pom in zip(ready, poms):
            if pom is None:
                pom = finder.near(*ga) if scope != "test" else None
                like = model(pom, finder).version if pom else ""
                if like != version and scope != "test" and d["type"] not in ("zip", "tar.gz"):
                    missing.setdefault(f"依赖树 {ga[0]}:{ga[1]}:{version}" + (f"（按相邻的 {like} 推测）" if like else ""), set()).add(rel)
                if not pom:
                    continue
                where += f"（按 {like} 推测）" if like != version else ""
            m = model(pom, finder)
            for k in m.deps:
                km = m.mgmt.get((k["group"], k["artifact"], k["type"], k["classifier"])) or {}
                s = _scope(scope, k["scope"] or km.get("scope"))
                if s and not k["optional"]:
                    nxt.append(({**k, "version": k["version"] or km.get("version", "")}, depth + 1, s, cut, where))
            for x in m.missing:
                # A library's own broken parent matters only if it left a version open.
                if any(not (k["version"] or (top.mgmt.get((k["group"], k["artifact"], k["type"], k["classifier"])) or {}).get("version")) for k in m.deps) and scope != "test":
                    missing.setdefault(x, set()).add(rel)
        level = nxt
    return True


def _add(comps, unversioned, ga, version, scope, depth, rel, where, shaky=False) -> None:
    if not version or "${" in version or re.search(r"[\[(,]", version):
        unversioned.setdefault(ga, {"vendor": ga[0], "name": ga[1], "version": "", "language": "Java", "direct": depth == 1, "paths": [rel], "scope": scope, "via": where})
        return
    got = comps.setdefault((*ga, version), {"vendor": ga[0], "name": ga[1], "version": version, "language": "Java", "direct": False, "paths": [], "scope": scope, "via": where})
    got["direct"] |= depth == 1
    if rel not in got["paths"]:
        got["paths"].append(rel)
    if "推测）" not in where and not shaky:
        got.pop("guessed", None)
        got["sure"] = True
    elif not got.get("sure"):
        got["guessed"] = True
    if _STRENGTH.get(scope, 3) > _STRENGTH.get(got["scope"], 3):
        got["scope"], got["via"] = scope, where
