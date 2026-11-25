"""The console must not be drivable from another web page, and no request field
may reach a shell or escape its directory.

Offline. Runs against the real app in-process; state goes to a temp directory.
"""

import os
import pathlib
import re
import sys
import tempfile

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
__import__("os").environ["SCA_OSV"] = "0"  # offline

HOME = tempfile.mkdtemp(prefix="sd-home-")
os.environ["USERPROFILE"] = os.environ["HOME"] = HOME  # settings live under home

from fastapi.testclient import TestClient

import _env  # noqa: F401
from core import asset_graph, config, jobs, pipeline, projects, toolset
from core.engines import tabby
from web import server

FAILED: list[str] = []
BASE = "http://127.0.0.1:8770"


def check(name: str, ok: bool, detail="") -> None:
    print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        FAILED.append(name)


def browser_gates() -> None:
    c = TestClient(server.app, base_url=BASE)
    tok = {"X-SD-Token": server.TOKEN}
    page = c.get("/")
    got = re.search(r'name="sd-token" content="([^"]+)"', page.text)
    check("page carries the token", got and got.group(1) == server.TOKEN)
    check("page cannot be framed or cached", page.headers["x-frame-options"] == "DENY"
          and page.headers["cache-control"] == "no-store")

    def code(method="GET", path="/api/projects", **h):
        return c.request(method, path, headers=h).status_code
    check("own page is served", code(**tok) == 200 and code(
        **tok, Origin=BASE, **{"Sec-Fetch-Site": "same-origin"}) == 200)
    check("localhost is served", TestClient(server.app, base_url="http://localhost:8770").get(
        "/api/projects", headers={**tok, "Origin": "http://localhost:8770"}).status_code == 200)
    check("no token is refused", code() == 403)
    check("wrong token is refused", code(**{"X-SD-Token": "x"}) == 403)
    check("non-ascii token is refused, not a crash",
          c.get("/api/projects", headers=[(b"x-sd-token", b"\xff\xfe")]).status_code == 403)
    for host in ("evil.example", "127.0.0.1.evil.example", "evil.example:8770", "localhost@evil.example",
                 "[::1", "", "2130706433"):
        for path in ("/", "/api/projects"):
            check(f"Host {host!r} is refused on {path}", code(path=path, Host=host, **tok) == 403)
    for origin in ("http://evil.example", "null", "https://127.0.0.1:8770", "http://127.0.0.1:9999"):
        check(f"Origin {origin} is refused", code(**tok, Origin=origin) == 403)
    for site in ("cross-site", "same-site"):
        check(f"Sec-Fetch-Site {site} is refused", code(**tok, **{"Sec-Fetch-Site": site}) == 403)

    open_routes = []
    for r in server.app.routes:
        for m in getattr(r, "methods", None) or ():
            p = re.sub(r"\{\w+\}", "x", r.path)
            if p.startswith("/api/") and c.request(m, p).status_code != 403:
                open_routes.append(p)
    check("every route but the page needs the token", not open_routes, open_routes)
    csp = page.headers["content-security-policy"]
    check("no inline or foreign script can run", "script-src 'self';" in csp and "'unsafe" not in csp, csp)
    static = "".join(f.read_text(encoding="utf-8") for f in (ROOT / "web" / "static").glob("*.js"))
    check("the console never parses HTML from data",
          not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write|\beval\(", static.replace("there is no innerHTML", "")))
    check("settings cannot be written cross-site",
          c.post("/api/settings", json={"values": {"OPENGREP_BIN": "x.exe"}},
                 headers={**tok, "Origin": "http://evil.example"}).status_code == 403
          and not config.CONFIG_FILE.exists())


def command_line(tmp: pathlib.Path) -> None:
    for heap in ("1m & echo x", "4g\n", "4g -version", "", "g", "-1g", "0g", "9999999g", '4g"', None):
        check(f"heap {heap!r} is refused", tabby.invalid_options(heap, "gadget") is not None)
    check("normal heap passes", not any(tabby.invalid_options(h, "web") for h in ("4g", "512m", "16G")))
    check("mode cannot inject a setting", tabby.invalid_options("4g", "web\nx = y") is not None)
    available, tabby.available = tabby.available, lambda: True  # else "not installed" masks the check
    built, tabby.submit_build = tabby.submit_build, lambda *a, **k: sys.exit("build must not start")
    for kw in ({"heap": "1m & echo x"}, {"mode": "evil"}):
        r = pipeline.tabby_audit(__file__, workdir=str(tmp / "w"), **kw)
        check(f"audit refuses {kw} before touching disk",
              r["ok"] is False and next(iter(kw)) in r["error"] and not (tmp / "w").exists(), r)
    tabby.available, tabby.submit_build = available, built
    check("empty jar path is refused", pipeline.tabby_audit("")["ok"] is False)
    check("build command is an argv list", isinstance(tabby.build_command("4g"), list))

    # no spaces: a quoted argument would be safe even under a shell
    marker = pathlib.Path(tempfile.gettempdir()) / f"sd-pwned-{os.getpid()}.txt"
    j = jobs.submit([sys.executable, "-c", "import sys; print(sys.argv[1]); print('错误', file=sys.stderr)",
                     f"a&echo.x>{marker}"], label="标签 😀")["job_id"]
    st = jobs.wait(j, 30)
    check("argv metacharacters are data", st["exit"] == "0" and not marker.exists()
          and any(str(marker) in x for x in st["tail"]), st)
    check("label survives non-ascii", st["label"] == "标签 😀", st["label"])
    st = jobs.wait(jobs.submit("echo HELLO_OUT && echo HELLO_ERR 1>&2")["job_id"], 30)
    check("shell job output is captured", "HELLO_OUT" in " ".join(st["tail"])
          and "HELLO_ERR" in " ".join(st["tail"]), st)
    st = jobs.wait(jobs.submit(["no-such-program-xyz"])["job_id"], 30)
    check("a job that cannot start ends as failed", st["state"] == "done" and st["exit"] != "0" and st["tail"], st)
    st = jobs.wait(jobs.submit([sys.executable, "-V"], cwd=str(tmp / "missing"))["job_id"], 30)
    check("a bad cwd ends as failed", st["state"] == "done" and st["exit"] != "0", st)


def paths(tmp: pathlib.Path) -> None:
    root = tmp / "proj"
    (root / "src").mkdir(parents=True)
    (root / "src" / "A.java").write_text("class A {}", encoding="utf-8")
    (tmp / "proj-secret").mkdir()
    (tmp / "proj-secret" / "s.txt").write_text("SECRET", encoding="utf-8")
    ok = lambda p: projects.read_source(str(root), p)["ok"]
    check("relative and absolute paths inside the project are read",
          ok("src/A.java") and ok("src\\A.java") and ok(str(root.resolve() / "src" / "A.java")))
    (root / "lib" / "x").mkdir(parents=True)
    (root / "lib" / "x" / "B.java").write_text("class B {}", encoding="utf-8")
    (root / "lib" / "A.java").write_text("class A2 {}", encoding="utf-8")
    check("a file named without its directories is found if there is only one", projects.read_source(str(root), "B.java").get("path") == "lib/x/B.java" and ok("x/B.java")
          and not ok("A.java") and not ok("y/B.java") and not ok("s.txt") and not ok("C.java"))
    for p in ("../proj-secret/s.txt", str(tmp.resolve() / "proj-secret" / "s.txt"), "C:/Windows/win.ini",
              "/Windows/win.ini", "src/../../proj-secret/s.txt"):
        check(f"{p!r} is out of bounds", not ok(p))

    touched, real = [], pathlib.Path.resolve

    def spy(self, *a, **k):
        touched.append(str(self))
        return real(self, *a, **k)
    pathlib.Path.resolve = spy
    try:
        for p in ("//127.0.0.1/nosuch/x", "\\\\127.0.0.1\\nosuch\\x", "\\\\?\\UNC\\127.0.0.1\\nosuch\\x"):
            check(f"UNC {p!r} is refused", not ok(p))
            r = toolset.asset_graph_summary(p + ".db")
            check(f"graph at UNC {p!r} is refused", r.get("ok") is False, r)
    finally:
        pathlib.Path.resolve = real
    check("UNC paths are never resolved", not [t for t in touched if "nosuch" in t], touched)

    asset_graph.DB_DIR = tmp / "graphs"
    asset_graph.DB_DIR.mkdir()
    outside, inside = tmp / "new" / "x.db", asset_graph.DB_DIR / "none.db"
    victim = tmp / "victim.db"
    victim.write_bytes(b"")
    for p in (outside, inside, victim, asset_graph.DB_DIR / ".." / "victim.db", asset_graph.DB_DIR, ""):
        check(f"graph {pathlib.Path(p).name!r} is refused", toolset.asset_graph_summary(str(p)).get("ok") is False)
    check("a refused graph creates and writes nothing",
          not outside.parent.exists() and not inside.exists() and victim.stat().st_size == 0)
    put = tmp / "app"
    put.mkdir()
    built = asset_graph.build(str(put), lookup_cves=False)
    check("a real graph still opens", toolset.asset_graph_summary(built["db"])["counts"]["App"] == 1)

    (tmp / "out").mkdir()
    (tmp / "out" / "log").write_text("SECRET", encoding="utf-8")
    saved, jobs.JOBS_DIR = jobs.JOBS_DIR, tmp / "jobs"
    for jid in ("../out", "..\\out", str(tmp / "out"), "abc", "ABCDEF12", "0000000g"):
        st = jobs.status(jid)
        check(f"job id {jid[-12:]!r} is refused", st["state"] == "unknown" and "tail" not in st, st)
    jobs.JOBS_DIR = saved


def main() -> int:
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as d:
        tmp = pathlib.Path(d)
        projects.STORE = tmp / "store"
        jobs.JOBS_DIR = tmp / "jobs"
        jobs.JOBS_DIR.mkdir()
        for fn, args in ((browser_gates, ()), (command_line, (tmp,)), (paths, (tmp,))):
            print(f"-- {fn.__name__}")
            fn(*args)
    print("FAILED: " + ", ".join(FAILED) if FAILED else "ALL PASS")
    return 1 if FAILED else 0


if __name__ == "__main__":
    raise SystemExit(main())
