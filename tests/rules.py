"""Every built-in rule must hit its vulnerable samples and stay quiet on safe ones.

Real engine, offline. A missing engine fails the suite.
"""

import pathlib
import sys
import tempfile

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

import _env  # noqa: F401
from core import ledger, rulebase, rulegen
from core.engines import opengrep

J = "class C {{ Object m({p}) throws Exception {{ {b} }} }}"
P = "from flask import request\n@app.route('/')\ndef f():\n    {}\n"
G = 'package m\nfunc h(w http.ResponseWriter, r *http.Request) {{\n\t{}\n}}\n'
R = "HttpServletRequest r"
JS = "app.get('/x', async (req, res) => {{ {} }});\n"


def js(body):
    return JS.format(body)



def java(body, p=R):
    return J.format(p=p, b=body)


def py(body):
    return P.format(body)


def go(body):
    return G.format(body)


PH = "<?php\n{}\n"
LV = "<?php\nclass C extends Controller {{\n  public function f(Request $request) {{\n    {}\n  }}\n}}\n"


def php(body):
    return PH.format(body)


def lv(body):
    return LV.format(body)


# (rule, must_hit, code)
CASES = [
    ("java-sqli-jdbc-statement", True, java('return st.executeQuery("a"+r.getParameter("x"));')),
    ("java-sqli-jdbc-statement", True, java('return st.executeQuery("a"+r.getParameterValues("x")[0]);')),
    ("java-sqli-jdbc-statement", True, java('return c.prepareStatement("a"+r.getParameter("x"));')),
    ("java-sqli-jdbc-statement", True, java('return st.executeUpdate("a"+r.getParameter("x"), 1);')),
    ("java-sqli-jdbc-statement", True, java('return st.executeQuery("a"+n);', "@RequestParam String n")),
    ("java-sqli-jdbc-statement", True, java('return st.executeQuery("a"+n);', '@PathVariable("n") String n')),
    ("java-sqli-jdbc-statement", True, java('return st.executeQuery("a"+b.getName());', "@RequestBody UserDto b")),
    ("java-sqli-jdbc-statement", False, java('return st.executeQuery("a"+n);', "@RequestParam Integer n")),
    ("java-sqli-jdbc-statement", False, java('return st.executeQuery("a"+n);', "String n")),
    ("java-sqli-jdbc-statement", False, java('return st.executeQuery("a"+Integer.parseInt(r.getParameter("x")));')),
    ("java-sqli-jdbc-statement", False, java(
        'PreparedStatement ps = c.prepareStatement("a=?"); ps.setString(1, r.getParameter("x")); return ps.executeQuery();')),
    ("java-cmd-injection-runtime-exec", True, java('return Runtime.getRuntime().exec(r.getParameter("x"));')),
    ("java-cmd-injection-runtime-exec", True, java('return Runtime.getRuntime().exec(r.getParameter("x"), null);')),
    ("java-cmd-injection-runtime-exec", True, java('return new ProcessBuilder("sh","-c",r.getParameter("x")).start();')),
    ("java-cmd-injection-runtime-exec", False, java('return Runtime.getRuntime().exec("ls");')),
    ("java-spel-injection", True, java('return parser.parseExpression(r.getParameter("x"));')),
    ("java-spel-injection", False, java('return parser.parseExpression("abcd".substring(1));')),
    ("java-ssrf-url-open", True, java('return new URL(r.getParameter("x")).openConnection();')),
    ("java-ssrf-url-open", True, java('URL u = new URL(r.getParameter("x")); return u.openStream();')),
    ("java-ssrf-url-open", True, java('RestTemplate t = new RestTemplate(); return t.getForObject(r.getParameter("x"), String.class);')),
    ("java-deser-objectinputstream", True, java('ObjectInputStream o = new ObjectInputStream(r.getInputStream()); return o.readObject();')),
    ("java-path-traversal", True, java('return new File("/d", r.getParameter("x"));')),
    ("java-path-traversal", False, java('return new File("/d", FilenameUtils.getName(r.getParameter("x")));')),
    ("java-xxe", True, java('DocumentBuilder b = f(); return b.parse(r.getInputStream());')),
    ("java-xss-response-write", True, java('w.getWriter().write(r.getParameter("x")); return 1;', R + ", HttpServletResponse w")),
    ("java-xss-response-write", False, java('w.getWriter().write(HtmlUtils.htmlEscape(r.getParameter("x"))); return 1;', R + ", HttpServletResponse w")),
    ("java-open-redirect", True, java('w.sendRedirect(r.getParameter("x")); return 1;', R + ", HttpServletResponse w")),

    ("py-sqli-cursor-execute", True, py('cur.execute("a" + request.json["x"])')),
    ("py-sqli-cursor-execute", True, py('cur.execute("a" + request.args["x"])')),
    ("py-sqli-cursor-execute", True, py('cur.execute(f"a {request.form.get(1)}")')),
    ("py-sqli-cursor-execute", True, "@router.get('/x')\nasync def f(q: str):\n    cur.execute('a' + q)\n"),
    ("py-sqli-cursor-execute", True, "@app.route('/<n>')\ndef f(n):\n    cur.execute('a' + n)\n"),
    ("py-sqli-cursor-execute", False, "@router.get('/x')\nasync def f(q: int):\n    cur.execute('a' + str(q))\n"),
    ("py-sqli-cursor-execute", False, py('cur.execute("a=%s", (request.args.get("x"),))')),
    ("py-sqli-cursor-execute", False, py('cur.execute("a" + str(int(request.args.get("x"))))')),
    ("py-command-injection", True, py('os.system("ls " + request.form["x"])')),
    ("py-command-injection", True, py('subprocess.check_output("ls " + request.args.get("x"), shell=True)')),
    ("py-command-injection", False, py('subprocess.run(["ls", request.args.get("x")])')),
    ("py-command-injection", False, py('os.system("ls " + shlex.quote(request.args.get("x")))')),
    ("py-code-injection", True, py('eval(request.args.get("x"))')),
    ("py-code-injection", False, py('ast.literal_eval(request.args.get("x"))')),
    ("py-unsafe-deserialization", True, py('pickle.loads(request.get_data())')),
    ("py-unsafe-deserialization", True, py('yaml.load(request.data, Loader=yaml.Loader)')),
    ("py-unsafe-deserialization", False, py('yaml.load(request.data, Loader=yaml.SafeLoader)')),
    ("py-ssrf-requests", True, py('requests.request("GET", request.args.get("x"))')),
    ("py-ssrf-requests", True, py('requests.get(request.args.get("x"))')),
    ("py-ssti", True, py('render_template_string(request.args.get("x"))')),
    ("py-ssti", False, py('render_template("a.html", x=request.args.get("x"))')),
    ("py-path-traversal", True, py('open("/d/" + request.args.get("x"))')),
    ("py-path-traversal", False, py('open("/d/" + secure_filename(request.args.get("x")))')),
    ("py-open-redirect", True, py('redirect(request.args.get("x"))')),

    ("go-sqli-query", True, go('db.Query("a" + r.FormValue("x"))')),
    ("go-sqli-query", True, go('db.QueryContext(ctx, "a" + r.URL.Query().Get("x"))')),
    ("go-sqli-query", True, "package m\nfunc h(c *gin.Context) {\n\tdb.Raw(\"a\" + c.Query(\"x\"))\n}\n"),
    ("go-sqli-query", False, go('db.Query("a=$1", r.FormValue("x"))')),
    ("go-sqli-query", False, "package m\nfunc h(c *gin.Context, r *http.Request) {\n\tc.Query(r.FormValue(\"x\"))\n}\n"),
    ("go-sqli-query", False, go('n, _ := strconv.Atoi(r.FormValue("x"))\n\tdb.Query("a" + strconv.Itoa(n))')),
    ("go-command-injection", True, go('exec.Command("sh", "-c", r.FormValue("x"))')),
    ("go-ssrf-http", True, go('http.NewRequest("GET", r.FormValue("x"), nil)')),
    ("go-ssrf-http", True, go('http.Get(r.FormValue("x"))')),
    ("go-path-traversal", True, go('os.Open("/d/" + r.FormValue("x"))')),
    ("go-path-traversal", False, go('os.Open("/d/" + filepath.Base(r.FormValue("x")))')),
    ("go-open-redirect", True, go('http.Redirect(w, r, r.FormValue("x"), 302)')),
    ("go-ssti", True, go('template.New("x").Parse(r.FormValue("x"))')),

    ("go-sqli-query", True, "package m\nfunc h(c *http.Context) {\n\tdb.Client.Raw(\"a\" + c.Query(\"x\"))\n}\n"),
    ("go-sqli-query", True, "package m\nfunc h(ctx *web.Context) {\n\tdb.Where(\"a=\" + ctx.Param(\"x\"))\n}\n"),
    ("go-sqli-query", False, "package m\nfunc h(c *http.Context) {\n\tdb.Where(\"a=?\", c.Query(\"x\"))\n}\n"),
    ("go-sqli-query", False, "package m\nfunc h(cache *Cache) {\n\tdb.Raw(\"a\" + cache.Query(\"x\"))\n}\n"),

    ("php-sqli-query", True, php("mysqli_query($conn, \"select * from t where id=\" . $_GET['id']);")),
    ("php-sqli-query", True, php("$id = $_POST['id'];\n$pdo->query(\"select * from t where id=$id\");")),
    ("php-sqli-query", True, lv("return DB::select(\"select * from u where n='\" . $request->input('n') . \"'\");")),
    ("php-sqli-query", True, lv("return User::whereRaw('n = ' . $request->get('n'))->get();")),
    ("php-sqli-query", True, php("$x = input('get.x');\nDb::query('select ' . $x);")),
    ("php-sqli-query", True, php("$this->db->query('select ' . $this->input->get('x'));")),
    ("php-sqli-query", False, php("mysqli_query($conn, 'select * from t where id=' . intval($_GET['id']));")),
    ("php-sqli-query", False, php("$s = $pdo->prepare('select * from t where id=?');\n$s->execute([$_GET['id']]);")),
    ("php-sqli-query", False, php("mysqli_query($conn, \"select * from t where n='\" . mysqli_real_escape_string($conn, $_GET['n']) . \"'\");")),
    ("php-sqli-query", False, lv("return DB::select('select * from u where n = ?', [$request->input('n')]);")),
    ("php-command-injection", True, php("system('ping ' . $_GET['h']);")),
    ("php-command-injection", True, php("$o = shell_exec('ls ' . $_REQUEST['d']);")),
    ("php-command-injection", False, php("system('ping ' . escapeshellarg($_GET['h']));")),
    ("php-code-injection", True, php("$f = create_function('', $_POST['code']);")),  # eval / assert are constructs the engine cannot match: sink leads for agents
    ("php-code-injection", True, php("call_user_func($_GET['f'], 1);")),
    ("php-code-injection", False, php("eval('return 1;'); $x = $_GET['f'];")),
    ("php-code-injection-include", True, php("include $_GET['page'] . '.php';")),
    ("php-code-injection-include", True, php("require_once('pages/' . $_GET['p']);")),
    ("php-code-injection-include", False, php("include basename($_GET['page']) . '.php';")),
    ("php-unsafe-deserialization", True, php("$o = unserialize($_COOKIE['s']);")),
    ("php-unsafe-deserialization", True, php("$o = unserialize(base64_decode($_POST['d']));")),
    ("php-ssrf-request", True, php("$h = curl_init($_GET['url']);")),
    ("php-ssrf-request", True, php("$c = curl_init(); curl_setopt($c, CURLOPT_URL, $_GET['url']);")),
    ("php-ssrf-request", True, php("echo_it(file_get_contents($_GET['u']));")),
    ("php-ssrf-request", False, php("$b = file_get_contents('php://input');")),
    ("php-path-traversal", True, php("readfile('/files/' . $_GET['f']);")),
    ("php-path-traversal", True, php("move_uploaded_file($_FILES['f']['tmp_name'], 'up/' . $_FILES['f']['name']);")),
    ("php-path-traversal", True, php("unlink($_POST['f']);")),
    ("php-path-traversal", False, php("readfile('/files/' . basename($_GET['f']));")),
    ("php-xss-echo", True, php("echo $_GET['q'];")),
    ("php-xss-echo", True, php("echo 'hi ' . $_GET['q'];")),
    ("php-xss-echo", True, php("print($_GET['q']);")),
    ("php-xss-echo", False, php("echo htmlspecialchars($_GET['q'], ENT_QUOTES);")),
    ("php-xss-echo", False, php("echo intval($_GET['q']);")),
    ("php-open-redirect", True, php("header('Location: ' . $_GET['next']);")),
    ("php-open-redirect", True, lv("return redirect($request->input('next'));")),
    ("php-open-redirect", False, php("header('Location: /home'); $x = $_GET['next'];")),
    ("php-ssti", True, php("$t = $twig->createTemplate($_POST['tpl']);")),
    ("php-ssti", False, php("echo $twig->render('page.twig', ['q' => $_GET['q']]);")),

    ("js-sqli-query", True, js("db.query('select ' + req.query.x);")),
    ("js-sqli-query", True, js("db.query(`select ${req.body.x}`, cb);")),
    ("js-sqli-query", True, js("const { id } = req.params; await prisma.$queryRawUnsafe('a' + id);")),
    ("js-sqli-query", True, js("knex('t').whereRaw('a=' + req.query.x);")),
    ("js-sqli-query", True, "router.get('/x', async ctx => { db.query('a' + ctx.query.x); });"),
    ("js-sqli-query", True, "@Controller()\nclass C { @Get() f(@Query('x') x: string) { return this.db.query('a' + x); } }"),
    ("js-sqli-query", True, "export async function POST(request: Request) { const b = await request.json(); db.query('a' + b.x); }"),
    ("js-sqli-query", False, js("db.query('select ?', [req.query.x]);")),
    ("js-sqli-query", False, js("db.query('select ' + parseInt(req.query.x));")),
    ("js-sqli-query", False, js("db.query('select 1'); other(req.query.x);")),
    ("js-sqli-query", False, "@Controller()\nclass C { @Get() f(@Query('x') x: number) { return this.db.query('a' + x); } }"),
    ("js-nosql-injection", True, js("User.findOne({ name: req.body.name });")),
    ("js-nosql-injection", False, js("User.findOne({ name: String(req.body.name) });")),
    ("js-command-injection", True, js("exec('ls ' + req.query.x);")),
    ("js-command-injection", True, "const cp = require('child_process');\n" + js("cp.exec(`ls ${req.query.x}`);")),
    ("js-command-injection", True, js("spawn('sh', ['-c', req.query.x]);")),
    ("js-command-injection", False, js("spawn('ls', [req.query.x]);")),
    ("js-command-injection", False, js("/a(b)/.exec(req.query.x);")),
    ("js-code-injection", True, js("eval(req.query.x);")),
    ("js-code-injection", True, js("new Function('a', req.body.code)(1);")),
    ("js-code-injection", False, js("JSON.parse(req.body.x);")),
    ("js-unsafe-deserialization", True, js("serialize.unserialize(req.cookies.p);")),
    ("js-ssrf-request", True, js("await fetch(req.query.url);")),
    ("js-ssrf-request", True, js("const r = await axios.get(req.body.url, {});")),
    ("js-ssrf-request", False, js("const a = request.get('host');")),
    ("js-ssti", True, js("ejs.render(req.query.t, {});")),
    ("js-ssti", False, js("res.render('a', { t: req.query.t });")),
    ("js-path-traversal", True, js("res.sendFile('/d/' + req.params.f);")),
    ("js-path-traversal", True, js("fs.readFileSync(path.join('/d', req.query.f));")),
    ("js-path-traversal", False, js("fs.readFileSync('/d/' + path.basename(req.query.f));")),
    ("js-xss-response", True, js("res.send('<b>' + req.query.x + '</b>');")),
    ("js-xss-response", False, js("res.send(escapeHtml(req.query.x));")),
    ("js-xss-response", False, js("res.json({ a: req.query.x });")),
    ("js-open-redirect", True, js("res.redirect(req.query.u);")),
    ("js-open-redirect", False, js("res.redirect('/home');")),
    ("js-prototype-pollution", True, js("_.merge(conf, req.body);")),
    ("js-dom-xss", True, "document.getElementById('a').innerHTML = location.hash.slice(1);"),
    ("js-dom-xss", True, "const q = new URLSearchParams(location.search).get('q'); document.write(q);"),
    ("js-dom-xss", True, "window.addEventListener('message', (e) => { box.innerHTML = e.data; });"),
    ("js-dom-xss", True, "window.addEventListener('message', function (e) { eval(e.data.code); }, false);"),
    ("js-dom-xss", True, "$('#a').html(window.location.search);"),
    ("js-dom-xss", True, "export default { mounted() { this.$el.innerHTML = this.$route.query.q; } }"),
    ("js-dom-xss", False, "box.innerHTML = DOMPurify.sanitize(location.hash);"),
    ("js-dom-xss", False, "box.textContent = location.hash;"),
    ("js-dom-xss", False, "setTimeout(() => load(location.hash), 10);"),
    ("js-client-redirect", True, "const u = new URLSearchParams(location.search).get('u'); window.location.href = u;"),
    ("js-client-redirect", False, "window.location.href = '/login?u=' + encodeURIComponent(location.href);"),
]
EXT = {"java": ".java", "python": ".py", "go": ".go", "js": ".ts", "php": ".php"}


def main() -> int:
    failed = []

    def check(name, ok, detail=""):
        print(("PASS " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
        if not ok:
            failed.append(name)

    if not opengrep.capabilities().get("available"):
        print("FAIL: opengrep 不可用，本套件不允许跳过")
        return 1
    by_id = {r["id"]: r for r in rulebase.RULES}
    for lang in rulebase.SOURCES:
        path = rulebase.TEMPLATES / f"{lang}-taint.yaml"
        check(f"{lang} template is rendered from rulebase",
              path.read_bytes().decode().replace("\r\n", "\n") == rulebase.builtin(lang))
    untested = set(by_id) - {c[0] for c in CASES if c[1]}
    check("every rule has a vulnerable sample", not untested, untested)
    unclassed = [r["id"] for r in rulebase.RULES
                 if ledger.class_of(r["id"]) not in ledger.CLASSES[r["lang"]]]
    check("every rule maps to a ledger class", not unclassed, unclassed)

    with tempfile.TemporaryDirectory() as d:
        tmp = pathlib.Path(d)
        for i, (rid, _, code) in enumerate(CASES):
            lang = by_id[rid]["lang"]
            f = tmp / lang / f"case{i:03d}" / f"s{EXT[lang]}"
            f.parent.mkdir(parents=True)
            f.write_text(code, encoding="utf-8")
        for lang in rulebase.SOURCES:
            res = opengrep.run_scan(str(tmp / lang), rules=str(rulebase.TEMPLATES / f"{lang}-taint.yaml"))
            check(f"{lang} rules load", res["ok"], res.get("error") or res.get("errors"))
            check(f"{lang} samples parse", not res["errors"], res["errors"][:3])
            hits = {(pathlib.Path(f["file"]).parent.name, f["rule_id"]) for f in res["findings"]}
            for i, (rid, want, code) in enumerate(CASES):
                if by_id[rid]["lang"] == lang:
                    got = (f"case{i:03d}", rid) in hits
                    check(f"{rid} {'hits' if want else 'quiet'} #{i}", got == want,
                          code.strip().replace("\n", " ")[:150])

    for family in rulegen.CATALOG:
        res = rulegen.prove(family)
        check(f"generated rule {family} proves itself", res["ok"], res)
    print("FAILED: " + ", ".join(failed) if failed else "ALL PASS")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
