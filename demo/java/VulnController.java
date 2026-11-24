// 审计引擎验收用的靶子：故意保留漏洞，不要在生产使用。
// FIXTURE ONLY - intentionally vulnerable.
package demo;

import jakarta.servlet.http.HttpServletRequest;
import java.sql.Statement;
import java.sql.Connection;

public class VulnController {
    private final Connection conn;

    public VulnController(Connection conn) {
        this.conn = conn;
    }

    // 期望：java-sqli-jdbc-statement，链完整
    public void search(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        String sql = "SELECT * FROM users WHERE name = '" + name + "'";
        Statement st = conn.createStatement();
        st.executeQuery(sql);
    }

    // 期望：java-sqli-jdbc-statement，经本地辅助方法（跨函数）
    public void searchByHelper(HttpServletRequest req) throws Exception {
        String raw = req.getParameter("q");
        run(raw);
    }

    private void run(String q) throws Exception {
        StringBuilder sb = new StringBuilder("SELECT * FROM t WHERE id = ");
        sb.append(q);
        conn.createStatement().execute(sb.toString());
    }

    // 期望：java-cmd-injection-runtime-exec
    public void ping(HttpServletRequest req) throws Exception {
        String host = req.getParameter("host");
        Runtime.getRuntime().exec("ping -c 1 " + host);
    }

    // 期望：干净——用了 prepareStatement 净化
    public void safe(HttpServletRequest req) throws Exception {
        String name = req.getParameter("name");
        conn.prepareStatement("SELECT * FROM users WHERE name = ?");
    }
}
