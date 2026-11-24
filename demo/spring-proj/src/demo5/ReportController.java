package demo5;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

// FIXTURE ONLY - intentionally vulnerable.
public class ReportController {
    private final JdbcTemplate jdbc;

    public ReportController(JdbcTemplate jdbc) {
        this.jdbc = jdbc;
    }

    @GetMapping("/report/export")
    public Object search(HttpServletRequest req) {
        String name = req.getParameter("name");
        return jdbc.queryForList("SELECT * FROM t WHERE name = '" + name + "'");
    }

    @PostMapping("/admin/users/import")
    public Object upload(HttpServletRequest req) {
        return jdbc.update("UPDATE t SET v = '" + req.getParameter("v") + "'");
    }
}
