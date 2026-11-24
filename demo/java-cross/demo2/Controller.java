package demo2;

import jakarta.servlet.http.HttpServletRequest;

public class Controller {
    private final Helper helper = new Helper();

    public void go(HttpServletRequest req) throws Exception {
        String id = req.getParameter("id");
        helper.run(id);
    }
}
