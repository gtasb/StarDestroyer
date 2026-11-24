package demo3;

public class Controller {
    private final Service service;

    public Controller(Service service) {
        this.service = service;
    }

    public void go(Req req) throws Exception {
        String id = req.getParameter("id");
        service.handle(id);
    }
}
