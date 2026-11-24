package demo3;

public class SafeServiceImpl implements Service {
    @Override
    public void handle(String q) {
        System.out.println("ignored");
    }
}
