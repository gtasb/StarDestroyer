package demo4;

public class Terminal {
    public void run(String cmd) {
        try {
            Runtime.getRuntime().exec(cmd);
        } catch (Exception ignored) {
        }
    }
}
