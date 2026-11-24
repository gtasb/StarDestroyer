package demo2;

import java.sql.Statement;

public class Helper {
    public void run(String q) throws Exception {
        Statement st = null;
        st.execute(q);
    }
}
