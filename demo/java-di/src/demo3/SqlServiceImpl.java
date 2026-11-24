package demo3;

import java.sql.Statement;

public class SqlServiceImpl implements Service {
    private final Statement statement;

    public SqlServiceImpl(Statement statement) {
        this.statement = statement;
    }

    @Override
    public void handle(String q) throws Exception {
        statement.execute(q);
    }
}
