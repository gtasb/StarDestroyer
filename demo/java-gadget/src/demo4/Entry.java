package demo4;

import java.io.Serializable;

// FIXTURE ONLY - intentionally vulnerable deserialization entrypoint.
public class Entry implements Serializable {
    private static final long serialVersionUID = 1L;

    private Object payload;

    private void readObject(java.io.ObjectInputStream in)
            throws java.io.IOException, ClassNotFoundException {
        in.defaultReadObject();
        new Middle().process(payload);
    }
}
