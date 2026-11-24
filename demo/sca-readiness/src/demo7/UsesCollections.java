package demo7;

import org.apache.commons.collections.Transformer;
import org.apache.commons.collections.functors.InvokerTransformer;

/**
 * FIXTURE ONLY: declares a dependency with a known deserialization CVE and
 * actually uses a class from it, so a reading agent has something to find.
 */
public class UsesCollections {
    public Transformer transformer() {
        return new InvokerTransformer("exec", new Class[]{String.class}, new Object[]{"id"});
    }
}
