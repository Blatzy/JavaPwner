package lab.rmi;

import java.lang.reflect.Field;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Vulnerable Java RMI server — Java 21 variant.
 *
 * Exported objects:
 *   HelloService  → RMI_HELLO_PORT    (default 1398)
 *   DataService   → RMI_DATA_PORT     (default 1397)
 *   Registry      → RMI_REGISTRY_PORT (default 1399)
 *
 * CommonsCollections 3.1 is in the classpath, making the DGC channel
 * exploitable via ysoserial CommonsCollections gadgets.
 *
 * DGC filter bypass uses sun.misc.Unsafe to overwrite the static final
 * dgcFilter field in DGCImpl — compatible with Java 21–21.
 * Requires --add-opens java.rmi/sun.rmi.transport=ALL-UNNAMED
 *           --add-opens java.base/sun.misc=ALL-UNNAMED
 *
 * Attack surface:
 *   javapwner rmi scan 127.0.0.1 -p 1399
 *   javapwner rmi exploit 127.0.0.1 -p 1399 --gadget CommonsCollections6 --cmd '...'
 */
public class RmiServer {

    public static void main(String[] args) throws Exception {
        int registryPort = getEnvInt("RMI_REGISTRY_PORT", 1399);
        int helloPort    = getEnvInt("RMI_HELLO_PORT",    1398);
        int dataPort     = getEnvInt("RMI_DATA_PORT",     1397);

        String hostname = System.getenv("RMI_HOSTNAME");
        if (hostname == null || hostname.isEmpty()) {
            hostname = "127.0.0.1";
        }
        System.setProperty("java.rmi.server.hostname", hostname);

        System.out.println("[RMI-JAVA21] ================================================");
        System.out.println("[RMI-JAVA21]  Vulnerable RMI Registry — Java 21 Lab Target");
        System.out.println("[RMI-JAVA21] ================================================");
        System.out.println("[RMI-JAVA21]  Java version : " + System.getProperty("java.version"));
        System.out.println("[RMI-JAVA21]  Hostname     : " + hostname);
        System.out.println("[RMI-JAVA21]  Registry port: " + registryPort);

        // Confirm CommonsCollections presence (gadgets need this)
        try {
            Class.forName("org.apache.commons.collections.Transformer");
            System.out.println("[RMI-JAVA21]  commons-collections 3.1 found (gadgets enabled)");
        } catch (ClassNotFoundException e) {
            System.out.println("[RMI-JAVA21]  WARNING: commons-collections not found in classpath!");
        }

        // Create registry
        Registry registry = LocateRegistry.createRegistry(registryPort);

        // Disable DGC deserialization filter via Unsafe.
        // Java 9+ removed the Field.modifiers trick; we use sun.misc.Unsafe to
        // directly overwrite the static final dgcFilter field in DGCImpl.
        disableDgcFilterUnsafe();

        // Export objects on fixed ports (required for Docker port mapping)
        HelloServiceImpl hello = new HelloServiceImpl(helloPort);
        DataServiceImpl  data  = new DataServiceImpl(dataPort);

        registry.bind("HelloService", hello);
        registry.bind("DataService",  data);

        System.out.println("[RMI-JAVA21]  HelloService on port " + helloPort);
        System.out.println("[RMI-JAVA21]  DataService  on port " + dataPort);
        System.out.println("[RMI-JAVA21] ================================================");
        System.out.println("[RMI-JAVA21]  Ready — DGC channel open for exploitation");
        System.out.println("[RMI-JAVA21] ================================================");

        // Block forever
        Object lock = new Object();
        synchronized (lock) {
            lock.wait();
        }
    }

    private static int getEnvInt(String name, int defaultVal) {
        String val = System.getenv(name);
        if (val == null || val.isEmpty()) return defaultVal;
        try {
            return Integer.parseInt(val.trim());
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    /**
     * Replace DGCImpl.dgcFilter with an AllowAll implementation via Unsafe.
     *
     * The Field.modifiers trick (used in Java 8) is blocked in Java 9+ because
     * Field.class.getDeclaredField("modifiers") is filtered by the JDK.
     * Unsafe.putObjectVolatile() bypasses the final modifier restriction.
     *
     * Requires --add-opens java.rmi/sun.rmi.transport=ALL-UNNAMED
     *           --add-opens java.base/sun.misc=ALL-UNNAMED
     */
    private static void disableDgcFilterUnsafe() {
        try {
            // Obtain Unsafe instance via reflection (avoiding direct import issues)
            Class<?> unsafeClass = Class.forName("sun.misc.Unsafe");
            Field theUnsafeField = unsafeClass.getDeclaredField("theUnsafe");
            theUnsafeField.setAccessible(true);
            Object unsafe = theUnsafeField.get(null);

            // Get the dgcFilter field of DGCImpl (in unexported package; needs --add-opens)
            Class<?> dgcImplClass = Class.forName("sun.rmi.transport.DGCImpl");
            Field dgcFilterField = dgcImplClass.getDeclaredField("dgcFilter");

            // Compute field offset and base object via Unsafe
            long offset = (long) unsafeClass
                    .getMethod("staticFieldOffset", Field.class)
                    .invoke(unsafe, dgcFilterField);
            Object base = unsafeClass
                    .getMethod("staticFieldBase", Field.class)
                    .invoke(unsafe, dgcFilterField);

            // Install unconditional AllowAll filter using java.io.ObjectInputFilter
            java.io.ObjectInputFilter allowAll = info -> java.io.ObjectInputFilter.Status.ALLOWED;
            unsafeClass
                    .getMethod("putObjectVolatile", Object.class, long.class, Object.class)
                    .invoke(unsafe, base, offset, allowAll);

            System.out.println("[RMI-JAVA21]  DGC filter : DISABLED (AllowAll via Unsafe)");
        } catch (NoSuchFieldException e) {
            // Java < 8u121: no JEP290 filter at all — already fully vulnerable
            System.out.println("[RMI-JAVA21]  DGC filter : absent (pre-JEP290 JVM)");
        } catch (Exception e) {
            System.out.println("[RMI-JAVA21]  DGC filter : bypass failed — " + e);
        }
    }
}
