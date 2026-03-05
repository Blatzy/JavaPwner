package lab.rmi;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Vulnerable Java RMI server — Java 8u202, JEP290 present but DGC filter unconfigured.
 *
 * This server does NOT configure sun.rmi.transport.dgcFilter (property absent → null).
 * On Java 8u202 (JEP290 property-configurable era, 8u121-8u231):
 *   - DGCImpl.dgcFilter field EXISTS (introduced in 8u121)
 *   - BUT the field value is null because no system property was set
 *   - DGCImpl.checkInput() skips filter when dgcFilter == null
 *   - Result: DGC channel fully open — exploitable without any bypass
 *
 * This models a deployment in the JEP290 era where an admin never configured
 * the DGC filter property, leaving it null even though the JVM supports it.
 * Contrast with:
 *   - pre-JEP290 (8u112): dgcFilter FIELD does not exist at all
 *   - java8 LTS (8u482): reflection bypass installs AllowAll filter
 *   - java11+: Unsafe.putObjectVolatile bypass required
 *
 * Exported objects:
 *   HelloService  → port from RMI_HELLO_PORT env (default 1598)
 *   DataService   → port from RMI_DATA_PORT  env (default 1597)
 *   Registry      → port from RMI_REGISTRY_PORT env (default 1599)
 *
 * CommonsCollections 3.1 is in the classpath, making the DGC channel
 * exploitable via ysoserial CommonsCollections gadgets.
 *
 * Attack surface:
 *   javapwner rmi scan 127.0.0.1 -p 1599
 *   javapwner rmi exploit 127.0.0.1 -p 1599 --gadget CommonsCollections6 --cmd '...'
 */
public class RmiServer {

    public static void main(String[] args) throws Exception {
        // Ports configurable via env (supports docker-compose environment section)
        int registryPort = parsePort(System.getenv("RMI_REGISTRY_PORT"), 1599);
        int helloPort    = parsePort(System.getenv("RMI_HELLO_PORT"),    1598);
        int dataPort     = parsePort(System.getenv("RMI_DATA_PORT"),     1597);

        String hostname = System.getenv("RMI_HOSTNAME");
        if (hostname == null || hostname.isEmpty()) {
            hostname = "127.0.0.1";
        }
        System.setProperty("java.rmi.server.hostname", hostname);

        System.out.println("[RMI-JEP290-PROP] ================================================");
        System.out.println("[RMI-JEP290-PROP]  Vulnerable RMI Registry — Java 8u202 Lab Target");
        System.out.println("[RMI-JEP290-PROP] ================================================");
        System.out.println("[RMI-JEP290-PROP]  Java version : " + System.getProperty("java.version"));
        System.out.println("[RMI-JEP290-PROP]  Hostname     : " + hostname);
        System.out.println("[RMI-JEP290-PROP]  JEP290 era   : property-configurable (8u121-8u231)");

        // DGC filter: null (property never set — field exists but is null)
        String dgcFilter = System.getProperty("sun.rmi.transport.dgcFilter", "<null — not configured>");
        System.out.println("[RMI-JEP290-PROP]  dgcFilter    : " + dgcFilter);
        System.out.println("[RMI-JEP290-PROP]  Bypass       : AllowAll DGC filter via reflection");

        // Confirm CommonsCollections presence (gadgets need this)
        try {
            Class.forName("org.apache.commons.collections.Transformer");
            System.out.println("[RMI-JEP290-PROP]  commons-collections 3.1 found (gadgets enabled)");
        } catch (ClassNotFoundException e) {
            System.out.println("[RMI-JEP290-PROP]  WARNING: commons-collections not found in classpath!");
        }

        // Create registry and export objects
        Registry registry = LocateRegistry.createRegistry(registryPort);

        // Disable DGC filter via reflection — same bypass as java8 LTS lab.
        // On 8u202, DGCImpl includes a hardcoded allow-list (backported via 8u191)
        // that rejects non-RMI classes. We replace it with AllowAll.
        disableDgcFilter();

        HelloServiceImpl hello = new HelloServiceImpl(helloPort);
        DataServiceImpl  data  = new DataServiceImpl(dataPort);

        registry.bind("HelloService", hello);
        registry.bind("DataService",  data);

        System.out.println("[RMI-JEP290-PROP]  Registry on port " + registryPort);
        System.out.println("[RMI-JEP290-PROP]  HelloService on port " + helloPort);
        System.out.println("[RMI-JEP290-PROP]  DataService  on port " + dataPort);
        System.out.println("[RMI-JEP290-PROP] ================================================");
        System.out.println("[RMI-JEP290-PROP]  Ready — DGC AllowAll bypass active");
        System.out.println("[RMI-JEP290-PROP] ================================================");

        // Block forever
        Object lock = new Object();
        synchronized (lock) {
            lock.wait();
        }
    }

    /**
     * Replace DGCImpl.dgcFilter with an AllowAll implementation via reflection.
     * Works on Java 8u121+ (JEP290 era). Uses sun.misc.ObjectInputFilter (Java 8 API).
     */
    @SuppressWarnings("unchecked")
    private static void disableDgcFilter() {
        try {
            Class<?> dgcImplClass = Class.forName("sun.rmi.transport.DGCImpl");
            Field dgcFilterField = dgcImplClass.getDeclaredField("dgcFilter");
            dgcFilterField.setAccessible(true);
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(dgcFilterField,
                    dgcFilterField.getModifiers() & ~Modifier.FINAL);
            sun.misc.ObjectInputFilter allowAll =
                    info -> sun.misc.ObjectInputFilter.Status.ALLOWED;
            dgcFilterField.set(null, allowAll);
            System.out.println("[RMI-JEP290-PROP]  DGC filter : DISABLED (AllowAll via reflection)");
        } catch (NoSuchFieldException e) {
            System.out.println("[RMI-JEP290-PROP]  DGC filter : absent (pre-JEP290 JVM)");
        } catch (Exception e) {
            System.out.println("[RMI-JEP290-PROP]  DGC filter : bypass failed — " + e);
        }
    }

    private static int parsePort(String envVal, int defaultPort) {
        if (envVal != null && !envVal.isEmpty()) {
            try {
                return Integer.parseInt(envVal.trim());
            } catch (NumberFormatException ignored) {
            }
        }
        return defaultPort;
    }
}
