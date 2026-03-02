package lab.rmi;

import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Vulnerable Java RMI server — Java 8u202, JEP290 opened via system property.
 *
 * This server does NOT use reflection to disable the DGC filter.
 * The filter is opened exclusively via the system property:
 *
 *   -Dsun.rmi.transport.dgcFilter=*;maxdepth=100;maxrefs=10000;maxbytes=10000000
 *
 * On Java 8u202 (JEP290 property-configurable era, 8u121-8u231), this property
 * causes the DGC filter to return ALLOWED for ALL class and stats checks because
 * the hardcoded depth>2 guard (introduced in 8u232) does not exist yet.
 *
 * This models a misconfigured production deployment where an admin has opened the
 * JEP290 filter via an environment variable or startup script, without understanding
 * that it fully bypasses the protection.
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

        // Show current DGC filter property (set via JAVA_OPTS in Dockerfile)
        String dgcFilter = System.getProperty("sun.rmi.transport.dgcFilter", "<not set>");
        System.out.println("[RMI-JEP290-PROP]  dgcFilter    : " + dgcFilter);
        System.out.println("[RMI-JEP290-PROP]  Bypass       : property-only (no reflection required)");

        // Confirm CommonsCollections presence (gadgets need this)
        try {
            Class.forName("org.apache.commons.collections.Transformer");
            System.out.println("[RMI-JEP290-PROP]  commons-collections 3.1 found (gadgets enabled)");
        } catch (ClassNotFoundException e) {
            System.out.println("[RMI-JEP290-PROP]  WARNING: commons-collections not found in classpath!");
        }

        // Create registry and export objects
        Registry registry = LocateRegistry.createRegistry(registryPort);

        HelloServiceImpl hello = new HelloServiceImpl(helloPort);
        DataServiceImpl  data  = new DataServiceImpl(dataPort);

        registry.bind("HelloService", hello);
        registry.bind("DataService",  data);

        System.out.println("[RMI-JEP290-PROP]  Registry on port " + registryPort);
        System.out.println("[RMI-JEP290-PROP]  HelloService on port " + helloPort);
        System.out.println("[RMI-JEP290-PROP]  DataService  on port " + dataPort);
        System.out.println("[RMI-JEP290-PROP] ================================================");
        System.out.println("[RMI-JEP290-PROP]  Ready — DGC filter open via system property");
        System.out.println("[RMI-JEP290-PROP] ================================================");

        // Block forever
        Object lock = new Object();
        synchronized (lock) {
            lock.wait();
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
