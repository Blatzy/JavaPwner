package lab.rmi;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Vulnerable Java RMI server (pre-JEP290, Java 8u111).
 *
 * Exported objects:
 *   HelloService  → port 1098 (fixed)
 *   DataService   → port 1097 (fixed)
 *   Registry      → port 1099
 *
 * CommonsCollections 3.1 is in the classpath, making the DGC channel
 * exploitable via ysoserial CommonsCollections gadgets.
 *
 * Attack surface:
 *   javapwner rmi scan 127.0.0.1
 *   javapwner rmi exploit 127.0.0.1 --gadget CommonsCollections6 --cmd '...'
 */
public class RmiServer {

    public static void main(String[] args) throws Exception {
        int registryPort = 1099;
        int helloPort    = 1098;
        int dataPort     = 1097;

        String hostname = System.getenv("RMI_HOSTNAME");
        if (hostname == null || hostname.isEmpty()) {
            hostname = "127.0.0.1";
        }
        System.setProperty("java.rmi.server.hostname", hostname);

        System.out.println("[RMI-VULN] ================================================");
        System.out.println("[RMI-VULN]  Vulnerable RMI Registry — Lab Target");
        System.out.println("[RMI-VULN] ================================================");
        System.out.println("[RMI-VULN]  Java version : " + System.getProperty("java.version"));
        System.out.println("[RMI-VULN]  Hostname     : " + hostname);

        // Confirm CommonsCollections presence (gadgets need this)
        try {
            Class.forName("org.apache.commons.collections.Transformer");
            System.out.println("[RMI-VULN]  commons-collections 3.1 found (gadgets enabled)");
        } catch (ClassNotFoundException e) {
            System.out.println("[RMI-VULN]  WARNING: commons-collections not found in classpath!");
        }

        // Create registry
        Registry registry = LocateRegistry.createRegistry(registryPort);

        // Fully disable DGC deserialization filter via reflection.
        //
        // Java 8u121+ (JEP290) added a hardcoded DGC filter in DGCImpl that:
        //   - Rejects depth > 2 for null-class (stats) checks
        //   - Whitelists only ObjID, UID, VMID, Lease
        // Setting sun.rmi.transport.dgcFilter=* via system property only helps
        // for named-class checks; null-class (depth/refs/bytes) checks fall back
        // to the hardcoded filter which rejects depth > 2 (CC6 uses depth 6).
        //
        // This reflection approach directly replaces the filter field with an
        // AllowAll implementation, simulating a completely misconfigured server
        // regardless of Java version.
        disableDgcFilter();

        // Export objects on fixed ports (required for Docker port mapping)
        HelloServiceImpl hello = new HelloServiceImpl(helloPort);
        DataServiceImpl  data  = new DataServiceImpl(dataPort);

        registry.bind("HelloService", hello);
        registry.bind("DataService",  data);

        System.out.println("[RMI-VULN]  Registry on port " + registryPort);
        System.out.println("[RMI-VULN]  HelloService on port " + helloPort);
        System.out.println("[RMI-VULN]  DataService  on port " + dataPort);
        System.out.println("[RMI-VULN] ================================================");
        System.out.println("[RMI-VULN]  Ready — DGC channel open for exploitation");
        System.out.println("[RMI-VULN] ================================================");

        // Block forever
        Object lock = new Object();
        synchronized (lock) {
            lock.wait();
        }
    }

    /**
     * Replace DGCImpl.dgcFilter with an AllowAll implementation via reflection.
     *
     * Works on Java 8u121+ where the dgcFilter field exists. On older versions
     * (no JEP290) the field is absent and the catch block is a no-op.
     */
    @SuppressWarnings("unchecked")
    private static void disableDgcFilter() {
        try {
            Class<?> dgcImplClass = Class.forName("sun.rmi.transport.DGCImpl");
            Field dgcFilterField = dgcImplClass.getDeclaredField("dgcFilter");
            dgcFilterField.setAccessible(true);

            // Remove the final modifier so we can replace the value
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(dgcFilterField,
                    dgcFilterField.getModifiers() & ~Modifier.FINAL);

            // Install a filter that unconditionally allows everything
            sun.misc.ObjectInputFilter allowAll =
                    info -> sun.misc.ObjectInputFilter.Status.ALLOWED;
            dgcFilterField.set(null, allowAll);

            System.out.println("[RMI-VULN]  DGC filter : DISABLED (AllowAll via reflection)");
        } catch (NoSuchFieldException e) {
            // Java < 8u121: no JEP290 filter at all — already fully vulnerable
            System.out.println("[RMI-VULN]  DGC filter : absent (pre-JEP290 JVM)");
        } catch (Exception e) {
            System.out.println("[RMI-VULN]  DGC filter : bypass failed — " + e);
        }
    }
}
