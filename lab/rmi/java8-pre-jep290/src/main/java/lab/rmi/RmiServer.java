package lab.rmi;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.rmi.registry.LocateRegistry;
import java.rmi.registry.Registry;

/**
 * Vulnerable Java RMI server — Java 8u111, pre-JEP290.
 *
 * Exported objects:
 *   HelloService  → port 1498 (fixed)
 *   DataService   → port 1497 (fixed)
 *   Registry      → port 1499
 *
 * Java 8u111 has no deserialization filter on the DGC channel:
 *   - DGCImpl.dgcFilter field does not exist (introduced in 8u121)
 *   - No property-based filter support
 *   - No hardcoded depth/refs/bytes restrictions
 *
 * CommonsCollections 3.1 is in the classpath, making the DGC channel
 * directly exploitable without any bypass.
 *
 * Attack surface:
 *   javapwner rmi scan 127.0.0.1 -p 1499
 *   javapwner rmi exploit 127.0.0.1 -p 1499 --gadget CommonsCollections6 --cmd '...'
 */
public class RmiServer {

    public static void main(String[] args) throws Exception {
        int registryPort = 1499;
        int helloPort    = 1498;
        int dataPort     = 1497;

        String hostname = System.getenv("RMI_HOSTNAME");
        if (hostname == null || hostname.isEmpty()) {
            hostname = "127.0.0.1";
        }
        System.setProperty("java.rmi.server.hostname", hostname);

        System.out.println("[RMI-PRE-JEP290] ================================================");
        System.out.println("[RMI-PRE-JEP290]  Vulnerable RMI Registry — Java 8u111 Lab Target");
        System.out.println("[RMI-PRE-JEP290] ================================================");
        System.out.println("[RMI-PRE-JEP290]  Java version : " + System.getProperty("java.version"));
        System.out.println("[RMI-PRE-JEP290]  Hostname     : " + hostname);
        System.out.println("[RMI-PRE-JEP290]  JEP290 era   : pre-JEP290 (< 8u121)");

        // Confirm CommonsCollections presence (gadgets need this)
        try {
            Class.forName("org.apache.commons.collections.Transformer");
            System.out.println("[RMI-PRE-JEP290]  commons-collections 3.1 found (gadgets enabled)");
        } catch (ClassNotFoundException e) {
            System.out.println("[RMI-PRE-JEP290]  WARNING: commons-collections not found in classpath!");
        }

        // Attempt disableDgcFilter() — on Java 8u111 this will hit NoSuchFieldException
        // (dgcFilter field was introduced in 8u121) and log the fact gracefully.
        disableDgcFilter();

        // Create registry
        Registry registry = LocateRegistry.createRegistry(registryPort);

        // Export objects on fixed ports (required for Docker port mapping)
        HelloServiceImpl hello = new HelloServiceImpl(helloPort);
        DataServiceImpl  data  = new DataServiceImpl(dataPort);

        registry.bind("HelloService", hello);
        registry.bind("DataService",  data);

        System.out.println("[RMI-PRE-JEP290]  Registry on port " + registryPort);
        System.out.println("[RMI-PRE-JEP290]  HelloService on port " + helloPort);
        System.out.println("[RMI-PRE-JEP290]  DataService  on port " + dataPort);
        System.out.println("[RMI-PRE-JEP290] ================================================");
        System.out.println("[RMI-PRE-JEP290]  Ready — DGC channel UNFILTERED (no JEP290)");
        System.out.println("[RMI-PRE-JEP290] ================================================");

        // Block forever
        Object lock = new Object();
        synchronized (lock) {
            lock.wait();
        }
    }

    /**
     * Attempt to disable DGCImpl.dgcFilter via reflection.
     *
     * On Java 8u111 (pre-JEP290), the dgcFilter field does not exist.
     * The NoSuchFieldException catch is the expected path — it logs the
     * fact that the JVM has no filter at all, which is the purpose of
     * this lab container.
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

            System.out.println("[RMI-PRE-JEP290]  DGC filter : DISABLED via reflection (unexpected on 8u111)");
        } catch (NoSuchFieldException e) {
            // Expected on Java < 8u121: DGCImpl.dgcFilter does not exist
            System.out.println("[RMI-PRE-JEP290]  DGC filter : absent (pre-JEP290 JVM — as expected)");
        } catch (Exception e) {
            System.out.println("[RMI-PRE-JEP290]  DGC filter : bypass attempt failed — " + e);
        }
    }
}
