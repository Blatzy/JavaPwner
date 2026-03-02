package lab.jini;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.Permission;

/**
 * Lab entrypoint for the Jini Reggie container.
 *
 * Disables the DGC deserialization filter via reflection, then delegates
 * to com.sun.jini.start.ServiceStarter to launch Reggie normally.
 *
 * Motivation: Java 8u391+ added a hardcoded DGC whitelist that only permits
 * ObjID, UID, VMID, and Lease.  This whitelist runs even when
 * -Dsun.rmi.transport.dgcFilter=* is set, because it is installed as a
 * separate, unconditional filter.  Setting dgcFilter to an AllowAll lambda
 * via reflection replaces the filter field before DGCImpl's static initializer
 * can install the whitelist, simulating a completely misconfigured server.
 *
 * SecurityManager note: ServiceStarter installs a SecurityManager if none is
 * present.  Even with an AllPermission policy, the AccessControlContext for
 * the DGC handler thread may contain restricted domains (e.g. from
 * NonActivatableServiceDescriptor's doPrivileged call) that block exec().
 * We pre-install a no-op SecurityManager so ServiceStarter skips its own
 * installation, leaving exec() unrestricted — exactly the misconfigured
 * server condition the lab simulates.
 */
public class LabStarter {

    public static void main(String[] args) throws Exception {
        System.out.println("[LAB] ================================================");
        System.out.println("[LAB]  Lab Jini Reggie — disabling DGC filter");
        System.out.println("[LAB] ================================================");

        disableDgcFilter();
        disableRegistryFilter();
        installNoOpSecurityManager();

        System.out.println("[LAB]  Delegating to ServiceStarter ...");
        System.out.println("[LAB] ================================================");

        com.sun.jini.start.ServiceStarter.main(args);
    }

    /**
     * Replace DGCImpl.dgcFilter with an AllowAll implementation via reflection.
     * Works on Java 8u121+ where the dgcFilter field exists.
     */
    @SuppressWarnings("unchecked")
    private static void disableDgcFilter() {
        try {
            Class<?> dgcImplClass = Class.forName("sun.rmi.transport.DGCImpl");
            Field dgcFilterField = dgcImplClass.getDeclaredField("dgcFilter");
            dgcFilterField.setAccessible(true);

            // Remove the final modifier
            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(dgcFilterField,
                    dgcFilterField.getModifiers() & ~Modifier.FINAL);

            // Install AllowAll filter
            sun.misc.ObjectInputFilter allowAll =
                    info -> sun.misc.ObjectInputFilter.Status.ALLOWED;
            dgcFilterField.set(null, allowAll);

            System.out.println("[LAB]  DGC filter : DISABLED (AllowAll via reflection)");
        } catch (NoSuchFieldException e) {
            System.out.println("[LAB]  DGC filter : absent (pre-JEP290 JVM)");
        } catch (Exception e) {
            System.out.println("[LAB]  DGC filter : bypass failed — " + e);
        }
    }

    /**
     * Pre-install a no-op SecurityManager so ServiceStarter does not replace it
     * with a real one.  ServiceStarter only calls System.setSecurityManager() when
     * getSecurityManager() == null.  Our no-op allows all permission checks so
     * Runtime.exec() is never blocked regardless of AccessControlContext.
     */
    private static void installNoOpSecurityManager() {
        try {
            System.setSecurityManager(new SecurityManager() {
                @Override public void checkPermission(Permission p) { /* allow */ }
                @Override public void checkPermission(Permission p, Object ctx) { /* allow */ }
            });
            System.out.println("[LAB]  SecurityManager : no-op installed (exec allowed)");
        } catch (Exception e) {
            System.out.println("[LAB]  SecurityManager : no-op install failed — " + e);
        }
    }

    /**
     * Replace RegistryImpl.registryFilter with AllowAll via reflection.
     */
    @SuppressWarnings("unchecked")
    private static void disableRegistryFilter() {
        try {
            Class<?> regClass = Class.forName("sun.rmi.registry.RegistryImpl");
            Field regFilterField = regClass.getDeclaredField("registryFilter");
            regFilterField.setAccessible(true);

            Field modifiersField = Field.class.getDeclaredField("modifiers");
            modifiersField.setAccessible(true);
            modifiersField.setInt(regFilterField,
                    regFilterField.getModifiers() & ~Modifier.FINAL);

            sun.misc.ObjectInputFilter allowAll =
                    info -> sun.misc.ObjectInputFilter.Status.ALLOWED;
            regFilterField.set(null, allowAll);

            System.out.println("[LAB]  Registry filter : DISABLED (AllowAll via reflection)");
        } catch (NoSuchFieldException e) {
            System.out.println("[LAB]  Registry filter : absent (pre-JEP290 JVM)");
        } catch (Exception e) {
            System.out.println("[LAB]  Registry filter : bypass failed — " + e);
        }
    }
}
