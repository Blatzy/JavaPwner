/*
 * JiniInspector — Tier 2 Jini Registrar inspection helper for JavaPwner.
 *
 * Connects to a Jini Lookup Service via LookupLocator, retrieves the
 * ServiceRegistrar proxy, and inspects its administration capabilities.
 *
 * Usage:
 *   javac -cp <jini-jars> JiniInspector.java
 *   java  -cp <jini-jars>:. \
 *         -Djava.security.policy=security.policy \
 *         -Djava.rmi.server.useCodebaseOnly=false \
 *         JiniInspector <host> <port> [timeout_ms]
 *
 * Output: single-line JSON to stdout.
 *
 * Required JARs on classpath (Apache River 3.x or Sun Jini 2.x):
 *   - jsk-lib.jar  /  jini-core.jar
 *   - jsk-platform.jar  /  jini-ext.jar
 *   - river-lib.jar  (River 3.x only)
 */

import net.jini.core.discovery.LookupLocator;
import net.jini.core.entry.Entry;
import net.jini.core.lookup.ServiceID;
import net.jini.core.lookup.ServiceItem;
import net.jini.core.lookup.ServiceMatches;
import net.jini.core.lookup.ServiceRegistrar;
import net.jini.core.lookup.ServiceTemplate;
import net.jini.admin.Administrable;
import net.jini.admin.JoinAdmin;

import java.util.LinkedHashSet;
import java.util.Set;

/**
 * Self-contained Jini Registrar inspector.
 * <p>
 * Checks whether the Registrar is {@code Administrable}, enumerates admin
 * capabilities ({@code JoinAdmin}, {@code DestroyAdmin},
 * {@code StorageLocationAdmin}), and lists registered services.
 */
@SuppressWarnings({"removal", "deprecation"})
public class JiniInspector {

    // DestroyAdmin lives in different packages depending on Jini vs River
    private static final String DESTROY_ADMIN_SUN = "com.sun.jini.admin.DestroyAdmin";
    private static final String DESTROY_ADMIN_RIVER = "org.apache.river.admin.DestroyAdmin";
    private static final String STORAGE_ADMIN_SUN = "com.sun.jini.admin.StorageLocationAdmin";

    // Maximum number of services to enumerate via lookup()
    private static final int MAX_SERVICES = 256;

    public static void main(String[] args) {
        // Install a SecurityManager to enable RMI codebase class loading.
        // On Java 21+ SecurityManager has been removed — catch and continue;
        // the necessary proxy classes (reggie-dl.jar) should be on the local
        // classpath instead.
        try {
            if (System.getSecurityManager() == null) {
                System.setSecurityManager(new SecurityManager());
            }
        } catch (UnsupportedOperationException ignored) {
            // Java 21+: SecurityManager removed entirely — not needed when
            // proxy JARs (reggie*.jar) are on the classpath.
        } catch (SecurityException ignored) {
            // Already managed or not permitted.
        }

        if (args.length < 2) {
            outputError("Usage: JiniInspector <host> <port> [timeout_ms]");
            System.exit(1);
            return;
        }

        String host = args[0];
        int port;
        int timeout = 5000;

        try {
            port = Integer.parseInt(args[1]);
        } catch (NumberFormatException e) {
            outputError("Invalid port: " + args[1]);
            System.exit(1);
            return;
        }

        if (args.length > 2) {
            try {
                timeout = Integer.parseInt(args[2]);
            } catch (NumberFormatException ignored) {
            }
        }

        try {
            inspect(host, port, timeout);
        } catch (Exception e) {
            outputError(e.getClass().getName() + ": " + sanitize(e.getMessage()));
            System.exit(1);
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // SUID-patching helpers
    // ──────────────────────────────────────────────────────────────────

    /**
     * Call {@code locator.getRegistrar(timeout)}, transparently handling
     * {@code InvalidClassException} caused by {@code serialVersionUID} mismatches
     * between the local reggie JAR (Apache River 3.x, SUID=2) and old targets
     * (Sun Jini 2.x, computed SUID).
     *
     * <p>Strategy:
     * <ol>
     *   <li>First attempt — normal deserialization.</li>
     *   <li>On {@code InvalidClassException}: parse the expected SUID from the
     *       exception message, patch the {@code ObjectStreamClass.suid} field of
     *       the affected local class via reflection, then retry once.</li>
     * </ol>
     *
     * <p>The reflection patch requires {@code --add-opens java.base/java.io=ALL-UNNAMED}
     * on JDK 17+.  When reflective access is denied the exception is re-thrown and
     * the caller reports it normally; no silent data loss occurs.
     */
    private static ServiceRegistrar getRegistrarWithSuidFix(
            LookupLocator locator, int timeout) throws Exception {
        try {
            return locator.getRegistrar(timeout);
        } catch (java.io.InvalidClassException ice) {
            String msg = ice.getMessage() != null ? ice.getMessage() : "";
            // Example message:
            // "com.sun.jini.reggie.RegistrarProxy; local class incompatible:
            //  stream classdesc serialVersionUID = 2425188657680236255,
            //  local class serialVersionUID = 2"
            String className = extractClassNameFromIce(msg);
            long streamSuid  = extractSuidFromMessage(msg, "stream classdesc serialVersionUID = ");
            if (className != null && streamSuid != 0) {
                boolean patched = patchObjectStreamClassSuid(className, streamSuid);
                if (patched) {
                    // Retry with the patched SUID
                    return locator.getRegistrar(timeout);
                }
            }
            throw ice; // re-throw: caller will output the error
        }
    }

    /** Extract the class name from an InvalidClassException message. */
    private static String extractClassNameFromIce(String msg) {
        int semi = msg.indexOf(';');
        if (semi > 0) {
            String candidate = msg.substring(0, semi).trim();
            if (candidate.contains(".")) return candidate;
        }
        return null;
    }

    /**
     * Parse a decimal long following {@code prefix} inside {@code msg}.
     * Returns 0 if not found or unparseable.
     */
    private static long extractSuidFromMessage(String msg, String prefix) {
        int idx = msg.indexOf(prefix);
        if (idx < 0) return 0L;
        int start = idx + prefix.length();
        int end = start;
        while (end < msg.length()
               && (Character.isDigit(msg.charAt(end)) || msg.charAt(end) == '-')) {
            end++;
        }
        try {
            return Long.parseLong(msg.substring(start, end));
        } catch (NumberFormatException e) {
            return 0L;
        }
    }

    /**
     * Use reflection to set {@code ObjectStreamClass.suid} for {@code className}
     * to {@code targetSuid}.
     *
     * <p>Works on JDK 8–16 unconditionally.  On JDK 17+ requires the JVM to be
     * launched with {@code --add-opens java.base/java.io=ALL-UNNAMED}.
     *
     * @return {@code true} if the patch was applied; {@code false} if access
     *         was denied (Java 17+ without the required {@code --add-opens}).
     */
    private static boolean patchObjectStreamClassSuid(String className, long targetSuid) {
        try {
            Class<?> clazz = Class.forName(className);
            java.io.ObjectStreamClass osc = java.io.ObjectStreamClass.lookup(clazz);
            if (osc == null) return false;
            java.lang.reflect.Field suidField =
                    java.io.ObjectStreamClass.class.getDeclaredField("suid");
            suidField.setAccessible(true);   // InaccessibleObjectException on JDK 17+ w/o --add-opens
            // suid is declared as 'volatile Long' (nullable) in modern OpenJDK
            suidField.set(osc, Long.valueOf(targetSuid));
            return true;
        } catch (Exception e) {
            // Reflective access denied (JDK 17+ strong encapsulation) or class not found
            return false;
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Main inspection logic
    // ──────────────────────────────────────────────────────────────────

    private static void inspect(String host, int port, int timeout) throws Exception {
        String jiniUrl = "jini://" + host + ":" + port;
        LookupLocator locator = new LookupLocator(jiniUrl);

        ServiceRegistrar registrar = getRegistrarWithSuidFix(locator, timeout);

        StringBuilder j = new StringBuilder(4096);
        j.append("{\"success\":true");

        // ── Registrar metadata ───────────────────────────────────────
        j.append(",\"registrar\":{");
        j.append("\"class_name\":\"").append(registrar.getClass().getName()).append("\"");

        appendInterfaces(j, registrar.getClass());

        // ServiceID
        try {
            ServiceID sid = registrar.getServiceID();
            if (sid != null) {
                j.append(",\"service_id\":\"").append(sid.toString()).append("\"");
            }
        } catch (Exception ignored) {
        }

        // Groups
        try {
            String[] groups = registrar.getGroups();
            j.append(",\"groups\":");
            appendStringArray(j, groups);
        } catch (Exception e) {
            j.append(",\"groups_error\":\"").append(sanitize(e.getMessage())).append("\"");
        }

        // Locator
        try {
            LookupLocator loc = registrar.getLocator();
            if (loc != null) {
                j.append(",\"locator\":\"").append(sanitize(loc.toString())).append("\"");
            }
        } catch (Exception ignored) {
        }

        j.append("}");  // end registrar

        // ── Admin inspection ─────────────────────────────────────────
        boolean isAdministrable = registrar instanceof Administrable;
        j.append(",\"admin\":{\"is_administrable\":").append(isAdministrable);

        if (isAdministrable) {
            inspectAdmin(j, (Administrable) registrar);
        }

        j.append("}");  // end admin

        // ── Service enumeration ──────────────────────────────────────
        j.append(",\"services\":[");
        int totalServices = 0;
        try {
            ServiceTemplate tmpl = new ServiceTemplate(null, null, null);
            ServiceMatches matches = registrar.lookup(tmpl, MAX_SERVICES);
            if (matches != null && matches.items != null) {
                totalServices = matches.totalMatches;
                boolean first = true;
                for (ServiceItem item : matches.items) {
                    if (item == null || item.service == null) continue;
                    if (!first) j.append(",");
                    first = false;
                    appendServiceItem(j, item);
                }
            }
        } catch (Exception e) {
            j.append("],\"services_error\":\"").append(sanitize(e.getMessage())).append("\"");
            j.append(",\"total_services\":").append(totalServices).append("}");
            System.out.println(j.toString());
            return;
        }
        j.append("],\"total_services\":").append(totalServices);

        j.append("}");
        System.out.println(j.toString());
    }

    // ──────────────────────────────────────────────────────────────────
    // Admin inspection
    // ──────────────────────────────────────────────────────────────────

    private static void inspectAdmin(StringBuilder j, Administrable administrable) {
        try {
            Object admin = administrable.getAdmin();
            j.append(",\"class_name\":\"").append(admin.getClass().getName()).append("\"");
            appendInterfaces(j, admin.getClass());

            j.append(",\"capabilities\":{");

            // ── JoinAdmin ────────────────────────────────────────────
            boolean hasJoinAdmin = admin instanceof JoinAdmin;
            j.append("\"join_admin\":{\"available\":").append(hasJoinAdmin);
            if (hasJoinAdmin) {
                inspectJoinAdmin(j, (JoinAdmin) admin);
            }
            j.append("}");

            // ── DestroyAdmin (via reflection — different packages) ───
            boolean hasDestroy = implementsInterface(admin, DESTROY_ADMIN_SUN)
                    || implementsInterface(admin, DESTROY_ADMIN_RIVER);
            j.append(",\"destroy_admin\":{\"available\":").append(hasDestroy).append("}");

            // ── StorageLocationAdmin ─────────────────────────────────
            boolean hasStorage = implementsInterface(admin, STORAGE_ADMIN_SUN);
            j.append(",\"storage_admin\":{\"available\":").append(hasStorage);
            if (hasStorage) {
                inspectStorageAdmin(j, admin);
            }
            j.append("}");

            j.append("}");  // end capabilities

        } catch (Exception e) {
            j.append(",\"error\":\"").append(sanitize(e.getMessage())).append("\"");
        }
    }

    private static void inspectJoinAdmin(StringBuilder j, JoinAdmin ja) {
        // Groups
        try {
            String[] groups = ja.getLookupGroups();
            j.append(",\"groups\":");
            appendStringArray(j, groups);
        } catch (Exception e) {
            j.append(",\"groups_error\":\"").append(sanitize(e.getMessage())).append("\"");
        }

        // Locators
        try {
            LookupLocator[] locs = ja.getLookupLocators();
            j.append(",\"locators\":[");
            if (locs != null) {
                for (int i = 0; i < locs.length; i++) {
                    if (i > 0) j.append(",");
                    j.append("\"").append(sanitize(locs[i].toString())).append("\"");
                }
            }
            j.append("]");
        } catch (Exception e) {
            j.append(",\"locators_error\":\"").append(sanitize(e.getMessage())).append("\"");
        }

        // Attributes
        try {
            Entry[] attrs = ja.getLookupAttributes();
            int count = (attrs != null) ? attrs.length : 0;
            j.append(",\"attributes_count\":").append(count);
            if (count > 0) {
                j.append(",\"attributes\":[");
                for (int i = 0; i < attrs.length; i++) {
                    if (i > 0) j.append(",");
                    j.append("\"").append(sanitize(
                            attrs[i] != null ? attrs[i].toString() : "null"
                    )).append("\"");
                }
                j.append("]");
            }
        } catch (Exception e) {
            j.append(",\"attributes_error\":\"").append(sanitize(e.getMessage())).append("\"");
        }
    }

    private static void inspectStorageAdmin(StringBuilder j, Object admin) {
        try {
            java.lang.reflect.Method getter =
                    admin.getClass().getMethod("getStorageLocation");
            Object loc = getter.invoke(admin);
            if (loc != null) {
                j.append(",\"location\":\"").append(sanitize(loc.toString())).append("\"");
            }
        } catch (Exception ignored) {
        }
    }

    // ──────────────────────────────────────────────────────────────────
    // Service item formatting
    // ──────────────────────────────────────────────────────────────────

    private static void appendServiceItem(StringBuilder j, ServiceItem item) {
        j.append("{\"service_id\":\"")
         .append(item.serviceID != null ? item.serviceID.toString() : "null")
         .append("\"");
        j.append(",\"class_name\":\"").append(item.service.getClass().getName()).append("\"");
        appendInterfaces(j, item.service.getClass());
        j.append(",\"is_administrable\":").append(item.service instanceof Administrable);

        if (item.attributeSets != null && item.attributeSets.length > 0) {
            j.append(",\"attributes\":[");
            for (int i = 0; i < item.attributeSets.length; i++) {
                if (i > 0) j.append(",");
                j.append("\"").append(sanitize(
                        item.attributeSets[i] != null ? item.attributeSets[i].toString() : "null"
                )).append("\"");
            }
            j.append("]");
        }
        j.append("}");
    }

    // ──────────────────────────────────────────────────────────────────
    // Reflection helpers
    // ──────────────────────────────────────────────────────────────────

    /**
     * Collect all interfaces implemented by {@code cls} (including inherited).
     */
    private static Class<?>[] getAllInterfaces(Class<?> cls) {
        Set<Class<?>> result = new LinkedHashSet<>();
        for (Class<?> c = cls; c != null; c = c.getSuperclass()) {
            for (Class<?> iface : c.getInterfaces()) {
                collectInterfaces(iface, result);
            }
        }
        return result.toArray(new Class<?>[0]);
    }

    private static void collectInterfaces(Class<?> iface, Set<Class<?>> result) {
        if (result.add(iface)) {
            for (Class<?> parent : iface.getInterfaces()) {
                collectInterfaces(parent, result);
            }
        }
    }

    /**
     * Check if {@code obj} implements an interface identified by its FQCN.
     * Uses reflection so it works even when only one of Sun/River JARs is present.
     */
    private static boolean implementsInterface(Object obj, String fqcn) {
        for (Class<?> iface : getAllInterfaces(obj.getClass())) {
            if (iface.getName().equals(fqcn)) {
                return true;
            }
        }
        return false;
    }

    // ──────────────────────────────────────────────────────────────────
    // JSON helpers
    // ──────────────────────────────────────────────────────────────────

    private static void appendInterfaces(StringBuilder j, Class<?> cls) {
        Class<?>[] ifaces = getAllInterfaces(cls);
        j.append(",\"interfaces\":[");
        for (int i = 0; i < ifaces.length; i++) {
            if (i > 0) j.append(",");
            j.append("\"").append(ifaces[i].getName()).append("\"");
        }
        j.append("]");
    }

    private static void appendStringArray(StringBuilder j, String[] arr) {
        j.append("[");
        if (arr != null) {
            for (int i = 0; i < arr.length; i++) {
                if (i > 0) j.append(",");
                j.append("\"").append(sanitize(arr[i])).append("\"");
            }
        }
        j.append("]");
    }

    private static String sanitize(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    private static void outputError(String message) {
        System.out.println("{\"success\":false,\"error\":\"" + sanitize(message) + "\"}");
    }
}
