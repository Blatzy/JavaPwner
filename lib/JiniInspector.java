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
public class JiniInspector {

    // DestroyAdmin lives in different packages depending on Jini vs River
    private static final String DESTROY_ADMIN_SUN = "com.sun.jini.admin.DestroyAdmin";
    private static final String DESTROY_ADMIN_RIVER = "org.apache.river.admin.DestroyAdmin";
    private static final String STORAGE_ADMIN_SUN = "com.sun.jini.admin.StorageLocationAdmin";

    // Maximum number of services to enumerate via lookup()
    private static final int MAX_SERVICES = 256;

    public static void main(String[] args) {
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
    // Main inspection logic
    // ──────────────────────────────────────────────────────────────────

    private static void inspect(String host, int port, int timeout) throws Exception {
        String jiniUrl = "jini://" + host + ":" + port;
        LookupLocator locator = new LookupLocator(jiniUrl);

        ServiceRegistrar registrar = locator.getRegistrar(timeout);

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
