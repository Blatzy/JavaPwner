import java.lang.instrument.Instrumentation;
import java.lang.reflect.Field;
import java.lang.reflect.Modifier;

/**
 * Java premain agent for JBoss AS 4.2.3.GA lab target.
 *
 * Disables DGC and Registry deserialization filters by replacing the
 * private static final dgcFilter / registryFilter fields with an AllowAll
 * implementation, making the JNP/JRMP channel exploitable on modern JDKs
 * (Java 8u121+) where JEP 290 would otherwise block ysoserial gadgets.
 *
 * Uses the Field.modifiers trick (Java 8 compatible).
 *
 * Invoked via: -javaagent:/opt/lab-agent.jar (in JAVA_OPTS)
 */
public class LabAgent {

    public static void premain(String agentArgs, Instrumentation inst) {
        System.out.println("[LAB-AGENT] ================================================");
        System.out.println("[LAB-AGENT]  JBoss Lab Agent — DGC/Registry filter bypass");
        System.out.println("[LAB-AGENT] ================================================");
        disableDgcFilter();
        disableRegistryFilter();
    }

    private static void disableDgcFilter() {
        try {
            // Force DGCImpl loading so its static initializer runs with the
            // system property filter (set in JAVA_OPTS) before we replace it.
            Class<?> dgcImplClass = Class.forName("sun.rmi.transport.DGCImpl");
            Field dgcFilterField = dgcImplClass.getDeclaredField("dgcFilter");
            dgcFilterField.setAccessible(true);

            // Remove final modifier so we can overwrite the field value
            Field modifiers = Field.class.getDeclaredField("modifiers");
            modifiers.setAccessible(true);
            modifiers.setInt(dgcFilterField, dgcFilterField.getModifiers() & ~Modifier.FINAL);

            // Install unconditional AllowAll filter
            sun.misc.ObjectInputFilter allowAll =
                    info -> sun.misc.ObjectInputFilter.Status.ALLOWED;
            dgcFilterField.set(null, allowAll);
            System.out.println("[LAB-AGENT]  DGC filter     : DISABLED (AllowAll via reflection)");
        } catch (NoSuchFieldException e) {
            System.out.println("[LAB-AGENT]  DGC filter     : absent (pre-JEP290 JVM)");
        } catch (Exception e) {
            System.out.println("[LAB-AGENT]  DGC filter     : bypass failed — " + e);
        }
    }

    private static void disableRegistryFilter() {
        try {
            Class<?> regImplClass = Class.forName("sun.rmi.registry.RegistryImpl");
            Field regFilterField = regImplClass.getDeclaredField("registryFilter");
            regFilterField.setAccessible(true);

            Field modifiers = Field.class.getDeclaredField("modifiers");
            modifiers.setAccessible(true);
            modifiers.setInt(regFilterField, regFilterField.getModifiers() & ~Modifier.FINAL);

            sun.misc.ObjectInputFilter allowAll =
                    info -> sun.misc.ObjectInputFilter.Status.ALLOWED;
            regFilterField.set(null, allowAll);
            System.out.println("[LAB-AGENT]  Registry filter: DISABLED (AllowAll via reflection)");
        } catch (NoSuchFieldException e) {
            System.out.println("[LAB-AGENT]  Registry filter: absent (pre-JEP290 JVM)");
        } catch (Exception e) {
            System.out.println("[LAB-AGENT]  Registry filter: bypass failed — " + e);
        }
    }
}
