package org.apache.commons.collections;

import java.io.PrintStream;
import java.io.PrintWriter;

/**
 * Patched replacement for commons-collections 3.1 FunctorException.
 *
 * The original FunctorException static initializer calls
 * Throwable.class.getDeclaredMethod("getCause") and catches ONLY
 * NoSuchMethodException.  When a SecurityManager is installed (even with
 * AllPermission policy), that call can throw SecurityException in some
 * Apache River DGC handler contexts, causing ExceptionInInitializerError.
 * The JVM then caches this failure and subsequent InvokerTransformer uses
 * throw NoClassDefFoundError instead of the intended FunctorException —
 * preventing the gadget chain from working at all.
 *
 * This patched version catches Throwable in the static initializer so that
 * any exception during initialization is silently absorbed, avoiding the
 * cached-initialization-failure problem entirely.
 *
 * Placed in /jini/classes which comes first on the Reggie classpath, so
 * it overrides the version bundled in commons-collections-3.1.jar.
 */
public class FunctorException extends RuntimeException {

    private static final long serialVersionUID = -4704772662371534952L;

    private static final boolean JDK_SUPPORTS_NESTED;

    static {
        boolean supportsNested = false;
        try {
            Throwable.class.getDeclaredMethod("getCause");
            supportsNested = true;
        } catch (Throwable t) {
            // Catches both NoSuchMethodException (Java < 1.4) and any
            // SecurityException thrown by a restrictive SecurityManager.
        }
        JDK_SUPPORTS_NESTED = supportsNested;
    }

    private final Throwable rootCause;

    public FunctorException() {
        super();
        this.rootCause = null;
    }

    public FunctorException(String msg) {
        super(msg);
        this.rootCause = null;
    }

    public FunctorException(Throwable rootCause) {
        super(rootCause == null ? null : rootCause.toString());
        this.rootCause = rootCause;
    }

    public FunctorException(String msg, Throwable rootCause) {
        super(msg);
        this.rootCause = rootCause;
    }

    public Throwable getCause() {
        return rootCause;
    }

    public void printStackTrace() {
        printStackTrace(System.err);
    }

    public void printStackTrace(PrintStream out) {
        synchronized (out) {
            super.printStackTrace(out);
            if (JDK_SUPPORTS_NESTED && rootCause != null) {
                out.print("Caused by: ");
                rootCause.printStackTrace(out);
            }
        }
    }

    public void printStackTrace(PrintWriter out) {
        synchronized (out) {
            super.printStackTrace(out);
            if (JDK_SUPPORTS_NESTED && rootCause != null) {
                out.print("Caused by: ");
                rootCause.printStackTrace(out);
                out.flush();
            }
        }
    }
}
