#!/bin/bash
# ============================================================
#  Jini / Apache River Reggie startup script
#  Runs inside the jini-reggie Docker container.
# ============================================================

HOSTNAME="${JINI_HOSTNAME:-127.0.0.1}"
CODEBASE_URL="${CODEBASE_URL:-http://127.0.0.1:8085}"
JINI_LIB="/jini/lib"
POLICY="/jini/security.policy"

echo "============================================================"
echo "  Jini / Apache River Reggie — Lab Target"
echo "============================================================"
echo "  Hostname      : $HOSTNAME"
echo "  Codebase URL  : $CODEBASE_URL"
echo "  Discovery port: 4160 (TCP Unicast)"
echo "  JRMP port     : 4162 (Reggie remote object)"
echo "  HTTP codebase : 8085"
echo "============================================================"

# ── 1. Start HTTP ClassServer (serves reggie-dl JAR to clients) ──────────────
echo "[CLASSSERVER] Starting on port 8085 serving $JINI_LIB ..."
java -cp "$JINI_LIB/tools-2.2.3.jar:$JINI_LIB/jsk-lib-2.2.3.jar:$JINI_LIB/jsk-platform-2.2.3.jar" \
     com.sun.jini.tool.ClassServer \
     -port 8085 \
     -dir "$JINI_LIB" \
     -verbose &
CLASSSERVER_PID=$!

sleep 1

# ── 2. Generate start config with resolved codebase URL ──────────────────────
RESOLVED_CONFIG="/tmp/start-reggie-resolved.config"
sed "s|REGGIE_CODEBASE|${CODEBASE_URL}|g" /jini/start-reggie.config > "$RESOLVED_CONFIG"

echo "[REGGIE] Config written to $RESOLVED_CONFIG"
echo "[REGGIE] Starting TransientRegistrarImpl ..."

# ── 3. Start Reggie via LabStarter ──────────────────────────────────────────
# LabStarter disables DGC/Registry deserialization filters via reflection
# before delegating to ServiceStarter.  The system property alone (*) is
# insufficient on Java 8u391+ which adds a hardcoded whitelist that runs
# regardless of user-defined filter properties.
exec java \
    -Djava.security.policy="$POLICY" \
    -Djava.rmi.server.hostname="$HOSTNAME" \
    -Djava.rmi.server.codebase="${CODEBASE_URL}/reggie-dl-2.2.3.jar" \
    -Djava.rmi.server.useCodebaseOnly=false \
    -Dnet.jini.discovery.interface=0.0.0.0 \
    -Dsun.rmi.transport.dgcFilter='*;maxdepth=100;maxrefs=10000;maxbytes=10000000' \
    -Dsun.rmi.registry.registryFilter='*' \
    -cp "/jini/classes:$JINI_LIB/start-2.2.3.jar:$JINI_LIB/jsk-platform-2.2.3.jar:$JINI_LIB/jsk-lib-2.2.3.jar:$JINI_LIB/reggie-2.2.3.jar:$JINI_LIB/reggie-dl-2.2.3.jar:$JINI_LIB/jini-ext-2.1.jar:$JINI_LIB/commons-collections-3.1.jar" \
    lab.jini.LabStarter \
    "$RESOLVED_CONFIG"
