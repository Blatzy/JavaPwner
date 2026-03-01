#!/bin/bash
# ============================================================
#  JBoss AS 4.2.3.GA post-install configuration
#  Run once at Docker build time (RUN ./configure.sh)
# ============================================================
set -e

JBOSS_HOME="/opt/jboss"
SERVER_LIB="$JBOSS_HOME/server/default/lib"

echo "[CONFIGURE] JBoss AS 4.2.3.GA post-install setup"

# ── 1. Add CommonsCollections 3.1 ────────────────────────────────────────────
# JBoss 4.2.3.GA ships with commons-collections-2.1.jar which does NOT
# contain the CC1/CC3/CC5/CC6 gadget-chain classes.
# We add CC 3.1 alongside the existing JAR so all ysoserial gadgets work.
echo "[CONFIGURE] Downloading commons-collections-3.1.jar ..."
wget -q \
    "https://repo1.maven.org/maven2/commons-collections/commons-collections/3.1/commons-collections-3.1.jar" \
    -O "$SERVER_LIB/commons-collections-3.1.jar"
echo "[CONFIGURE] Added: $SERVER_LIB/commons-collections-3.1.jar"

# ── 2. Verify HTTP invoker deployment ────────────────────────────────────────
# JBoss 4.2.3.GA ships all HTTP invoker servlets inside http-invoker.sar:
#   /invoker/JMXInvokerServlet     (CVE-2015-7501)
#   /invoker/EJBInvokerServlet     (CVE-2017-7504)
#   /invoker/readonly/*            (CVE-2017-12149 style filter)
# The SAR is at server/default/deploy/http-invoker.sar/invoker.war/WEB-INF/web.xml
DEPLOY="$JBOSS_HOME/server/default/deploy"
INVOKER_WAR="$DEPLOY/http-invoker.sar/invoker.war/WEB-INF/web.xml"

if [ -f "$INVOKER_WAR" ]; then
    echo "[CONFIGURE] Found: http-invoker.sar (JMXInvokerServlet + EJBInvokerServlet + readonly)"
    grep -o 'url-pattern>[^<]*</url-pattern' "$INVOKER_WAR" | sed 's/url-pattern>//;s|</url-pattern||' | sort -u | while read p; do
        echo "[CONFIGURE]   servlet path: $p"
    done
else
    echo "[CONFIGURE] WARNING: http-invoker.sar not found — invoker endpoints unavailable"
fi

# ── 3. Bind JBoss Naming (JNP) to all interfaces ─────────────────────────────
# The JNP service config is in server/default/conf/jboss-service.xml.
# We set RmiPort to a fixed value (1098 on loopback inside container)
# and keep the main JNP port at 1099 (mapped to host:4444 in docker-compose).
echo "[CONFIGURE] Patching JNP bind address ..."
JBOSS_SVC="$JBOSS_HOME/server/default/conf/jboss-service.xml"
if [ -f "$JBOSS_SVC" ]; then
    # Ensure the NamingService listens on 0.0.0.0
    sed -i 's|<attribute name="BindAddress">.*</attribute>|<attribute name="BindAddress">0.0.0.0</attribute>|g' \
        "$JBOSS_SVC" 2>/dev/null || true
fi

# ── 4. Print library summary ─────────────────────────────────────────────────
echo "[CONFIGURE] Libraries in server/default/lib:"
ls "$SERVER_LIB"/ | grep -E "(commons|serializ)" || true

echo "[CONFIGURE] Done."
