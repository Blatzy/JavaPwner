# ── Apache River 2.2.3 Reggie (Jini Lookup Service) ─────────────────────────
#
# Eclipse Temurin 8 (latest Java 8 LTS, widely available).
# JEP 290 DGC filter disabled via -Dsun.rmi.transport.dgcFilter=*
# so the Reggie JRMP channel is fully exploitable.
#
# The Reggie object is exported via JrmpExporter on port 4162, allowing
# JavaPwner to perform JRMP DGC dirty() exploitation.
#
# Attack surface:
#   javapwner jini scan    -t 127.0.0.1 -p 4160
#   javapwner jini exploit -t 127.0.0.1 -p 4162 ...
#   javapwner jini read-file -t 127.0.0.1 -p 4160 --path /etc/passwd
#
FROM eclipse-temurin:8-jdk

LABEL description="Apache River 2.2.3 Reggie (Jini LUS, JEP290 disabled via dgcFilter=*)"

RUN apt-get update -qq && apt-get install -qq -y wget && rm -rf /var/lib/apt/lists/*

WORKDIR /jini/lib

# Apache River 2.2.3 JARs — bundled locally (copied from project lib/)
COPY lib/reggie-2.2.3.jar       .
COPY lib/reggie-dl-2.2.3.jar    .
COPY lib/jsk-lib-2.2.3.jar      .
COPY lib/jsk-platform-2.2.3.jar .

# Apache River server-side JARs (ServiceStarter + ClassServer) — from Maven Central
# start-2.2.3.jar  : com.sun.jini.start.ServiceStarter
# tools-2.2.3.jar  : com.sun.jini.tool.ClassServer
# jini-ext-2.1.jar : net.jini.jrmp.JrmpExporter (JRMP transport, needed by reggie.config)
RUN wget -q "https://repo1.maven.org/maven2/org/apache/river/start/2.2.3/start-2.2.3.jar" && \
    wget -q "https://repo1.maven.org/maven2/org/apache/river/tools/2.2.3/tools-2.2.3.jar" && \
    wget -q "https://repo1.maven.org/maven2/net/jini/jini-ext/2.1/jini-ext-2.1.jar"

# CommonsCollections 3.1 — makes the Reggie JRMP DGC channel exploitable
# via CC gadget chains (downloaded from Maven Central)
RUN wget -q "https://repo1.maven.org/maven2/commons-collections/commons-collections/3.1/commons-collections-3.1.jar"

WORKDIR /jini

COPY security.policy       /jini/security.policy
COPY reggie.config         /jini/reggie.config
COPY start-reggie.config   /jini/start-reggie.config
COPY start.sh              /jini/start.sh
COPY LabStarter.java       /jini/LabStarter.java
COPY FunctorException.java /jini/FunctorException.java
RUN chmod +x /jini/start.sh

# Compile LabStarter — disables DGC/Registry filters and SecurityManager
# before starting Reggie, simulating a fully misconfigured server.
RUN mkdir -p /jini/classes && \
    javac -d /jini/classes \
          -cp "/jini/lib/start-2.2.3.jar:/jini/lib/jsk-lib-2.2.3.jar:/jini/lib/jsk-platform-2.2.3.jar" \
          /jini/LabStarter.java

# Compile patched FunctorException — its static initializer catches Throwable
# instead of only NoSuchMethodException, preventing ExceptionInInitializerError
# when getDeclaredMethod is called under a restrictive SecurityManager context.
# Placed in /jini/classes (before commons-collections-3.1.jar on the classpath)
# so the patched version takes precedence.
RUN javac -d /jini/classes /jini/FunctorException.java

# Ports:
#   4160 — Jini Unicast Discovery (TCP)
#   4162 — Reggie JRMP remote object (JrmpExporter, exploitable DGC)
#   8085 — HTTP ClassServer (codebase, path-traversal target)
EXPOSE 4160 4162 8085

CMD ["/jini/start.sh"]
