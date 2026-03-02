# ── JBoss AS 4.2.3.GA — Vulnerable Java EE Server ───────────────────────────
#
# Vulnerabilities exposed:
#   CVE-2015-7501  /invoker/JMXInvokerServlet  (HTTP deserialization RCE)
#   CVE-2017-7504  /invoker/EJBInvokerServlet  (HTTP deserialization RCE)
#   JNP DGC        port 4444 (host) → 1099 (container)
#
# CommonsCollections 3.1 is added to server/default/lib so CC gadgets work.
#
# Attack surface:
#   javapwner jboss scan       -t 127.0.0.1
#   javapwner jboss exploit    -t 127.0.0.1 --gadget CommonsCollections6 --cmd '...'
#   javapwner jboss jnp-scan   -t 127.0.0.1          (port 4444 default)
#   javapwner jboss jnp-exploit -t 127.0.0.1 --gadget CommonsCollections6 --cmd '...'
#
FROM eclipse-temurin:8-jdk

LABEL description="JBoss AS 4.2.3.GA (CVE-2015-7501, CVE-2017-7504)" \
      attack-surface="HTTP invoker deserialization + JNP DGC"

RUN apt-get update -qq && apt-get install -qq -y wget unzip && rm -rf /var/lib/apt/lists/*

WORKDIR /opt

# Download JBoss AS 4.2.3.GA from SourceForge (official archive).
# Uses multiple CDN mirrors as fallback for reliability.
RUN echo "Downloading JBoss AS 4.2.3.GA (~99MB) ..." && \
    wget --progress=dot:giga --tries=3 --timeout=60 \
        "https://sourceforge.net/projects/jboss/files/JBoss/JBoss-4.2.3.GA/jboss-4.2.3.GA.zip/download" \
        -O /tmp/jboss.zip \
    || wget --progress=dot:giga --tries=3 \
        "https://versaweb.dl.sourceforge.net/project/jboss/JBoss/JBoss-4.2.3.GA/jboss-4.2.3.GA.zip" \
        -O /tmp/jboss.zip \
    || wget --progress=dot:giga --tries=3 \
        "https://nchc.dl.sourceforge.net/project/jboss/JBoss/JBoss-4.2.3.GA/jboss-4.2.3.GA.zip" \
        -O /tmp/jboss.zip && \
    echo "Extracting ..." && \
    unzip -q /tmp/jboss.zip -d /opt && \
    mv /opt/jboss-4.2.3.GA /opt/jboss && \
    rm /tmp/jboss.zip && \
    chmod +x /opt/jboss/bin/*.sh && \
    echo "JBoss AS 4.2.3.GA installed to /opt/jboss"

ENV JBOSS_HOME=/opt/jboss

# Compile the lab agent and package it as a JAR.
# The agent disables DGC/Registry deserialization filters via reflection so
# that ysoserial gadgets pass through on modern JDKs (Java 8u121+).
COPY LabAgent.java /opt/LabAgent.java
RUN javac /opt/LabAgent.java -d /opt/ && \
    mkdir -p /opt/META-INF && \
    printf 'Premain-Class: LabAgent\n' > /opt/META-INF/MANIFEST.MF && \
    jar cfm /opt/lab-agent.jar /opt/META-INF/MANIFEST.MF -C /opt LabAgent.class && \
    echo "Lab agent built: /opt/lab-agent.jar"

# Apply lab configuration (add CC3.1, verify invoker deployment)
COPY configure.sh /opt/configure.sh
RUN chmod +x /opt/configure.sh && /opt/configure.sh

# Ports:
#   8080 — HTTP (JMXInvokerServlet, EJBInvokerServlet)
#   8443 — HTTPS (optional)
#   1099 — JNP/JNDI bootstrap (mapped to host:4444 in docker-compose)
#   4447 — JRMP transport for NamingService (mapped to host:4447 in docker-compose)
EXPOSE 8080 8443 1099 4447

# Bind all interfaces so Docker port mapping works.
# -javaagent installs the AllowAll DGC/Registry filter bypass before JBoss starts.
# -Djava.rmi.server.hostname=127.0.0.1 ensures that RMI stubs embedded in the
# JNP bootstrap reference 127.0.0.1 (reachable from the host via docker-compose
# port mapping 4447:4447).
ENV JAVA_OPTS="-javaagent:/opt/lab-agent.jar \
  -Djava.rmi.server.hostname=127.0.0.1 \
  -Dsun.rmi.transport.dgcFilter=*;maxdepth=100;maxrefs=10000;maxbytes=10000000 \
  -Dsun.rmi.registry.registryFilter=*;maxdepth=100;maxrefs=10000;maxbytes=10000000 \
  -Xbootclasspath/a:/opt/jboss/server/default/lib/commons-collections-3.1.jar"

CMD ["/opt/jboss/bin/run.sh", "-b", "0.0.0.0"]
