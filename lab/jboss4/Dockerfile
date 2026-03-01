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

# Apply lab configuration (add CC3.1, verify invoker deployment)
COPY configure.sh /opt/configure.sh
RUN chmod +x /opt/configure.sh && /opt/configure.sh

# Ports:
#   8080 — HTTP (JMXInvokerServlet, EJBInvokerServlet)
#   8443 — HTTPS (optional)
#   1099 — JNP/JNDI (mapped to host:4444 in docker-compose)
#   1098 — RMI object port (internal, not exposed to host)
EXPOSE 8080 8443 1099 1098

# Bind all interfaces so Docker port mapping works
# Disable JEP 290 DGC/Registry filters so the JNP JRMP channel is exploitable
# (JBoss run.sh inherits JAVA_OPTS from the environment)
ENV JAVA_OPTS="-Dsun.rmi.transport.dgcFilter=* -Dsun.rmi.registry.registryFilter=*"

CMD ["/opt/jboss/bin/run.sh", "-b", "0.0.0.0"]
