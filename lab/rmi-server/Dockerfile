# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM maven:3.8.8-eclipse-temurin-8 AS builder

WORKDIR /build
COPY pom.xml .
# Pre-fetch dependencies (cache layer)
RUN mvn -q dependency:go-offline
COPY src/ src/
RUN mvn -q package -DskipTests

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
#
# Eclipse Temurin 8 (latest Java 8 LTS, widely available on any registry).
# JEP 290 deserialization filters set to allow all classes AND remove limits,
# simulating a misconfigured production deployment:
#
#   sun.rmi.transport.dgcFilter=*;maxdepth=100;maxrefs=10000;maxbytes=10000000
#
#   The wildcard alone (*) only returns ALLOWED for named-class checks but
#   UNDECIDED for the null-class depth/refs/bytes summary check.  UNDECIDED
#   causes the built-in hardcoded DGC filter to run, which rejects depth > 2.
#   Adding explicit maxdepth/maxrefs/maxbytes limits makes the filter return
#   ALLOWED for those checks too, fully bypassing the hardcoded restriction.
#
# CommonsCollections1/3/5/6 gadget chains all work.
#
FROM eclipse-temurin:8-jdk

LABEL description="Vulnerable Java RMI Registry (JEP290 disabled, CC3.1)" \
      attack-surface="RMI DGC dirty() + Registry bind()" \
      cve="misconfigured JEP290 (sun.rmi filters set to *)"

WORKDIR /app
COPY --from=builder /build/target/rmi-server-fat.jar .

# Ports:
#   1099 — RMI Registry
#   1098 — HelloService remote object (fixed port, required for Docker NAT)
#   1097 — DataService  remote object (fixed port, required for Docker NAT)
EXPOSE 1099 1098 1097

CMD ["sh", "-c", \
     "exec java \
      -Djava.rmi.server.hostname=${RMI_HOSTNAME:-127.0.0.1} \
      -Djava.rmi.server.logCalls=false \
      -Dsun.rmi.transport.dgcFilter='*' \
      -Dsun.rmi.registry.registryFilter='*' \
      -jar /app/rmi-server-fat.jar"]
