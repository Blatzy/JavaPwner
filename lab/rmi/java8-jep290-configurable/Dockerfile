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
# Azul Zulu 8u202 — falls in the JEP290 property-configurable era (8u121–8u231).
# JEP290 is present (DGCImpl.dgcFilter field exists) but the hardcoded depth>2
# check introduced in 8u232 is NOT yet present.
#
# The system property alone is sufficient to open the filter:
#   sun.rmi.transport.dgcFilter=*;maxdepth=100;maxrefs=10000;maxbytes=10000000
#
# On 8u202, the wildcard (*) returns ALLOWED for both named-class AND null-class
# (depth/refs/bytes) checks because the hardcoded DGC check does not exist yet.
# No reflection bypass required — simulates a misconfigured legacy server.
#
# CommonsCollections 3.1 in classpath → exploitable via DGC dirty().
#
FROM azul/zulu-openjdk:8u202

LABEL description="Vulnerable Java RMI Registry — Java 8u202 JEP290 present but DGC unconfigured" \
      attack-surface="RMI DGC dirty() — JEP290 present but dgcFilter=null (property never set)" \
      jep290-era="JEP290 property-configurable (8u121-8u231) — filter field exists but null" \
      cve="unconfigured JEP290 dgcFilter — DGC fully open"

WORKDIR /app
COPY --from=builder /build/target/rmi-server-fat.jar .

# Ports:
#   1599 — RMI Registry
#   1598 — HelloService remote object (fixed port, required for Docker NAT)
#   1597 — DataService  remote object (fixed port, required for Docker NAT)
EXPOSE 1599 1598 1597

CMD ["sh", "-c", \
     "exec java \
      -Djava.rmi.server.hostname=${RMI_HOSTNAME:-127.0.0.1} \
      -Djava.rmi.server.logCalls=false \
      -jar /app/rmi-server-fat.jar \
      ${RMI_REGISTRY_PORT:-1599} ${RMI_HELLO_PORT:-1598} ${RMI_DATA_PORT:-1597}"]
