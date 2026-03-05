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
# Azul Zulu 8u112 — Java 8 release BEFORE JEP 290 (introduced 8u121).
# This JVM has NO deserialization filter on the DGC channel whatsoever:
#   - DGCImpl.dgcFilter field does not exist yet
#   - No property-based filter support
#   - No hardcoded depth/refs/bytes checks
#
# CommonsCollections 3.1 in classpath → directly exploitable, no bypass needed.
# Represents the most common legacy scenario in pre-2017 Java deployments.
#
FROM azul/zulu-openjdk:8u112

LABEL description="Vulnerable Java RMI Registry — Java 8u112 pre-JEP290 (no filter at all)" \
      attack-surface="RMI DGC dirty() — no filter, direct RCE" \
      jep290-era="pre-JEP290 (< 8u121) — DGCImpl.dgcFilter field absent" \
      cve="no filter — CVE-2011-3521 era exploitation model"

WORKDIR /app
COPY --from=builder /build/target/rmi-server-fat.jar .

# Ports:
#   1499 — RMI Registry
#   1498 — HelloService remote object (fixed port, required for Docker NAT)
#   1497 — DataService  remote object (fixed port, required for Docker NAT)
EXPOSE 1499 1498 1497

CMD ["sh", "-c", \
     "exec java \
      -Djava.rmi.server.hostname=${RMI_HOSTNAME:-127.0.0.1} \
      -Djava.rmi.server.logCalls=false \
      -jar /app/rmi-server-fat.jar"]
