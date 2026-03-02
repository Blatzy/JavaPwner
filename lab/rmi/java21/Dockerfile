# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-21 AS builder

WORKDIR /build
COPY pom.xml .
# Pre-fetch dependencies (cache layer)
RUN mvn -q dependency:go-offline
COPY src/ src/
RUN mvn -q package -DskipTests

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
#
# Eclipse Temurin 21 — Java 21 LTS.
# JEP 290 filter bypassed via Unsafe (Field.modifiers trick removed in Java 9+).
# SecurityManager is removed in Java 21.
# --add-opens required for Unsafe.theUnsafe and DGCImpl.dgcFilter access.
# CommonsCollections1/3/5/6 gadget chains all work.
#
FROM eclipse-temurin:21-jdk

LABEL description="Vulnerable Java RMI Registry — Java 21 (JEP290 disabled, CC3.1)" \
      attack-surface="RMI DGC dirty() + Registry bind()" \
      java-version="21"

WORKDIR /app
COPY --from=builder /build/target/rmi-server-fat.jar .

# Ports:
#   1399 — RMI Registry
#   1398 — HelloService remote object (fixed port, required for Docker NAT)
#   1397 — DataService  remote object (fixed port, required for Docker NAT)
EXPOSE 1399 1398 1397

CMD ["sh", "-c", \
     "exec java \
      --add-opens java.rmi/sun.rmi.transport=ALL-UNNAMED \
      --add-opens java.base/sun.misc=ALL-UNNAMED \
      -Djava.rmi.server.hostname=${RMI_HOSTNAME:-127.0.0.1} \
      -Djava.rmi.server.logCalls=false \
      -Dsun.rmi.transport.dgcFilter='*;maxdepth=100;maxrefs=10000;maxbytes=10000000' \
      -Dsun.rmi.registry.registryFilter='*;maxdepth=100;maxrefs=10000;maxbytes=10000000' \
      -jar /app/rmi-server-fat.jar"]
