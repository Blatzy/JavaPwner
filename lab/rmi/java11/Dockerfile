# ── Stage 1: Build ──────────────────────────────────────────────────────────
FROM maven:3.9.6-eclipse-temurin-11 AS builder

WORKDIR /build
COPY pom.xml .
# Pre-fetch dependencies (cache layer)
RUN mvn -q dependency:go-offline
COPY src/ src/
RUN mvn -q package -DskipTests

# ── Stage 2: Runtime ─────────────────────────────────────────────────────────
#
# Eclipse Temurin 11 — Java 11 LTS.
# JEP 290 filter bypassed via Unsafe (Field.modifiers trick removed in Java 9+).
# --add-opens required for Unsafe.theUnsafe and DGCImpl.dgcFilter access.
# CommonsCollections1/3/5/6 gadget chains all work.
#
FROM eclipse-temurin:11-jdk

LABEL description="Vulnerable Java RMI Registry — Java 11 (JEP290 disabled, CC3.1)" \
      attack-surface="RMI DGC dirty() + Registry bind()" \
      java-version="11"

WORKDIR /app
COPY --from=builder /build/target/rmi-server-fat.jar .

# Ports:
#   1199 — RMI Registry
#   1198 — HelloService remote object (fixed port, required for Docker NAT)
#   1197 — DataService  remote object (fixed port, required for Docker NAT)
EXPOSE 1199 1198 1197

CMD ["sh", "-c", \
     "exec java \
      --add-opens java.rmi/sun.rmi.transport=ALL-UNNAMED \
      --add-opens java.base/sun.misc=ALL-UNNAMED \
      -Djava.rmi.server.hostname=${RMI_HOSTNAME:-127.0.0.1} \
      -Djava.rmi.server.logCalls=false \
      -Dsun.rmi.transport.dgcFilter='*;maxdepth=100;maxrefs=10000;maxbytes=10000000' \
      -Dsun.rmi.registry.registryFilter='*;maxdepth=100;maxrefs=10000;maxbytes=10000000' \
      -jar /app/rmi-server-fat.jar"]
