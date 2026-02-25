# JavaPwner — Development Plan

> Status: In progress
> Updated: 2026-02-25

---

## Audit findings

### Bugs

| ID | File | Description |
|----|------|-------------|
| B1 | `javapwner/core/socket_helper.py` | `write_java_utf` defined twice (L202 and L208). Python silently uses the second definition. Remove the duplicate. |
| B2 | `javapwner/core/jvm_bridge.py` | `JvmBridge.__init__` calls `os.environ["JAVA_HOME"] = java_home`, mutating the global process environment. Fix: pass a modified env dict to subprocess calls instead. |
| B3 | `javapwner/core/jvm_bridge.py` | `_JAR_GLOBS` constant is defined but never used by `_discover_jars()`. Dead code — remove. |

### Optimisations

| ID | Description |
|----|-------------|
| O1 | `multicast_discover()` in scanner.py is not exposed as a CLI command. Add `javapwner jini multicast`. |
| O2 | `jrmp.py` duplicates logic already needed by the RMI module. Refactor to `javapwner/core/jrmp.py` and import from both Jini and RMI modules. |

---

## Phase A — Bug fixes & polish

**Files modified:** `socket_helper.py`, `jvm_bridge.py`, `jini_cmds.py`

1. Remove duplicate `write_java_utf` definition from `socket_helper.py`.
2. Fix `os.environ` mutation in `jvm_bridge.py`; pass a per-subprocess env dict instead.
3. Remove dead `_JAR_GLOBS` constant from `jvm_bridge.py`.
4. Expose `multicast_discover()` as `javapwner jini multicast` CLI command.

---

## Phase B — RMI module

**New files:**
- `javapwner/protocols/rmi/protocol.py` — wire primitives
- `javapwner/protocols/rmi/scanner.py` — full Registry enumeration (replaces stub)
- `javapwner/protocols/rmi/exploiter.py` — payload delivery
- `javapwner/cli/rmi_cmds.py` — Click commands

**New tests:**
- `tests/test_rmi_protocol.py`
- `tests/test_rmi_scanner.py`

### B.1 `protocol.py` — RMI wire primitives

Constants and builders for the Java RMI over-the-wire format:

- `REGISTRY_OBJID` (all-zero 20-byte ObjID)
- `DGC_OBJID` (ObjID num=2, zeros for UID)
- `REGISTRY_INTERFACE_HASH = 4905912898345647071L`
- Method hashes: `LIST_HASH`, `LOOKUP_HASH`, `BIND_HASH`, `REBIND_HASH`, `UNBIND_HASH`
- `build_registry_call(op_hash, arg_stream)` → CALL message bytes
- `build_list_call()` → Registry list() call (no args)
- `build_lookup_call(name)` → Registry lookup(String) call
- `parse_registry_return(data)` → parses a RETURN message, returns `{"names": [...]}` or `{"error": ...}`

### B.2 `scanner.py` — Registry enumeration

```python
class RmiScanResult:
    is_open: bool
    is_jrmp: bool
    is_registry: bool
    jrmp_host: str | None
    jrmp_port: int | None
    bound_names: list[str]
    name_types: dict[str, str]  # name → class name from stub
    jep290_dgc: bool | None     # DGC JEP 290 state
    raw_response: bytes
    error: str | None

class RmiScanner:
    DEFAULT_PORTS = (1099, 8282, 8283)
    def scan(host, port) -> RmiScanResult
```

Scan procedure:
1. TCP connect
2. JRMP handshake (reuse `jrmp.build_jrmp_handshake()`)
3. Send Registry list() call
4. Parse RETURN → extract bound names
5. DGC JEP 290 probe (reuse `DgcFingerprintResult` logic from `probe.py`)

### B.3 `exploiter.py` — payload delivery

```python
class RmiExploitResult:
    sent: bool
    likely_success: bool
    exception_in_response: bool
    response_bytes: bytes
    error: str | None

class RmiExploiter:
    def exploit_dgc(host, port, payload_bytes) -> RmiExploitResult
    def exploit_registry(host, port, payload_bytes) -> RmiExploitResult
    def exploit(host, port, gadget, command) -> RmiExploitResult
```

### B.4 CLI commands

```
javapwner rmi scan   -t HOST [-p 1099]        # enumerate Registry
javapwner rmi exploit -t HOST -p PORT --gadget CC6 --cmd 'id'
```

---

## Phase C — JBoss module

**New files:**
- `javapwner/protocols/jboss/fingerprint.py` — protocol detection
- `javapwner/protocols/jboss/invoker.py` — HTTP invoker exploitation
- `javapwner/protocols/jboss/scanner.py` — full scanner (replaces stub)
- `javapwner/cli/jboss_cmds.py` — Click commands

**New tests:**
- `tests/test_jboss_fingerprint.py`
- `tests/test_jboss_scanner.py`

### C.1 `fingerprint.py` — protocol detection

Detect which JBoss protocol the endpoint speaks:

```python
class JBossProtocol(Enum):
    UNKNOWN = "unknown"
    HTTP_INVOKER = "http_invoker"     # HTTP POST to /invoker/*
    REMOTING2 = "jboss_remoting2"     # binary, prefix 77 01 16 79
    JNP = "jnp"                       # Java Naming Provider (port 1099/4444)
    MANAGEMENT = "management"         # management console (port 9990)

class JBossFingerprint:
    protocol: JBossProtocol
    version: str | None   # "JBoss 4.x", "JBoss AS 6", "WildFly 8+"
    invoker_paths: list[str]  # confirmed HTTP invoker endpoints
    banner: str | None
```

HTTP fingerprint checks:
- `GET /` → look for `JBoss` / `WildFly` in response headers or body
- `GET /web-console/Invoker` → 200 = JBoss 4.x invoker
- `GET /invoker/JMXInvokerServlet` → 200 = HTTP invoker present
- `GET /invoker/readonly` → 200 = read-only invoker (CVE-2017-12149 vector)
- `GET /jbossws/` → JBoss WS presence
- Binary probe on port 4444/4446: check for JNP MAGIC or Remoting2 GREETING

### C.2 `invoker.py` — HTTP invoker exploitation

Target CVEs:
- **CVE-2015-7501** (`/invoker/JMXInvokerServlet`) — JBoss 4.x/5.x/6.x HTTP invoker
- **CVE-2017-12149** (`/invoker/readonly`) — JBoss AS 6.x
- **CVE-2017-7504** (`/invoker/EJBInvokerServlet`) — JBoss 4.x

```python
class InvokerExploitResult:
    sent: bool
    likely_success: bool
    http_status: int | None
    endpoint: str
    response_text: str | None
    error: str | None

class HttpInvoker:
    KNOWN_ENDPOINTS = [
        "/invoker/JMXInvokerServlet",
        "/invoker/EJBInvokerServlet",
        "/invoker/readonly",
        "/web-console/Invoker",
    ]
    def exploit(host, port, payload_bytes, path=None) -> InvokerExploitResult
    def probe_endpoints(host, port) -> list[str]  # returns reachable paths
```

POST a raw serialised Java object to each endpoint. The HTTP invoker deserializes
the POST body directly → ysoserial payload triggers RCE.

### C.3 `scanner.py` — full JBoss scanner

```python
class JBossScanResult:
    is_open: bool
    fingerprint: JBossFingerprint
    jep290_active: bool | None
    invoker_endpoints: list[str]
    error: str | None

class JBossScanner:
    DEFAULT_PORT = 8080
    def scan(host, port) -> JBossScanResult
```

### C.4 CLI commands

```
javapwner jboss scan    -t HOST [-p 8080]
javapwner jboss exploit -t HOST -p PORT --gadget CC6 --cmd 'id'
```

---

## Phase D — Cross-cutting improvements

### D.1 `core/jrmp.py` — shared JRMP module

Move `javapwner/protocols/jini/jrmp.py` to `javapwner/core/jrmp.py`.
Add backward-compat re-export in `javapwner/protocols/jini/jrmp.py`.
Import from `javapwner/protocols/rmi/protocol.py` instead of duplicating.

### D.2 Expose `multicast_discover()` as CLI command

```
javapwner jini multicast [-t GROUP] [-p PORT] [--wait SECS]
```

### D.3 Update `main.py`

Replace stub `rmi` and `jboss` groups with real command groups from
`javapwner/cli/rmi_cmds.py` and `javapwner/cli/jboss_cmds.py`.

---

## Running tests

```bash
.venv/bin/pytest tests/ --ignore=tests/integration -q
```

Live integration tests (requires a real target):
```bash
JINI_HOST=<ip> JINI_PORT=4160 .venv/bin/pytest tests/integration/ -m live
```

---

## Key research notes

### Java RMI wire protocol

- **ObjID** (20 bytes): `long objNum (8)` + `short uid.unique (2)` + `long uid.time (8)` + `short uid.count (2)`
- Well-known ObjIDs: Registry=0, Activator=1, DGC=2 (all-zeros for UID portion)
- **CALL format**: `0x50` + ObjID(20) + `int op=-1`(4) + `long methodHash`(8) + `ObjectOutputStream args`
- Registry interface hash: `4905912898345647071L`
- Registry method hashes: list=`2571371466621089378L`, lookup=`-7538657168040752697L`
- **JEP 290 DGC probe**: send DGC dirty() call with `java.util.HashMap` → TC_EXCEPTION = filtered

### JBoss attack surface

- `CVE-2015-7501`: HTTP POST to `/invoker/JMXInvokerServlet` with serialized CC1 payload
- `CVE-2017-12149`: HTTP POST to `/invoker/readonly` — no auth, raw serialized body
- `CVE-2017-7504`: HTTP POST to `/invoker/EJBInvokerServlet`
- **JBoss Remoting 2** handshake: `77 01 16 79 …` (magic prefix `0x77011679`)
- **Detection**: `JBoss` / `WildFly` in `X-Powered-By` or `Server` response headers
