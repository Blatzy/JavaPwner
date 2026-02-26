"""RMI Registry scanner — enumerate bound names, probe JEP 290 filters.

Typical RMI ports:
  - 1099  : default RMI Registry
  - 8282  : JMX RMI connector (JBoss, Tomcat, WebLogic)
  - 8283  : JMX RMI connector (alternate)

Scan procedure:
  1. TCP connect + JRMP handshake (confirm JRMP)
  2. Send Registry list() call → collect bound names
  3. DGC JEP 290 probe (harmless HashMap, no ysoserial needed)
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.serialization import detect_exception_in_stream
from javapwner.core.socket_helper import TCPSession
from javapwner.exceptions import ConnectionError
from javapwner.protocols.rmi.protocol import (
    build_jrmp_handshake,
    build_list_call,
    build_lookup_call,
    parse_jrmp_ack,
    parse_registry_return,
    parse_lookup_return,
    DGC_OBJID,
    MSG_CALL,
    JAVA_STREAM_MAGIC,
    JAVA_STREAM_VERSION,
    TC_ENDBLOCKDATA,
)
import struct as _struct

_RECV_TIMEOUT = 4.0


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class RmiScanResult:
    """Full result of an RMI endpoint scan."""

    host: str
    port: int

    # Connectivity
    is_open: bool = False
    is_jrmp: bool = False
    jrmp_version: int | None = None
    jrmp_host: str | None = None
    jrmp_port: int | None = None

    # Registry
    is_registry: bool = False
    bound_names: list[str] = field(default_factory=list)

    # DGC JEP 290
    dgc_reachable: bool = False
    jep290_active: bool | None = None  # None = unknown

    # Lookup details (E.2)
    name_types: dict[str, str] = field(default_factory=dict)
    stub_endpoints: dict[str, dict] = field(default_factory=dict)

    # URLDNS probe (I.6)
    urldns_sent: bool = False
    urldns_canary: str | None = None

    # Raw data
    raw_return_bytes: bytes = field(default=b"", repr=False)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        jep290_str: str
        if not self.dgc_reachable:
            jep290_str = "unreachable"
        elif self.jep290_active is True:
            jep290_str = "filtered (JEP 290)"
        elif self.jep290_active is False:
            jep290_str = "unfiltered — RCE likely"
        else:
            jep290_str = "unknown"

        return {
            "host": self.host,
            "port": self.port,
            "is_open": self.is_open,
            "is_jrmp": self.is_jrmp,
            "jrmp_version": self.jrmp_version,
            "jrmp_host": self.jrmp_host,
            "jrmp_port": self.jrmp_port,
            "is_registry": self.is_registry,
            "bound_names": self.bound_names,
            "dgc_jep290": jep290_str,
            "name_types": self.name_types,
            "stub_endpoints": self.stub_endpoints,
            "urldns_sent": self.urldns_sent,
            "urldns_canary": self.urldns_canary,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Scanner
# ---------------------------------------------------------------------------

# Well-known ports that commonly run JRMP/RMI services
COMMON_RMI_PORTS: tuple[int, ...] = (
    1099,   # default RMI Registry
    1098,   # RMI activation system
    1097,   # RMI activation (callback)
    8282,   # JMX RMI connector (JBoss, Tomcat)
    8283,   # JMX RMI connector (alternate JBoss/WF)
    8686,   # JMX RMI (GlassFish 3.x)
    9099,   # JMX RMI (WebLogic alternate)
    9999,   # JMX RMI (JBoss default JMX)
    9001,   # JMX RMI (various)
    7001,   # WebLogic RMI
    7002,   # WebLogic RMI SSL
    7003,   # WebLogic admin
    4444,   # JBoss JNP / RMI
    4445,   # JBoss JNP RMI
    4446,   # JBoss Remoting
    1100,   # various custom
    1089,   # various custom
    50500,  # JMX RMI (custom deployments)
    50501,  # JMX RMI (alternate)
    11099,  # JMX RMI (Spring Boot Actuator)
)


class RmiScanner:
    """Scan a Java RMI endpoint for Registry entries and JEP 290 state.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    DEFAULT_PORTS = (1099, 8282, 8283)

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan_ports(
        self,
        host: str,
        ports: list[int],
        *,
        urldns_canary: str | None = None,
    ) -> list[RmiScanResult]:
        """Scan multiple *ports* and return results for every JRMP-speaking endpoint.

        For each port that responds to a JRMP handshake, a full scan is run
        (Registry list, lookup, DGC JEP 290 probe).  Ports that are closed or
        that do not speak JRMP are silently skipped.

        Parameters
        ----------
        host:
            Target hostname or IP address.
        ports:
            List of TCP ports to probe.
        urldns_canary:
            Optional URLDNS canary (see :meth:`scan`).

        Returns
        -------
        list[RmiScanResult]
            Results for all JRMP-speaking endpoints, ordered by port number.
        """
        found: list[RmiScanResult] = []
        for port in sorted(set(ports)):
            result = self.scan(host, port, urldns_canary=urldns_canary)
            if result.is_jrmp or result.is_open:
                found.append(result)
        return found

    def scan(
        self,
        host: str,
        port: int,
        *,
        urldns_canary: str | None = None,
    ) -> RmiScanResult:
        """Full scan: JRMP confirm → Registry list → lookup → DGC probe.

        Parameters
        ----------
        urldns_canary:
            If provided, send a URLDNS payload via DGC dirty() to detect
            blind deserialization. Check DNS logs for resolution.
        """
        result = RmiScanResult(host=host, port=port)

        # --- Step 1: JRMP handshake ---
        ack_data = self._jrmp_handshake(host, port, result)
        if ack_data is None:
            return result

        # --- Step 2: Registry list() ---
        self._registry_list(host, port, ack_data, result)

        # --- Step 2b: Lookup per bound name ---
        if result.bound_names:
            self._registry_lookups(host, port, result)

        # --- Step 3: DGC JEP 290 probe ---
        self._dgc_probe(host, port, result)

        # --- Step 4: URLDNS canary (optional) ---
        if urldns_canary:
            self._urldns_probe(host, port, urldns_canary, result)

        return result

    # ------------------------------------------------------------------
    # Internal steps
    # ------------------------------------------------------------------

    def _jrmp_handshake(
        self, host: str, port: int, result: RmiScanResult
    ) -> bytes | None:
        """Perform JRMP handshake. Returns the ack data, or None on failure."""
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack = sess.recv(512, exact=False)
                if not ack:
                    result.error = "No response to JRMP handshake"
                    return None
                try:
                    info = parse_jrmp_ack(ack)
                except ValueError as exc:
                    result.is_open = True
                    result.error = str(exc)
                    return None

                result.is_open = True
                result.is_jrmp = True
                result.jrmp_version = info.get("version")
                result.jrmp_host = info.get("hostname")
                result.jrmp_port = info.get("port")
                return ack
        except ConnectionError as exc:
            result.error = str(exc)
            return None

    def _registry_list(
        self,
        host: str,
        port: int,
        _ack_data: bytes,
        result: RmiScanResult,
    ) -> None:
        """Send a Registry list() call and parse the response."""
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack = sess.recv(512, exact=False)
                if not ack:
                    return
                try:
                    parse_jrmp_ack(ack)
                except ValueError:
                    return

                sess.send(build_list_call())
                raw = sess.recv_all(timeout=_RECV_TIMEOUT)
                result.raw_return_bytes = raw

                if not raw:
                    return

                parsed = parse_registry_return(raw)
                if "error" not in parsed:
                    result.is_registry = True
                    result.bound_names = parsed.get("names", [])
                elif "names" in parsed:
                    result.is_registry = True
                    result.bound_names = parsed.get("names", [])
        except ConnectionError:
            pass

    def _registry_lookups(
        self, host: str, port: int, result: RmiScanResult
    ) -> None:
        """Call lookup() for each bound name and extract class/endpoint info."""
        for name in result.bound_names:
            try:
                with TCPSession(host, port, timeout=self.timeout) as sess:
                    sess.send(build_jrmp_handshake())
                    ack = sess.recv(512, exact=False)
                    if not ack:
                        continue
                    try:
                        parse_jrmp_ack(ack)
                    except ValueError:
                        continue

                    sess.send(build_lookup_call(name))
                    raw = sess.recv_all(timeout=_RECV_TIMEOUT)
                    if not raw:
                        continue

                    parsed = parse_lookup_return(raw)
                    if parsed.get("class_name"):
                        result.name_types[name] = parsed["class_name"]
                    if parsed.get("endpoint"):
                        result.stub_endpoints[name] = parsed["endpoint"]
            except ConnectionError:
                continue

    def _urldns_probe(
        self, host: str, port: int, canary: str, result: RmiScanResult
    ) -> None:
        """Send a URLDNS ysoserial payload via DGC to detect blind deser."""
        try:
            from javapwner.core.payload import YsoserialWrapper
            wrapper = YsoserialWrapper()
            payload = wrapper.generate_urldns(canary)
        except Exception:
            return

        dgc_call = _build_dgc_dirty_call(payload)
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack = sess.recv(512, exact=False)
                if not ack:
                    return
                try:
                    parse_jrmp_ack(ack)
                except ValueError:
                    return
                sess.send(dgc_call)
                sess.recv_all(timeout=_RECV_TIMEOUT)
                result.urldns_sent = True
                result.urldns_canary = canary
        except ConnectionError:
            pass

    def _dgc_probe(self, host: str, port: int, result: RmiScanResult) -> None:
        """DGC JEP 290 probe using a harmless serialised HashMap."""
        hashmap_payload = _build_hashmap_payload()
        dgc_call = _build_dgc_dirty_call(hashmap_payload)

        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack = sess.recv(512, exact=False)
                if not ack:
                    return
                try:
                    parse_jrmp_ack(ack)
                except ValueError:
                    return

                result.dgc_reachable = True
                sess.send(dgc_call)
                response = sess.recv_all(timeout=_RECV_TIMEOUT)

                if detect_exception_in_stream(response):
                    result.jep290_active = True
                else:
                    result.jep290_active = False
        except ConnectionError:
            pass


# ---------------------------------------------------------------------------
# DGC helpers (self-contained, no dependency on jini/jrmp.py)
# ---------------------------------------------------------------------------

_DGC_OP_INDEX = _struct.pack(">i", 1)          # dirty() op index (old-style dispatch)
# DGC interface hash — source: sun/rmi/transport/DGCImpl_Skel.class
# 0xF6B6898D8BF28643 unsigned = -669196253586618813 signed int64
_DGC_INTERFACE_HASH = _struct.pack(">q", -669196253586618813)


def _build_dgc_dirty_call(payload_bytes: bytes) -> bytes:
    """Wrap *payload_bytes* in a JRMP DGC dirty() call."""
    return bytes([MSG_CALL]) + DGC_OBJID + _DGC_OP_INDEX + _DGC_INTERFACE_HASH + payload_bytes


def _build_hashmap_payload() -> bytes:
    """Return a minimal serialised java.util.HashMap (empty, harmless probe)."""
    return bytes.fromhex(
        "aced0005"
        "73"
        "72"
        "0012"
        "6a6176612e7574696c2e486173684d6170"
        "0507dac1c31660d1"
        "03"
        "0002"
        "46"
        "000a"
        "6c6f6164466163746f72"
        "49"
        "0009"
        "7468726573686f6c64"
        "7870"
        "3f400000"
        "00000000"
        "7708"
        "00000010"
        "00000000"
        "78"
    )
