"""JiniScanner — TCP + UDP probe with JRMP and Unicast Discovery detection."""

from __future__ import annotations

import socket
import struct
import threading
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.socket_helper import TCPSession, UDPSession, JINI_MULTICAST_GROUP
from javapwner.exceptions import ConnectionError, JrmpError, ProtocolError
from javapwner.protocols.jini import jrmp, protocol

DEFAULT_PORT = 4160
_RECV_TIMEOUT = 3.0   # seconds to wait for first response byte


@dataclass
class MulticastDiscoveryResult:
    """Result of an active Multicast Discovery Request."""
    sent: bool = False
    responders: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "responder_count": len(self.responders),
            "responders": self.responders,
            "error": self.error,
        }


@dataclass
class ScanResult:
    host: str
    port: int
    is_open: bool = False
    is_jrmp: bool = False
    jrmp_version: int | None = None
    jrmp_host: str | None = None
    jrmp_port: int | None = None
    has_unicast_response: bool = False
    unicast_version: int | None = None
    raw_proxy_bytes: bytes = field(default=b"", repr=False)
    groups: list[str] = field(default_factory=list)
    fingerprint_strings: list[str] = field(default_factory=list)
    udp_response: bool = False

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_open": self.is_open,
            "is_jrmp": self.is_jrmp,
            "jrmp_version": self.jrmp_version,
            "jrmp_host": self.jrmp_host,
            "jrmp_port": self.jrmp_port,
            "has_unicast_response": self.has_unicast_response,
            "unicast_version": self.unicast_version,
            "raw_proxy_bytes": self.raw_proxy_bytes.hex(),
            "groups": self.groups,
            "fingerprint_strings": self.fingerprint_strings,
            "udp_response": self.udp_response,
        }


class JiniScanner:
    """Probes a host:port for Apache River / Jini services."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, host: str, port: int = DEFAULT_PORT) -> ScanResult:
        result = ScanResult(host=host, port=port)

        # Step 1: TCP port probe
        result.is_open = self._tcp_probe(host, port)
        if not result.is_open:
            return result

        # Step 2: JRMP handshake
        self._jrmp_probe(host, port, result)

        # Step 3: Unicast Discovery v1
        if not self._unicast_v1_probe(host, port, result):
            # Step 4: fall back to Unicast Discovery v2
            self._unicast_v2_probe(host, port, result)

        # Step 5: UDP multicast probe
        self._udp_probe(result)

        return result

    # ------------------------------------------------------------------
    # Individual probes
    # ------------------------------------------------------------------

    def _tcp_probe(self, host: str, port: int) -> bool:
        try:
            with TCPSession(host, port, timeout=self.timeout):
                pass
            return True
        except ConnectionError:
            return False

    def _jrmp_probe(self, host: str, port: int, result: ScanResult) -> None:
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(jrmp.build_jrmp_handshake())
                data = sess.recv(256, exact=False)
                if not data:
                    return
                ack = jrmp.parse_jrmp_ack(data)
                result.is_jrmp = True
                result.jrmp_version = ack.get("version")
                result.jrmp_host = ack.get("hostname")
                result.jrmp_port = ack.get("port")
        except (ConnectionError, JrmpError):
            pass

    def _unicast_v1_probe(self, host: str, port: int, result: ScanResult) -> bool:
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(protocol.build_unicast_request_v1())
                data = sess.recv_all(timeout=_RECV_TIMEOUT)
                if not data:
                    return False
                parsed = protocol.parse_unicast_response_v1(data)
                if parsed["is_valid"]:
                    result.has_unicast_response = True
                    result.unicast_version = 1
                    result.raw_proxy_bytes = data
                    result.groups = parsed["groups"]
                    result.fingerprint_strings = parsed["fingerprint_strings"]
                    return True
        except (ConnectionError, ProtocolError):
            pass
        return False

    def _unicast_v2_probe(self, host: str, port: int, result: ScanResult) -> None:
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(protocol.build_unicast_request_v2())
                data = sess.recv_all(timeout=_RECV_TIMEOUT)
                if not data:
                    return
                parsed = protocol.parse_unicast_response_v2(data)
                if parsed["is_valid"]:
                    result.has_unicast_response = True
                    result.unicast_version = 2
                    result.raw_proxy_bytes = data
                    result.groups = parsed["groups"]
                    result.fingerprint_strings = parsed["fingerprint_strings"]
                    if parsed.get("host"):
                        result.jrmp_host = result.jrmp_host or parsed["host"]
                    if parsed.get("port"):
                        result.jrmp_port = result.jrmp_port or parsed["port"]
        except (ConnectionError, ProtocolError):
            pass

    def _udp_probe(self, result: ScanResult) -> None:
        """Passive UDP multicast listen — see if any Reggie is announcing."""
        try:
            udp = UDPSession(timeout=2.0)
            # Send a minimal Unicast v1 request as a multicast datagram
            data = udp.recv_multicast(group=JINI_MULTICAST_GROUP, port=result.port)
            if data:
                result.udp_response = True
        except ConnectionError:
            pass

    # ------------------------------------------------------------------
    # Active Multicast Discovery
    # ------------------------------------------------------------------

    def multicast_discover(
        self,
        groups: list[str] | None = None,
        wait: float = 3.0,
    ) -> MulticastDiscoveryResult:
        """Send a Multicast Discovery Request and collect unicast responses.

        Opens a TCP server on a random port, sends a Multicast Request v1
        datagram to ``224.0.1.85:4160`` advertising that port, then waits
        up to *wait* seconds for Reggie instances to connect back and
        deliver their Unicast Discovery responses.

        Returns a :class:`MulticastDiscoveryResult` with one entry per
        responding Reggie.
        """
        mdr = MulticastDiscoveryResult()
        responders: list[dict[str, Any]] = []

        # 1. Open a TCP server socket on a random port
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind(("0.0.0.0", 0))
            srv.listen(16)
            srv.settimeout(wait)
            callback_port = srv.getsockname()[1]
        except OSError as exc:
            mdr.error = f"TCP listen failed: {exc}"
            srv.close()
            return mdr

        # 2. Accept connections in a background thread
        def _accept_loop() -> None:
            while True:
                try:
                    conn, addr = srv.accept()
                except (socket.timeout, OSError):
                    break
                try:
                    conn.settimeout(self.timeout)
                    data = b""
                    while True:
                        chunk = conn.recv(8192)
                        if not chunk:
                            break
                        data += chunk
                        if len(data) > 131072:
                            break
                    if data:
                        entry: dict[str, Any] = {
                            "source": f"{addr[0]}:{addr[1]}",
                        }
                        # Try parsing as v1 first, then v2
                        parsed = protocol.parse_unicast_response_v1(data)
                        if parsed["is_valid"]:
                            entry["unicast_version"] = 1
                            entry["groups"] = parsed["groups"]
                            entry["fingerprint_strings"] = parsed["fingerprint_strings"]
                        else:
                            try:
                                parsed = protocol.parse_unicast_response_v2(data)
                                if parsed["is_valid"]:
                                    entry["unicast_version"] = 2
                                    entry["host"] = parsed.get("host")
                                    entry["port"] = parsed.get("port")
                                    entry["groups"] = parsed["groups"]
                                    entry["fingerprint_strings"] = parsed["fingerprint_strings"]
                            except ProtocolError:
                                entry["raw_hex"] = data[:256].hex()
                        responders.append(entry)
                except Exception:
                    pass
                finally:
                    conn.close()

        accept_thread = threading.Thread(target=_accept_loop, daemon=True)
        accept_thread.start()

        # 3. Send multicast request
        try:
            request_data = protocol.build_multicast_request_v1(
                callback_port=callback_port, groups=groups,
            )
            udp = UDPSession(timeout=2.0)
            udp.send_multicast(request_data, group=JINI_MULTICAST_GROUP, port=DEFAULT_PORT)
            mdr.sent = True
        except ConnectionError as exc:
            mdr.error = f"Multicast send failed: {exc}"

        # 4. Wait for responses
        accept_thread.join(timeout=wait + 1.0)
        srv.close()

        mdr.responders = responders
        return mdr
