"""JBoss Remoting 3 / JBoss Marshalling fingerprinter.

WildFly 8+ uses JBoss Remoting 3 (fully re-written binary protocol) for
EJB and management communication.  The default port is ``8080`` (HTTP
Upgrade) or ``4447`` (native Remoting 3).

Detection: we send the JBoss Remoting 3 channel open bytes and check for
a valid response frame.  The wire format is:
  - Frame header: 1-byte type + 3-byte length
  - Type 0x00 = GREETING
"""

from __future__ import annotations

import socket
from dataclasses import dataclass
from typing import Any


@dataclass
class Remoting3Fingerprint:
    """Result of probing for JBoss Remoting 3."""
    is_remoting3: bool = False
    server_name: str | None = None
    channel_type: str | None = None
    # SASL ANONYMOUS auth means no credentials required for channel open
    sasl_anonymous: bool = False
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "is_remoting3": self.is_remoting3,
            "server_name": self.server_name,
            "channel_type": self.channel_type,
            "sasl_anonymous": self.sasl_anonymous,
            "error": self.error,
        }


class JBossRemoting3Fingerprinter:
    """Detect JBoss Remoting 3 endpoints.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def fingerprint(self, host: str, port: int) -> Remoting3Fingerprint:
        """Probe *host:port* for a JBoss Remoting 3 service."""
        result = Remoting3Fingerprint()

        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)

                # Send a minimal Remoting 3 GREETING
                # Greeting frame: type=0x00, length=0x000000
                greeting = b"\x00\x00\x00\x00"
                sock.sendall(greeting)

                # Read response
                try:
                    response = sock.recv(256)
                except socket.timeout:
                    result.error = "No response (timeout)"
                    return result

                if not response:
                    result.error = "Empty response"
                    return result

                # Detect Remoting 3 GREETING response
                # The server echoes a greeting frame with supported capabilities
                if len(response) >= 4:
                    frame_type = response[0]
                    if frame_type == 0x00:
                        # GREETING frame
                        result.is_remoting3 = True
                        self._parse_greeting(response[4:], result)
                    elif response[:4] == b"\x47\x45\x54\x20":
                        # HTTP response — might be HTTP Upgrade endpoint
                        result.error = "HTTP endpoint (try HTTP Upgrade)"

                # Also try HTTP Upgrade detection
                if not result.is_remoting3:
                    self._try_http_upgrade(host, port, result)

        except OSError as exc:
            result.error = str(exc)

        return result

    def _parse_greeting(self, data: bytes, result: Remoting3Fingerprint) -> None:
        """Extract capabilities from a Remoting 3 GREETING response.

        Also detects SASL ANONYMOUS capability — when advertised, the endpoint
        may allow unauthenticated channel opens (relevant for deserialization
        attacks without credentials on EAP 6 / WildFly 8+).
        """
        i = 0
        while i < len(data) - 2:
            cap_type = data[i]
            cap_len = data[i + 1]
            if i + 2 + cap_len > len(data):
                break
            cap_data = data[i + 2:i + 2 + cap_len]

            if cap_type == 0x00 and cap_data:
                # Server name / version
                try:
                    result.server_name = cap_data.decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif cap_type == 0x01 and cap_data:
                try:
                    result.channel_type = cap_data.decode("utf-8", errors="replace")
                except Exception:
                    pass
            elif cap_type == 0x03 and cap_data:
                # SASL mechanisms list (space or comma separated)
                try:
                    mechs = cap_data.decode("utf-8", errors="replace")
                    if "ANONYMOUS" in mechs.upper():
                        result.sasl_anonymous = True
                except Exception:
                    pass

            i += 2 + cap_len

    def _try_http_upgrade(
        self, host: str, port: int, result: Remoting3Fingerprint
    ) -> None:
        """Attempt HTTP Upgrade to ``jboss-remoting`` protocol."""
        try:
            with socket.create_connection((host, port), timeout=self.timeout) as sock:
                sock.settimeout(self.timeout)

                # HTTP Upgrade request for Remoting 3
                upgrade_req = (
                    f"GET / HTTP/1.1\r\n"
                    f"Host: {host}:{port}\r\n"
                    f"Upgrade: jboss-remoting\r\n"
                    f"Connection: Upgrade\r\n"
                    f"Sec-JbossRemoting-Key: test\r\n"
                    f"\r\n"
                ).encode()

                sock.sendall(upgrade_req)

                try:
                    response = sock.recv(1024)
                except socket.timeout:
                    return

                if not response:
                    return

                resp_text = response.decode("utf-8", errors="replace").lower()
                # Check for HTTP/1.1 101 Switching Protocols on the first line
                first_line = resp_text.split("\n", 1)[0].strip()
                if (
                    ("101" in first_line and "switching" in resp_text)
                    or ("101" in first_line and "upgrade" in resp_text)
                ):
                    result.is_remoting3 = True
                    result.channel_type = "http-upgrade"

        except OSError:
            pass
