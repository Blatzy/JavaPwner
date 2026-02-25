"""TCP/UDP session helpers and Java I/O primitives (big-endian)."""

import socket
import struct
from typing import Optional

from javapwner.exceptions import ConnectionError


JINI_MULTICAST_GROUP = "224.0.1.85"
JINI_DEFAULT_PORT = 4160


class TCPSession:
    """Context-manager wrapper around a TCP socket with Java-friendly helpers."""

    def __init__(self, host: str, port: int, timeout: float = 5.0):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[socket.socket] = None

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> "TCPSession":
        self.connect()
        return self

    def __exit__(self, *_):
        self.close()

    # ------------------------------------------------------------------
    # Connection
    # ------------------------------------------------------------------

    def connect(self) -> None:
        try:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.settimeout(self.timeout)
            self._sock.connect((self.host, self.port))
        except (OSError, socket.timeout) as exc:
            raise ConnectionError(f"Cannot connect to {self.host}:{self.port}: {exc}") from exc

    def close(self) -> None:
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    # ------------------------------------------------------------------
    # I/O
    # ------------------------------------------------------------------

    def send(self, data: bytes) -> None:
        if not self._sock:
            raise ConnectionError("Socket not connected")
        try:
            self._sock.sendall(data)
        except (OSError, socket.timeout) as exc:
            raise ConnectionError(f"Send failed: {exc}") from exc

    def recv(self, n: int, exact: bool = False) -> bytes:
        """Receive up to *n* bytes. If *exact* is True, loop until all *n* bytes
        arrive or the connection closes."""
        if not self._sock:
            raise ConnectionError("Socket not connected")
        buf = b""
        try:
            while len(buf) < n:
                chunk = self._sock.recv(n - len(buf))
                if not chunk:
                    break
                buf += chunk
                if not exact:
                    break
        except socket.timeout as exc:
            if exact and not buf:
                raise ConnectionError(f"Recv timed out after 0 bytes: {exc}") from exc
        except OSError as exc:
            raise ConnectionError(f"Recv failed: {exc}") from exc
        return buf

    def recv_all(self, timeout: Optional[float] = None) -> bytes:
        """Read until the remote end closes or *timeout* seconds of silence."""
        if not self._sock:
            raise ConnectionError("Socket not connected")
        old_timeout = self._sock.gettimeout()
        if timeout is not None:
            self._sock.settimeout(timeout)
        buf = b""
        try:
            while True:
                chunk = self._sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except socket.timeout:
            pass
        except OSError as exc:
            raise ConnectionError(f"Recv_all failed: {exc}") from exc
        finally:
            if timeout is not None:
                self._sock.settimeout(old_timeout)
        return buf


class UDPSession:
    """Multicast UDP session for Jini discovery."""

    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout

    def send_multicast(self, data: bytes, group: str = JINI_MULTICAST_GROUP,
                       port: int = JINI_DEFAULT_PORT) -> None:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(self.timeout)
            sock.sendto(data, (group, port))
        except OSError as exc:
            raise ConnectionError(f"UDP multicast send failed: {exc}") from exc
        finally:
            sock.close()

    def recv_multicast(self, group: str = JINI_MULTICAST_GROUP,
                       port: int = JINI_DEFAULT_PORT,
                       bufsize: int = 8192) -> bytes:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.settimeout(self.timeout)
            sock.bind(("", port))
            mreq = socket.inet_aton(group) + socket.inet_aton("0.0.0.0")
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)
            data, _ = sock.recvfrom(bufsize)
            return data
        except socket.timeout:
            return b""
        except OSError as exc:
            raise ConnectionError(f"UDP multicast recv failed: {exc}") from exc
        finally:
            sock.close()


# ---------------------------------------------------------------------------
# Java I/O helpers (big-endian, matching java.io.DataOutput / DataInput)
# ---------------------------------------------------------------------------

def read_java_short(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (value, new_offset) for a big-endian signed 16-bit int."""
    val = struct.unpack_from(">h", data, offset)[0]
    return val, offset + 2


def read_java_ushort(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (value, new_offset) for a big-endian unsigned 16-bit int."""
    val = struct.unpack_from(">H", data, offset)[0]
    return val, offset + 2


def read_java_int(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (value, new_offset) for a big-endian signed 32-bit int."""
    val = struct.unpack_from(">i", data, offset)[0]
    return val, offset + 4


def read_java_long(data: bytes, offset: int = 0) -> tuple[int, int]:
    """Return (value, new_offset) for a big-endian signed 64-bit int."""
    val = struct.unpack_from(">q", data, offset)[0]
    return val, offset + 8


def read_java_utf(data: bytes, offset: int = 0) -> tuple[str, int]:
    """Read a Java writeUTF string (2-byte length prefix, UTF-8 payload).
    Returns (string, new_offset)."""
    length = struct.unpack_from(">H", data, offset)[0]
    offset += 2
    raw = data[offset: offset + length]
    return raw.decode("utf-8", errors="replace"), offset + length


def write_java_short(value: int) -> bytes:
    return struct.pack(">h", value)


def write_java_ushort(value: int) -> bytes:
    return struct.pack(">H", value)


def write_java_int(value: int) -> bytes:
    return struct.pack(">i", value)


def write_java_long(value: int) -> bytes:
    return struct.pack(">q", value)


def write_java_utf(value: str) -> bytes:
    """Encode a string as Java writeUTF (2-byte length prefix + UTF-8 payload)."""
    encoded = value.encode("utf-8")
    return struct.pack(">H", len(encoded)) + encoded
