"""RMI scanner stub — ports 8282/8283 (JMX/RMI).

TODO: Implement full RMI registry enumeration and JMX exploitation.
"""

from __future__ import annotations


class RmiScanner:
    """Stub scanner for Java RMI/JMX endpoints (ports 8282, 8283)."""

    DEFAULT_PORTS = (8282, 8283)

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, host: str, port: int) -> dict:
        raise NotImplementedError("RMI scanner not yet implemented")
