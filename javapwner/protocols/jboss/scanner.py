"""JBoss scanner stub — port 4444 (JNP / JNDI).

TODO: Implement JBoss JNP enumeration and exploitation.
"""

from __future__ import annotations


class JBossScanner:
    """Stub scanner for JBoss JNP/JNDI endpoint (port 4444)."""

    DEFAULT_PORT = 4444

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, host: str, port: int) -> dict:
        raise NotImplementedError("JBoss scanner not yet implemented")
