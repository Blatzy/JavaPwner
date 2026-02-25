"""JBoss / WildFly scanner — fingerprint + invoker enumeration.

Replaces the NotImplementedError stub with a real scanner that:

1. Fingerprints the target (HTTP banner + binary Remoting 2 probe).
2. Enumerates reachable HTTP invoker endpoints.
3. Reports likely exploit vectors with CVE references.
"""

from __future__ import annotations

import socket
from dataclasses import dataclass, field
from typing import Any

from javapwner.protocols.jboss.fingerprint import JBossFingerprint, JBossFingerprinter
from javapwner.protocols.jboss.invoker import HttpInvoker

# CVE context per invoker path
_PATH_CVE_MAP = {
    "/invoker/JMXInvokerServlet": "CVE-2015-7501",
    "/invoker/EJBInvokerServlet": "CVE-2017-7504",
    "/invoker/readonly": "CVE-2017-12149",
    "/web-console/Invoker": "CVE-2015-7501 (web-console variant)",
}


@dataclass
class JBossScanResult:
    """Full result of a JBoss scan."""

    host: str
    port: int

    # Connectivity
    is_open: bool = False

    # Fingerprint
    fingerprint: JBossFingerprint | None = None

    # HTTP invoker
    invoker_endpoints: list[str] = field(default_factory=list)
    invoker_cves: list[str] = field(default_factory=list)

    # Error
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "is_open": self.is_open,
            "fingerprint": self.fingerprint.to_dict() if self.fingerprint else None,
            "invoker_endpoints": self.invoker_endpoints,
            "invoker_cves": self.invoker_cves,
            "error": self.error,
        }


class JBossScanner:
    """Scan a JBoss / WildFly endpoint for fingerprint and exploit surface.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    DEFAULT_PORT = 8080

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def scan(self, host: str, port: int) -> JBossScanResult:
        """Run the full scan: fingerprint → invoker enumeration."""
        result = JBossScanResult(host=host, port=port)

        # Step 1: fingerprint
        fingerprinter = JBossFingerprinter(timeout=self.timeout)
        try:
            fp = fingerprinter.fingerprint(host, port)
            result.fingerprint = fp
            if fp.is_jboss or fp.invoker_paths or fp.remoting2_confirmed:
                result.is_open = True
        except Exception as exc:
            result.error = f"Fingerprint error: {exc}"
            return result

        if not result.is_open:
            # Try a basic TCP connect to confirm the port is open at all
            try:
                with socket.create_connection((host, port), timeout=self.timeout):
                    result.is_open = True
            except OSError:
                result.error = f"Port {port} closed or filtered"
                return result

        # Step 2: HTTP invoker enumeration
        invoker = HttpInvoker(timeout=self.timeout)
        try:
            reachable = invoker.probe_endpoints(host, port)
            result.invoker_endpoints = reachable
            result.invoker_cves = [
                _PATH_CVE_MAP[p] for p in reachable if p in _PATH_CVE_MAP
            ]
        except Exception as exc:
            result.error = f"Invoker probe error: {exc}"

        return result
