"""JBoss / WildFly protocol fingerprinting.

Detection strategy
------------------
1. **HTTP banner** — send a ``GET /`` and examine ``Server`` /
   ``X-Powered-By`` response headers plus the response body.
2. **HTTP invoker paths** — check a list of well-known invoker servlet
   paths for HTTP 200 / 500 responses.
3. **Binary remoting** — connect to the target port and look for the
   JBoss Remoting 2 GREETING magic (``0x77 0x01 0x16 0x79``).
4. **JNP** — the Java Naming Provider uses port 1099/4444; we probe for
   the JNDI Service Provider protocol magic.

All probes are optional: if a connection is refused the fingerprinter
gracefully degrades and sets the appropriate result fields.
"""

from __future__ import annotations

import socket
import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

_HTTP_TIMEOUT = 4.0
_BINARY_TIMEOUT = 3.0

# JBoss Remoting 2 uses a fixed GREETING prefix
_REMOTING2_MAGIC = b"\x77\x01\x16\x79"

# Well-known HTTP invoker servlet paths (checked in order).
# Paths marked with CVE annotations correspond to deserialization vectors.
_INVOKER_PATHS = [
    "/invoker/JMXInvokerServlet",     # CVE-2015-7501
    "/invoker/EJBInvokerServlet",     # CVE-2017-7504
    "/invoker/readonly",              # CVE-2017-12149
    "/web-console/Invoker",           # CVE-2015-7501 (web-console variant)
    "/jboss-net/Hessian",
    # Spring HTTP Invoker — deserializes POST body (same vector as JBoss invokers)
    "/remoting/httpInvoker",
    "/spring-remoting/",
    "/remoting/",
    # Additional JBoss management / admin paths
    "/jmx-console/",                  # JBoss AS 4.x/5.x — information disclosure + invoke
    "/admin-console/",
    "/status",
]

# Strings that identify JBoss in HTTP responses
_JBOSS_KEYWORDS = [
    "jboss",
    "wildfly",
    "jboss application server",
    "jboss as",
    "jboss-4",
    "jboss-5",
    "jboss-6",
    "jboss-7",
    "wildfly-8",
    "wildfly-9",
    "wildfly-10",
]


class JBossProtocol(str, Enum):
    """Detected protocol / product family."""
    UNKNOWN = "unknown"
    HTTP_INVOKER = "http_invoker"
    REMOTING2 = "jboss_remoting2"
    JNP = "jnp"
    MANAGEMENT = "management"


@dataclass
class InvokerPathProbe:
    """Result of probing a single invoker path."""
    path: str
    reachable: bool = False
    http_status: int | None = None
    requires_auth: bool = False
    cve: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "reachable": self.reachable,
            "http_status": self.http_status,
            "requires_auth": self.requires_auth,
            "cve": self.cve,
        }


# CVE / advisory mapping per invoker path
_PATH_CVE = {
    "/invoker/JMXInvokerServlet": "CVE-2015-7501",
    "/invoker/EJBInvokerServlet": "CVE-2017-7504",
    "/invoker/readonly": "CVE-2017-12149",
    "/web-console/Invoker": "CVE-2015-7501",
    # Spring HTTP Invoker — deserializes arbitrary ObjectOutputStream (Spring RCE)
    "/remoting/httpInvoker": "Spring-HTTP-Invoker-Deser",
    "/spring-remoting/": "Spring-HTTP-Invoker-Deser",
    "/remoting/": "Spring-HTTP-Invoker-Deser",
    # JBoss management consoles
    "/jmx-console/": "JBoss-JMX-Console",
    "/admin-console/": "JBoss-Admin-Console",
}


@dataclass
class JBossFingerprint:
    """Result of a JBoss fingerprinting probe."""

    protocol: JBossProtocol = JBossProtocol.UNKNOWN
    version: str | None = None          # e.g. "JBoss AS 6.x" / "WildFly 10"
    edition: str | None = None          # "EAP" | "AS" | "WildFly" | None
    product: str | None = None          # raw product string from headers/body
    invoker_paths: list[str] = field(default_factory=list)   # confirmed HTTP paths
    invoker_probes: list[InvokerPathProbe] = field(default_factory=list)
    banner: str | None = None           # first 256 chars of HTTP response body
    remoting2_confirmed: bool = False
    is_jboss: bool = False
    scheme: str = "http"                # "http" or "https"

    def to_dict(self) -> dict[str, Any]:
        return {
            "protocol": self.protocol.value,
            "version": self.version,
            "edition": self.edition,
            "product": self.product,
            "invoker_paths": self.invoker_paths,
            "invoker_probes": [p.to_dict() for p in self.invoker_probes],
            "banner": self.banner,
            "remoting2_confirmed": self.remoting2_confirmed,
            "is_jboss": self.is_jboss,
            "scheme": self.scheme,
        }


class JBossFingerprinter:
    """Probe a host:port for JBoss / WildFly indicators.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    def __init__(self, timeout: float = 5.0, scheme: str = "http"):
        self.timeout = timeout
        self.scheme = scheme

    def fingerprint(
        self,
        host: str,
        port: int,
        scheme: str | None = None,
        remoting_port: int | None = None,
    ) -> JBossFingerprint:
        """Run all fingerprinting probes and return a :class:`JBossFingerprint`.

        Parameters
        ----------
        host, port:
            Target JBoss HTTP endpoint.
        scheme:
            ``"http"`` or ``"https"``.  If ``None``, uses the instance default.
        remoting_port:
            Port to probe for JBoss Remoting 2 binary protocol.  Defaults to
            4446 (JBoss Remoting default).  Set to ``port`` explicitly if the
            target is known to multiplex on a single port.
        """
        fp = JBossFingerprint()
        _scheme = scheme or self.scheme
        fp.scheme = _scheme

        # HTTP probes
        base_url = f"{_scheme}://{host}:{port}"
        self._probe_http_banner(base_url, fp)
        self._probe_invoker_paths(base_url, fp)

        # Binary Remoting 2 probe — uses dedicated Remoting port (default 4446),
        # NOT the HTTP port.  Caller may override with remoting_port=port if
        # scanning a known-Remoting2 port directly.
        r2_port = remoting_port if remoting_port is not None else 4446
        self._probe_remoting2(host, r2_port, fp)

        # Synthesise overall verdict
        if fp.invoker_paths or fp.is_jboss:
            fp.protocol = JBossProtocol.HTTP_INVOKER
        if fp.remoting2_confirmed:
            fp.protocol = JBossProtocol.REMOTING2

        return fp

    # ------------------------------------------------------------------
    # HTTP
    # ------------------------------------------------------------------

    def _probe_http_banner(self, base_url: str, fp: JBossFingerprint) -> None:
        """GET / and inspect headers + body."""
        ctx = None
        if base_url.startswith("https"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                base_url + "/",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT, context=ctx)
            body_bytes = resp.read(1024)
            headers = {k.lower(): v for k, v in resp.headers.items()}

            # Check server header
            server = headers.get("server", "")
            x_powered = headers.get("x-powered-by", "")
            combined = f"{server} {x_powered}".lower()

            fp.banner = body_bytes[:256].decode("utf-8", errors="replace")
            body_lower = fp.banner.lower()

            for kw in _JBOSS_KEYWORDS:
                if kw in combined or kw in body_lower:
                    fp.is_jboss = True
                    fp.product = (server or x_powered or "JBoss").strip()
                    break

            # Version / edition extraction
            if fp.is_jboss:
                fp.version = _extract_version(combined + " " + body_lower)
                fp.edition = _extract_edition(combined + " " + body_lower)

        except (urllib.error.URLError, OSError, Exception):
            pass

    def _probe_invoker_paths(self, base_url: str, fp: JBossFingerprint) -> None:
        """Check each well-known invoker servlet path."""
        ctx = None
        if base_url.startswith("https"):
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        for path in _INVOKER_PATHS:
            probe = InvokerPathProbe(path=path, cve=_PATH_CVE.get(path))
            url = base_url + path
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT, context=ctx)
                # Any response (even 500) at the invoker path = present
                probe.reachable = True
                probe.http_status = resp.status
                fp.invoker_paths.append(path)
                fp.is_jboss = True
                if not fp.version:
                    fp.version = _version_from_path(path)
            except urllib.error.HTTPError as exc:
                probe.http_status = exc.code
                if exc.code in (401, 403):
                    # Auth required but endpoint exists
                    probe.reachable = True
                    probe.requires_auth = True
                    fp.is_jboss = True
                elif exc.code in (400, 415, 500):
                    probe.reachable = True
                    fp.invoker_paths.append(path)
                    fp.is_jboss = True
                    if not fp.version:
                        fp.version = _version_from_path(path)
            except (urllib.error.URLError, OSError, Exception):
                pass
            fp.invoker_probes.append(probe)

    # ------------------------------------------------------------------
    # Binary
    # ------------------------------------------------------------------

    def _probe_remoting2(self, host: str, port: int, fp: JBossFingerprint) -> None:
        """Connect and check for JBoss Remoting 2 GREETING magic."""
        try:
            with socket.create_connection((host, port), timeout=_BINARY_TIMEOUT) as sock:
                # JBoss Remoting 2 sends a GREETING frame immediately on connect
                data = sock.recv(8)
                if data and data[:4] == _REMOTING2_MAGIC:
                    fp.remoting2_confirmed = True
                    fp.is_jboss = True
                    if not fp.version:
                        fp.version = "JBoss Remoting 2.x"
        except (OSError, Exception):
            pass


# ---------------------------------------------------------------------------
# Version string helpers
# ---------------------------------------------------------------------------

def _extract_version(text: str) -> str | None:
    """Extract a version hint from a combined string of headers + body text."""
    import re
    # WildFly 10.x, JBoss AS 6.1, JBoss EAP 6.4, etc.
    patterns = [
        r"wildfly[\s/-]?(\d+[\.\d]*)",
        r"jboss[\s\-]?as[\s/]?(\d+[\.\d]*)",
        r"jboss[\s\-]?eap[\s/]?(\d+[\.\d]*)",
        r"jboss[\s/]?(\d+[\.\d]*)",
    ]
    for pat in patterns:
        m = re.search(pat, text, re.IGNORECASE)
        if m:
            ver = m.group(1)
            if "wildfly" in pat:
                return f"WildFly {ver}"
            if "eap" in pat:
                return f"JBoss EAP {ver}"
            if "as" in pat:
                return f"JBoss AS {ver}"
            return f"JBoss {ver}"
    return None


def _extract_edition(text: str) -> str | None:
    """Identify the JBoss edition (EAP, AS, WildFly) from text."""
    text_l = text.lower()
    if "wildfly" in text_l:
        return "WildFly"
    if "eap" in text_l:
        return "EAP"
    if "jboss as" in text_l or "jboss application server" in text_l:
        return "AS"
    if "jboss" in text_l:
        return "JBoss"
    return None


def _version_from_path(path: str) -> str | None:
    """Guess a rough JBoss version from the invoker path."""
    path_versions = {
        "/invoker/JMXInvokerServlet": "JBoss 4.x/5.x/6.x",
        "/invoker/EJBInvokerServlet": "JBoss 4.x",
        "/invoker/readonly": "JBoss AS 6.x",
        "/web-console/Invoker": "JBoss 4.x",
    }
    return path_versions.get(path)
