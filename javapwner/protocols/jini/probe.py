"""JiniProbe — active probes for codebase URLs and embedded JRMP endpoints.

Two probes are provided:

* :class:`CodebaseProbeResult` / ``probe_codebase`` — extract all codebase URLs
  from the raw proxy blob, test HTTP/HTTPS reachability, and flag accessible
  URLs as RMI codebase attack vectors.

* :class:`EndpointProbeResult` / ``probe_endpoint`` — extract (host, port) hints
  from TCPEndpoint structures embedded in the serialised proxy, then confirm
  each candidate by attempting a real JRMP handshake.
"""

from __future__ import annotations

import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.serialization import (
    extract_endpoint_hints,
    extract_raw_urls,
    find_nested_streams,
)
from javapwner.core.socket_helper import TCPSession
from javapwner.exceptions import ConnectionError
from javapwner.protocols.jini import jrmp
from javapwner.protocols.jini.scanner import JiniScanner, ScanResult

_CODEBASE_TIMEOUT = 3.0
_JRMP_TIMEOUT = 3.0


@dataclass
class CodebaseProbeResult:
    """Results of a codebase-URL probe against a Jini target."""

    urls: list[str] = field(default_factory=list)
    reachable: dict[str, bool] = field(default_factory=dict)
    content_hints: dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "urls": self.urls,
            "reachable": self.reachable,
            "content_hints": self.content_hints,
        }


@dataclass
class EndpointProbeResult:
    """Results of an embedded-endpoint probe against a Jini target."""

    candidates: list[dict] = field(default_factory=list)
    confirmed: dict | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidates": self.candidates,
            "confirmed": self.confirmed,
        }


class JiniProbe:
    """Active probes for codebase URLs and embedded JRMP endpoints."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._scanner = JiniScanner(timeout=timeout)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _get_raw(self, host: str, port: int, scan_result: ScanResult | None) -> bytes:
        if scan_result is None:
            scan_result = self._scanner.scan(host, port)
        return scan_result.raw_proxy_bytes

    # ------------------------------------------------------------------
    # Public probes
    # ------------------------------------------------------------------

    def probe_codebase(
        self, host: str, port: int, scan_result: ScanResult | None = None
    ) -> CodebaseProbeResult:
        """Extract and probe codebase URLs from the serialised proxy blob.

        Steps:
        1. Collect all URLs from the raw stream and every nested stream.
        2. For ``http://`` / ``https://`` URLs attempt a GET with a 3-second
           timeout.  ``file://`` and ``jrmi://`` URLs are marked unreachable
           without any network attempt.
        3. Accessible HTTP/HTTPS URLs are noted as potential RMI codebase
           attack vectors (caller can check ``result.reachable``).
        """
        raw = self._get_raw(host, port, scan_result)
        result = CodebaseProbeResult()

        if not raw:
            return result

        seen: set[str] = set()
        all_urls: list[str] = []

        for url in extract_raw_urls(raw):
            if url not in seen:
                seen.add(url)
                all_urls.append(url)

        for _, sub in find_nested_streams(raw):
            for url in extract_raw_urls(sub):
                if url not in seen:
                    seen.add(url)
                    all_urls.append(url)

        result.urls = all_urls

        for url in all_urls:
            lower = url.lower()
            if lower.startswith("http://") or lower.startswith("https://"):
                try:
                    resp = urllib.request.urlopen(url, timeout=_CODEBASE_TIMEOUT)
                    result.reachable[url] = True
                    try:
                        body = resp.read(256)
                        result.content_hints[url] = body[:200].decode(
                            "utf-8", errors="replace"
                        )
                    except Exception:
                        pass
                except Exception:
                    result.reachable[url] = False
            else:
                result.reachable[url] = False

        return result

    def probe_endpoint(
        self, host: str, port: int, scan_result: ScanResult | None = None
    ) -> EndpointProbeResult:
        """Extract embedded JRMP endpoint hints and confirm via handshake.

        Steps:
        1. Parse the raw proxy blob for (host, port) pairs embedded as
           TC_STRING followed by a big-endian uint32.
        2. For each candidate, open a TCP connection and send the 7-byte JRMP
           handshake.  If the first byte of the response is ``0x4E``
           (ProtocolAck), that candidate is confirmed.
        3. Returns the first confirmed endpoint; ``result.confirmed`` is
           ``None`` if none responded correctly.
        """
        raw = self._get_raw(host, port, scan_result)
        result = EndpointProbeResult()

        if not raw:
            return result

        candidates = extract_endpoint_hints(raw)
        result.candidates = candidates

        for candidate in candidates:
            h, p = candidate["host"], candidate["port"]
            try:
                with TCPSession(h, p, timeout=_JRMP_TIMEOUT) as sess:
                    sess.send(jrmp.build_jrmp_handshake())
                    data = sess.recv(1, exact=False)
                    if data and data[0] == jrmp.PROTOCOL_ACK:
                        result.confirmed = candidate
                        break
            except ConnectionError:
                continue

        return result
