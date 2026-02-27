"""JiniProbe — active probes for codebase URLs, JRMP endpoints, and DGC fingerprinting.

Probes provided:

* :class:`CodebaseProbeResult` / ``probe_codebase`` — extract all codebase URLs
  from the raw proxy blob, test HTTP/HTTPS reachability, and flag accessible
  URLs as RMI codebase attack vectors.

* :class:`EndpointProbeResult` / ``probe_endpoint`` — extract (host, port) hints
  from TCPEndpoint structures embedded in the serialised proxy, then confirm
  each candidate by attempting a real JRMP handshake.

* :class:`DgcFingerprintResult` / ``probe_dgc`` — fingerprint DGC deserialization
  filters (JEP 290) without requiring ysoserial.  Sends a crafted DGC dirty()
  call with a ``java.util.HashMap`` payload and analyses the server response.
"""

from __future__ import annotations

import struct
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.serialization import (
    JAVA_SERIAL_HEADER,
    TC_BLOCKDATA,
    TC_EXCEPTION,
    TC_OBJECT,
    detect_exception_in_stream,
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


@dataclass
class DgcFingerprintResult:
    """Results of a DGC-based JEP 290 / deserialization filter fingerprint.

    This probe does **not** require ysoserial — it crafts a minimal DGC
    dirty() call embedding a ``java.util.HashMap`` instance and analyses
    the server response.

    Possible outcomes:

    * ``jep290_active = True`` — the server rejected the HashMap with a
      ``TC_EXCEPTION``, indicating that deserialization filters (JEP 290) are
      installed on the DGC endpoint.  RCE via DGC dirty() is unlikely.
    * ``jep290_active = False`` — the HashMap was **not** rejected.  The DGC
      endpoint does **not** appear to filter deserialization, so ysoserial
      payloads delivered via DGC dirty() should work.
    * ``dgc_reachable = False`` — the DGC endpoint did not respond at all
      (port filtered, timeout, or not a JRMP endpoint).
    """

    dgc_reachable: bool = False
    jep290_active: bool | None = None  # None = unknown / unreachable
    response_bytes: bytes = field(default=b"", repr=False)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        status: str
        if not self.dgc_reachable:
            status = "unreachable"
        elif self.jep290_active is True:
            status = "filtered (JEP 290)"
        elif self.jep290_active is False:
            status = "unfiltered — RCE likely"
        else:
            status = "unknown"
        return {
            "dgc_reachable": self.dgc_reachable,
            "jep290_active": self.jep290_active,
            "status": status,
            "error": self.error,
        }


class JiniProbe:
    """Active probes for codebase URLs, embedded JRMP endpoints, and DGC filters."""

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

    # ------------------------------------------------------------------
    # DGC JEP 290 fingerprint
    # ------------------------------------------------------------------

    def probe_dgc(
        self, host: str, port: int
    ) -> DgcFingerprintResult:
        """Fingerprint DGC deserialization filters — **no ysoserial required**.

        Sends a DGC dirty() call containing a harmless
        ``java.util.HashMap`` instance.  On a JEP-290-protected endpoint the
        HashMap will be **rejected** by the built-in DGC filter and the server
        responds with ``TC_EXCEPTION``.  On an unprotected endpoint the HashMap
        passes through (dirty() raises an internal error *after*
        deserialization).

        This is the same technique used by *remote-method-guesser*'s
        ``enum`` action ("RMI server JEP290 enumeration").
        """
        result = DgcFingerprintResult()

        # Build a minimal Java serialised stream containing a HashMap
        hashmap_payload = self._build_hashmap_payload()
        dgc_call = jrmp.build_dgc_dirty_call(hashmap_payload)

        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(jrmp.build_jrmp_handshake())
                ack = sess.recv(256, exact=False)
                if not ack:
                    result.error = "No JRMP handshake response"
                    return result

                try:
                    jrmp.parse_jrmp_ack(ack)
                except Exception:
                    result.error = "Invalid JRMP ack — not a JRMP endpoint"
                    return result

                result.dgc_reachable = True

                sess.send(jrmp.build_client_endpoint())
                sess.send(dgc_call)
                response = sess.recv_all(timeout=_JRMP_TIMEOUT)
                result.response_bytes = response

                # Analyse the response
                if detect_exception_in_stream(response):
                    result.jep290_active = True
                else:
                    # No TC_EXCEPTION → the HashMap was *not* filtered.
                    result.jep290_active = False

        except ConnectionError as exc:
            result.error = f"Connection failed: {exc}"
        except Exception as exc:  # noqa: BLE001
            result.error = f"Unexpected error: {exc}"

        return result

    @staticmethod
    def _build_hashmap_payload() -> bytes:
        """Build a minimal Java serialised ``java.util.HashMap``.

        This is a well-formed, self-contained ``ObjectOutputStream`` that
        contains an empty HashMap.  It is used as a deserialization probe:
        the DGC filter blocks it on JEP-290 endpoints, but it is completely
        harmless on unprotected endpoints.

        Wire format (hex)::

            AC ED 00 05          → stream magic + version
            73                   → TC_OBJECT
            72                   → TC_CLASSDESC
            00 12                → class name length = 18
            6A 61 76 61 ...      → "java.util.HashMap"
            05 07 DA C1 C3 16 60 D1  → serialVersionUID
            03                   → SC_WRITE_METHOD | SC_SERIALIZABLE
            00 02                → 2 fields
            46 00 0A             → float "loadFactor"
            6C 6F 61 64 46 61 63 74 6F 72
            49 00 09             → int "threshold"
            74 68 72 65 73 68 6F 6C 64
            78 70               → TC_ENDBLOCKDATA + TC_NULL (superclass)
            3F 40 00 00          → loadFactor = 0.75
            00 00 00 00          → threshold = 0
            77 08                → TC_BLOCKDATA, length = 8
            00 00 00 10          → capacity = 16
            00 00 00 00          → size = 0
            78                   → TC_ENDBLOCKDATA
        """
        return bytes.fromhex(
            "aced0005"              # STREAM_MAGIC + STREAM_VERSION
            "73"                    # TC_OBJECT
            "72"                    # TC_CLASSDESC
            "0012"                  # length=18
            "6a6176612e7574696c"    # "java.util"
            "2e486173684d6170"      # ".HashMap"
            "0507dac1c31660d1"      # serialVersionUID
            "03"                    # flags: SC_WRITE_METHOD | SC_SERIALIZABLE
            "0002"                  # 2 fields
            # field 1: float loadFactor
            "46"                    # 'F' — float
            "000a"                  # length=10
            "6c6f6164466163746f72"  # "loadFactor"
            # field 2: int threshold
            "49"                    # 'I' — int
            "0009"                  # length=9
            "7468726573686f6c64"    # "threshold"
            "7870"                  # TC_ENDBLOCKDATA + TC_NULL (no superclass)
            "3f400000"              # loadFactor = 0.75f
            "00000000"              # threshold = 0
            "7708"                  # TC_BLOCKDATA (8 bytes)
            "00000010"              # capacity = 16
            "00000000"              # size = 0
            "78"                    # TC_ENDBLOCKDATA
        )
