"""JiniEnumerator — deep enumeration of Jini services.

This module combines multiple enumeration sources:

**Tier 1 — Heuristic** (no JVM required):
  Extract class names, strings, URLs, and endpoints from the raw serialised
  proxy blob returned by the Unicast Discovery protocol.

**Tier 1+ — Deep Serial Analysis** (no JVM required):
  Parse ``TC_CLASSDESC`` / ``TC_PROXYCLASSDESC`` entries to build a class
  hierarchy, extract codebase annotation URLs, serial version UIDs, filesystem
  paths, and system information from the stream.

**Tier 1++ — HTTP Codebase Exploitation** (no JVM required):
  Probe the HTTP codebase server for directory listings, test path traversal,
  and read arbitrary files from the target filesystem.

Tier 2 enumeration (full ``ServiceRegistrar.lookup()`` via JVM bridge) is
reserved for future implementation.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.serialization import (
    extract_class_annotations,
    extract_endpoint_hints,
    extract_file_paths,
    extract_raw_urls,
    extract_strings_from_stream,
    extract_system_info,
    find_nested_streams,
    get_stream_metadata,
    parse_class_descriptors,
)
from javapwner.protocols.jini.codebase import CodebaseExploreResult, CodebaseExplorer
from javapwner.protocols.jini.scanner import JiniScanner, ScanResult

# Patterns that suggest interesting Jini / Java RMI class names
_JINI_CLASS_RE = re.compile(r"net\.jini\.|com\.sun\.jini\.|org\.apache\.river\.")
_IFACE_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9_$]*(?:\.[a-zA-Z][a-zA-Z0-9_$]*)+)")
_URL_RE = re.compile(r"((?:jrmi?|http|https|rmi)://[^\s\x00-\x1f\"]+)")


@dataclass
class EnumResult:
    # --- Tier 1 (original) ---
    groups: list[str] = field(default_factory=list)
    extracted_classes: list[str] = field(default_factory=list)
    potential_services: list[dict[str, str]] = field(default_factory=list)
    raw_strings: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    tier: int = 1
    codebase_urls: list[str] = field(default_factory=list)
    embedded_endpoints: list[dict] = field(default_factory=list)
    nested_stream_count: int = 0

    # --- Tier 1+ (deep serial analysis) ---
    class_descriptors: list[dict[str, Any]] = field(default_factory=list)
    class_annotations: list[dict[str, Any]] = field(default_factory=list)
    proxy_interfaces: list[str] = field(default_factory=list)
    serial_version_uids: dict[str, int] = field(default_factory=dict)
    file_paths: list[str] = field(default_factory=list)
    system_info: dict[str, Any] = field(default_factory=dict)

    # --- Tier 1++ (HTTP codebase exploitation) ---
    codebase_exploits: list[CodebaseExploreResult] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "groups": self.groups,
            "extracted_classes": self.extracted_classes,
            "potential_services": self.potential_services,
            "raw_strings": self.raw_strings,
            "urls": self.urls,
            "codebase_urls": self.codebase_urls,
            "embedded_endpoints": self.embedded_endpoints,
            "nested_stream_count": self.nested_stream_count,
            # Deep analysis
            "class_descriptors": self.class_descriptors,
            "class_annotations": self.class_annotations,
            "proxy_interfaces": self.proxy_interfaces,
            "serial_version_uids": self.serial_version_uids,
            "file_paths": self.file_paths,
            "system_info": self.system_info,
            # Codebase exploitation
            "codebase_exploits": [e.to_dict() for e in self.codebase_exploits],
        }


class JiniEnumerator:
    """Deep enumeration of a Jini / Reggie target.

    Combines heuristic string extraction, deep serial stream parsing,
    and HTTP codebase server exploitation into a single ``enumerate()`` call.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._scanner = JiniScanner(timeout=timeout)

    def enumerate(
        self,
        host: str,
        port: int,
        scan_result: ScanResult | None = None,
        *,
        probe_codebase: bool = True,
        progress_cb: "Callable[[str], None] | None" = None,
    ) -> EnumResult:
        """Run all enumeration tiers against *host*:*port*.

        Parameters
        ----------
        host, port:
            Target Jini lookup service.
        scan_result:
            Optional pre-existing :class:`ScanResult` (avoids double scanning).
        probe_codebase:
            If ``True`` (default), also probe HTTP codebase servers.
            The probe is done per-URL; ``progress_cb`` receives live messages.
        progress_cb:
            Optional callable receiving a plain-text status message for each
            long operation (traversal probes, file reads).
        """
        if scan_result is None:
            scan_result = self._scanner.scan(host, port)

        result = EnumResult(groups=scan_result.groups)

        raw = scan_result.raw_proxy_bytes
        if not raw:
            return result

        # === Tier 1: heuristic string extraction ===
        strings = extract_strings_from_stream(raw)
        result.raw_strings = strings

        classes = self._extract_classes(strings)
        result.extracted_classes = classes

        urls = self._extract_urls(strings)
        result.urls = urls

        result.potential_services = self._identify_services(classes, strings)

        # Nested streams
        nested = find_nested_streams(raw)
        result.nested_stream_count = len(nested)

        # Codebase URLs (from raw bytes)
        seen_cb: set[str] = set()
        cb_urls: list[str] = []
        for url in extract_raw_urls(raw):
            if url not in seen_cb:
                seen_cb.add(url)
                cb_urls.append(url)
        for _, sub in nested:
            for url in extract_raw_urls(sub):
                if url not in seen_cb:
                    seen_cb.add(url)
                    cb_urls.append(url)
        result.codebase_urls = cb_urls

        # Embedded endpoints
        result.embedded_endpoints = extract_endpoint_hints(raw)

        # === Tier 1+: deep serial analysis ===
        result.class_descriptors = parse_class_descriptors(raw)
        result.class_annotations = extract_class_annotations(raw)
        result.file_paths = extract_file_paths(raw)
        result.system_info = extract_system_info(raw)

        # Extract proxy interfaces and serial UIDs from descriptors
        for desc in result.class_descriptors:
            if desc["type"] == "proxy":
                result.proxy_interfaces.extend(desc["interfaces"])
            elif desc["type"] == "class":
                result.serial_version_uids[desc["name"]] = desc["uid"]

        result.tier = 2  # Tier 1+ achieved

        # === Tier 1++: HTTP codebase exploitation ===
        if probe_codebase:
            http_urls = self.collect_codebase_http_urls(result)
            if http_urls:
                explorer = CodebaseExplorer(
                    timeout=self.timeout,
                    progress_cb=progress_cb,
                )
                for base_url in http_urls:
                    exploit_result = explorer.explore(base_url)
                    result.codebase_exploits.append(exploit_result)

        return result

    def collect_codebase_http_urls(self, enum_result: EnumResult) -> list[str]:
        """Return deduplicated HTTP/HTTPS base URLs to probe for codebase exploitation.

        Collects from ``codebase_urls`` (raw bytes) and ``class_annotations``.
        Call this after :meth:`enumerate` to get URLs for per-URL probing.
        """
        seen_http: set[str] = set()
        http_urls: list[str] = []

        for url in enum_result.codebase_urls:
            base = self._url_base(url)
            if base and base not in seen_http:
                seen_http.add(base)
                http_urls.append(base)

        for annot in enum_result.class_annotations:
            url = annot.get("annotation_url", "") or annot.get("url", "")
            base = self._url_base(url)
            if base and base not in seen_http:
                seen_http.add(base)
                http_urls.append(base)

        return http_urls

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _url_base(url: str) -> str | None:
        """Extract the base URL (scheme + host + port + /) from a full URL."""
        lower = url.lower()
        if not (lower.startswith("http://") or lower.startswith("https://")):
            return None
        # Find the first '/' after the scheme
        after_scheme = url.find("//") + 2
        slash = url.find("/", after_scheme)
        if slash == -1:
            return url + "/"
        return url[:slash + 1]

    def _extract_classes(self, strings: list[str]) -> list[str]:
        classes = []
        seen: set[str] = set()
        for s in strings:
            matches = _IFACE_RE.findall(s)
            for m in matches:
                if m not in seen and len(m) < 200:
                    seen.add(m)
                    classes.append(m)
            # Also accept the whole string if it looks like a FQCN
            if s not in seen and _IFACE_RE.fullmatch(s):
                seen.add(s)
                classes.append(s)
        return classes

    def _extract_urls(self, strings: list[str]) -> list[str]:
        urls = []
        seen: set[str] = set()
        for s in strings:
            for url in _URL_RE.findall(s):
                if url not in seen:
                    seen.add(url)
                    urls.append(url)
        return urls

    def _identify_services(self, classes: list[str], strings: list[str]) -> list[dict[str, str]]:
        services = []
        seen: set[str] = set()

        # Known Jini service interfaces
        _KNOWN_IFACES: dict[str, str] = {
            "net.jini.core.lookup.ServiceRegistrar": "Jini Lookup Service (Reggie)",
            "net.jini.space.JavaSpace": "JavaSpace",
            "net.jini.space.JavaSpace05": "JavaSpace05",
            "net.jini.core.transaction.server.TransactionManager": "Transaction Manager",
            "net.jini.core.lease.LeaseRenewalManager": "Lease Renewal Manager",
            "com.sun.jini.reggie.RegistrarProxy": "Reggie Proxy",
            "org.apache.river.reggie": "Apache River Reggie",
        }

        for cls in classes:
            for known, label in _KNOWN_IFACES.items():
                if known in cls and label not in seen:
                    seen.add(label)
                    services.append({"name": label, "class": cls, "source": "class_match"})

            if _JINI_CLASS_RE.search(cls) and cls not in seen:
                seen.add(cls)
                services.append({"name": cls, "source": "jini_namespace"})

        return services
