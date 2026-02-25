"""JiniEnumerator — Tier 1 heuristic enumeration of Jini services.

This module operates purely in Python by extracting class names and strings
from the raw serialised proxy blob returned by the Unicast Discovery protocol.
It does NOT require a running JVM or jini-bridge.jar.

Tier 2 enumeration (full ServiceRegistrar.lookup()) will be added later with
lib/jini-bridge.jar.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.serialization import extract_strings_from_stream, get_stream_metadata
from javapwner.protocols.jini.scanner import JiniScanner, ScanResult

# Patterns that suggest interesting Jini / Java RMI class names
_JINI_CLASS_RE = re.compile(r"net\.jini\.|com\.sun\.jini\.|org\.apache\.river\.")
_IFACE_RE = re.compile(r"([a-zA-Z][a-zA-Z0-9_$]*(?:\.[a-zA-Z][a-zA-Z0-9_$]*)+)")
_URL_RE = re.compile(r"((?:jrmi?|http|https|rmi)://[^\s\x00-\x1f\"]+)")


@dataclass
class EnumResult:
    groups: list[str] = field(default_factory=list)
    extracted_classes: list[str] = field(default_factory=list)
    potential_services: list[dict[str, str]] = field(default_factory=list)
    raw_strings: list[str] = field(default_factory=list)
    urls: list[str] = field(default_factory=list)
    tier: int = 1

    def to_dict(self) -> dict[str, Any]:
        return {
            "tier": self.tier,
            "groups": self.groups,
            "extracted_classes": self.extracted_classes,
            "potential_services": self.potential_services,
            "raw_strings": self.raw_strings,
            "urls": self.urls,
        }


class JiniEnumerator:
    """Heuristic (Tier 1) enumeration of a Jini / Reggie target."""

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout
        self._scanner = JiniScanner(timeout=timeout)

    def enumerate(self, host: str, port: int, scan_result: ScanResult | None = None) -> EnumResult:
        if scan_result is None:
            scan_result = self._scanner.scan(host, port)

        result = EnumResult(groups=scan_result.groups)

        raw = scan_result.raw_proxy_bytes
        if not raw:
            return result

        strings = extract_strings_from_stream(raw)
        result.raw_strings = strings

        classes = self._extract_classes(strings)
        result.extracted_classes = classes

        urls = self._extract_urls(strings)
        result.urls = urls

        result.potential_services = self._identify_services(classes, strings)

        return result

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

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
