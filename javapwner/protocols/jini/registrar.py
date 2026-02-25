"""Tier 2 Registrar inspection — live JVM interaction with the Jini Lookup Service.

This module provides two levels of admin interface detection:

**Heuristic (no JVM)** — :func:`heuristic_admin_check`
  Analyses ``proxy_interfaces`` extracted by Tier 1+ to detect
  ``Administrable``, ``JoinAdmin``, ``DestroyAdmin`` without a JVM.
  Fast but cannot confirm capabilities or enumerate registered services.

**Active (JVM bridge)** — :class:`RegistrarInspector`
  Uses :class:`~javapwner.core.jvm_bridge.JvmBridge` to run
  ``JiniInspector.java`` as a subprocess.  Connects to the real Lookup
  Service, calls ``getAdmin()``, and introspects the admin object's
  interfaces and capabilities.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from javapwner.core.jvm_bridge import JvmBridge
from javapwner.exceptions import JvmBridgeError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Known admin-related interfaces
# ---------------------------------------------------------------------------

_ADMIN_INTERFACES: dict[str, str] = {
    "net.jini.admin.Administrable": "Administrable (getAdmin())",
    "net.jini.admin.JoinAdmin": "JoinAdmin (groups/locators/attributes)",
    "com.sun.jini.admin.DestroyAdmin": "DestroyAdmin [Sun] (destroy service)",
    "org.apache.river.admin.DestroyAdmin": "DestroyAdmin [River] (destroy service)",
    "com.sun.jini.admin.StorageLocationAdmin": "StorageLocationAdmin (storage path)",
    "net.jini.space.JavaSpace": "JavaSpace (tuple space operations)",
    "net.jini.space.JavaSpace05": "JavaSpace05 (tuple space operations)",
    "net.jini.core.transaction.server.TransactionManager": "TransactionManager",
    "net.jini.activation.ActivationAdmin": "ActivationAdmin",
}


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AdminCapability:
    """A single admin capability detected on the Registrar or a service."""
    name: str               # e.g. "JoinAdmin", "DestroyAdmin"
    interface: str           # FQCN of the interface
    available: bool = False
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "name": self.name,
            "interface": self.interface,
            "available": self.available,
        }
        if self.details:
            d["details"] = self.details
        return d


@dataclass
class ServiceInfo:
    """A service registered in the Jini Lookup Service."""
    service_id: str
    class_name: str
    interfaces: list[str] = field(default_factory=list)
    is_administrable: bool = False
    attributes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "service_id": self.service_id,
            "class_name": self.class_name,
            "interfaces": self.interfaces,
            "is_administrable": self.is_administrable,
            "attributes": self.attributes,
        }


@dataclass
class RegistrarInfo:
    """Complete Tier 2 inspection result for a Jini Registrar."""

    # Source: "heuristic" (Tier 1+ only) or "jvm" (active JVM bridge)
    source: str = "heuristic"

    # Registrar metadata
    registrar_class: str = ""
    registrar_interfaces: list[str] = field(default_factory=list)
    service_id: str | None = None
    groups: list[str] = field(default_factory=list)
    locator: str | None = None

    # Admin inspection
    is_administrable: bool = False
    admin_class: str | None = None
    admin_interfaces: list[str] = field(default_factory=list)
    admin_capabilities: list[AdminCapability] = field(default_factory=list)

    # Registered services (JVM only)
    services: list[ServiceInfo] = field(default_factory=list)
    total_services: int = 0

    # Error (if inspection partially failed)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "registrar_class": self.registrar_class,
            "registrar_interfaces": self.registrar_interfaces,
            "service_id": self.service_id,
            "groups": self.groups,
            "locator": self.locator,
            "is_administrable": self.is_administrable,
            "admin_class": self.admin_class,
            "admin_interfaces": self.admin_interfaces,
            "admin_capabilities": [c.to_dict() for c in self.admin_capabilities],
            "services": [s.to_dict() for s in self.services],
            "total_services": self.total_services,
            "error": self.error,
        }

    @property
    def has_destroy_admin(self) -> bool:
        return any(c.name == "DestroyAdmin" and c.available for c in self.admin_capabilities)

    @property
    def has_join_admin(self) -> bool:
        return any(c.name == "JoinAdmin" and c.available for c in self.admin_capabilities)

    @property
    def has_storage_admin(self) -> bool:
        return any(c.name == "StorageLocationAdmin" and c.available for c in self.admin_capabilities)


# ---------------------------------------------------------------------------
# Heuristic admin check (no JVM)
# ---------------------------------------------------------------------------

def heuristic_admin_check(
    proxy_interfaces: list[str],
    class_names: list[str] | None = None,
) -> RegistrarInfo:
    """Analyse Tier 1+ data to detect admin interfaces without a JVM.

    Checks ``proxy_interfaces`` (from ``TC_PROXYCLASSDESC``) and
    ``class_names`` for known admin-related interfaces.

    Returns a :class:`RegistrarInfo` with ``source="heuristic"``.
    """
    class_names = class_names or []
    info = RegistrarInfo(source="heuristic")

    all_names = set(proxy_interfaces) | set(class_names)

    # Detect Administrable
    for name in all_names:
        if "Administrable" in name:
            info.is_administrable = True
            break

    # Detect specific admin interfaces
    for iface_fqcn, label in _ADMIN_INTERFACES.items():
        found = any(iface_fqcn in n for n in all_names)
        if found:
            short_name = iface_fqcn.rsplit(".", 1)[-1]
            # Normalise DestroyAdmin variants
            if "DestroyAdmin" in short_name:
                short_name = "DestroyAdmin"
            cap = AdminCapability(
                name=short_name,
                interface=iface_fqcn,
                available=True,
            )
            # Avoid duplicate DestroyAdmin entries
            if not any(c.name == cap.name for c in info.admin_capabilities):
                info.admin_capabilities.append(cap)

    # Infer registrar class from class names
    for cn in class_names:
        if "RegistrarProxy" in cn:
            info.registrar_class = cn
            break

    # Proxy interfaces are the registrar's interfaces
    info.registrar_interfaces = list(proxy_interfaces)

    return info


# ---------------------------------------------------------------------------
# Active inspection (JVM bridge)
# ---------------------------------------------------------------------------

class RegistrarInspector:
    """Tier 2 — live Registrar inspection using the JVM bridge.

    Connects to the Jini Lookup Service, retrieves the
    ``ServiceRegistrar`` proxy, and inspects its administration
    capabilities by calling ``getAdmin()`` through the JVM.

    Parameters
    ----------
    bridge:
        A configured :class:`~javapwner.core.jvm_bridge.JvmBridge`.
    """

    def __init__(self, bridge: JvmBridge):
        self._bridge = bridge

    def inspect(
        self,
        host: str,
        port: int = 4160,
        timeout_ms: int = 5000,
    ) -> RegistrarInfo:
        """Connect to *host*:*port* and return full Registrar inspection.

        Raises :class:`~javapwner.exceptions.JvmBridgeError` if the
        JVM bridge cannot operate (missing JDK, JARs, etc.).

        Network errors from the Java side are reported in
        ``RegistrarInfo.error`` rather than raised.
        """
        issues = self._bridge.check_prerequisites()
        if issues:
            raise JvmBridgeError(
                "JVM bridge prerequisites not met:\n  • " + "\n  • ".join(issues)
            )

        raw = self._bridge.run_inspector(host, port, timeout_ms)
        return self._parse_result(raw)

    # ------------------------------------------------------------------
    # Result parsing
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_result(raw: dict[str, Any]) -> RegistrarInfo:
        """Convert the JSON dict from JiniInspector into a :class:`RegistrarInfo`."""
        info = RegistrarInfo(source="jvm")

        if not raw.get("success"):
            info.error = raw.get("error", "Unknown error from JiniInspector")
            return info

        # ── Registrar ────────────────────────────────────────────────
        reg = raw.get("registrar", {})
        info.registrar_class = reg.get("class_name", "")
        info.registrar_interfaces = reg.get("interfaces", [])
        info.service_id = reg.get("service_id")
        info.groups = reg.get("groups", [])
        info.locator = reg.get("locator")

        # ── Admin ────────────────────────────────────────────────────
        admin = raw.get("admin", {})
        info.is_administrable = admin.get("is_administrable", False)
        info.admin_class = admin.get("class_name")
        info.admin_interfaces = admin.get("interfaces", [])

        if info.is_administrable and "capabilities" in admin:
            caps = admin["capabilities"]

            # JoinAdmin
            ja = caps.get("join_admin", {})
            if ja.get("available"):
                details: dict[str, Any] = {}
                if "groups" in ja:
                    details["groups"] = ja["groups"]
                if "locators" in ja:
                    details["locators"] = ja["locators"]
                if "attributes_count" in ja:
                    details["attributes_count"] = ja["attributes_count"]
                if "attributes" in ja:
                    details["attributes"] = ja["attributes"]
                info.admin_capabilities.append(AdminCapability(
                    name="JoinAdmin",
                    interface="net.jini.admin.JoinAdmin",
                    available=True,
                    details=details,
                ))

            # DestroyAdmin
            da = caps.get("destroy_admin", {})
            if da.get("available"):
                info.admin_capabilities.append(AdminCapability(
                    name="DestroyAdmin",
                    interface="com.sun.jini.admin.DestroyAdmin",
                    available=True,
                ))

            # StorageLocationAdmin
            sa = caps.get("storage_admin", {})
            if sa.get("available"):
                details = {}
                if "location" in sa:
                    details["location"] = sa["location"]
                info.admin_capabilities.append(AdminCapability(
                    name="StorageLocationAdmin",
                    interface="com.sun.jini.admin.StorageLocationAdmin",
                    available=True,
                    details=details,
                ))

        if admin.get("error"):
            info.error = admin["error"]

        # ── Services ─────────────────────────────────────────────────
        info.total_services = raw.get("total_services", 0)
        for svc in raw.get("services", []):
            info.services.append(ServiceInfo(
                service_id=svc.get("service_id", ""),
                class_name=svc.get("class_name", ""),
                interfaces=svc.get("interfaces", []),
                is_administrable=svc.get("is_administrable", False),
                attributes=svc.get("attributes", []),
            ))

        return info
