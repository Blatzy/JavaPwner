"""Tests for Tier 2 Registrar inspection (heuristic + JVM bridge parsing)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from javapwner.exceptions import JvmBridgeError
from javapwner.protocols.jini.registrar import (
    AdminCapability,
    RegistrarInfo,
    RegistrarInspector,
    ServiceInfo,
    heuristic_admin_check,
)


# -----------------------------------------------------------------------
# Heuristic admin check (no JVM)
# -----------------------------------------------------------------------

class TestHeuristicAdminCheck:
    """Tests for heuristic_admin_check() — Tier 1+ data only."""

    def test_empty_inputs(self):
        info = heuristic_admin_check([], [])
        assert info.source == "heuristic"
        assert not info.is_administrable
        assert info.admin_capabilities == []

    def test_detects_administrable_in_proxy_interfaces(self):
        interfaces = [
            "net.jini.core.lookup.ServiceRegistrar",
            "net.jini.admin.Administrable",
            "java.io.Serializable",
        ]
        info = heuristic_admin_check(interfaces)
        assert info.is_administrable is True

    def test_detects_join_admin(self):
        interfaces = [
            "net.jini.admin.Administrable",
            "net.jini.admin.JoinAdmin",
        ]
        info = heuristic_admin_check(interfaces)
        assert info.is_administrable is True
        assert any(c.name == "JoinAdmin" and c.available for c in info.admin_capabilities)

    def test_detects_destroy_admin_sun(self):
        interfaces = ["com.sun.jini.admin.DestroyAdmin"]
        class_names = ["com.sun.jini.reggie.RegistrarProxy"]
        info = heuristic_admin_check(interfaces, class_names)
        assert any(c.name == "DestroyAdmin" and c.available for c in info.admin_capabilities)
        assert info.registrar_class == "com.sun.jini.reggie.RegistrarProxy"

    def test_detects_destroy_admin_river(self):
        interfaces = ["org.apache.river.admin.DestroyAdmin"]
        info = heuristic_admin_check(interfaces)
        assert any(c.name == "DestroyAdmin" and c.available for c in info.admin_capabilities)

    def test_no_duplicate_destroy_admin(self):
        """Both Sun and River DestroyAdmin should produce one capability."""
        interfaces = [
            "com.sun.jini.admin.DestroyAdmin",
            "org.apache.river.admin.DestroyAdmin",
        ]
        info = heuristic_admin_check(interfaces)
        destroy_caps = [c for c in info.admin_capabilities if c.name == "DestroyAdmin"]
        assert len(destroy_caps) == 1

    def test_detects_javaspace(self):
        interfaces = ["net.jini.space.JavaSpace05"]
        info = heuristic_admin_check(interfaces)
        assert any(c.name == "JavaSpace05" for c in info.admin_capabilities)

    def test_combined_detection(self):
        interfaces = [
            "net.jini.core.lookup.ServiceRegistrar",
            "net.jini.admin.Administrable",
            "net.jini.admin.JoinAdmin",
        ]
        class_names = [
            "com.sun.jini.admin.DestroyAdmin",
            "com.sun.jini.reggie.RegistrarProxy",
        ]
        info = heuristic_admin_check(interfaces, class_names)
        assert info.is_administrable is True
        cap_names = {c.name for c in info.admin_capabilities}
        assert "JoinAdmin" in cap_names
        assert "DestroyAdmin" in cap_names


# -----------------------------------------------------------------------
# RegistrarInfo properties
# -----------------------------------------------------------------------

class TestRegistrarInfoProperties:

    def test_has_destroy_admin(self):
        info = RegistrarInfo()
        assert not info.has_destroy_admin
        info.admin_capabilities.append(
            AdminCapability(name="DestroyAdmin", interface="x", available=True)
        )
        assert info.has_destroy_admin

    def test_has_join_admin(self):
        info = RegistrarInfo()
        assert not info.has_join_admin
        info.admin_capabilities.append(
            AdminCapability(name="JoinAdmin", interface="x", available=True)
        )
        assert info.has_join_admin

    def test_has_storage_admin(self):
        info = RegistrarInfo()
        assert not info.has_storage_admin
        info.admin_capabilities.append(
            AdminCapability(name="StorageLocationAdmin", interface="x", available=True)
        )
        assert info.has_storage_admin

    def test_to_dict_roundtrip(self):
        info = RegistrarInfo(
            source="jvm",
            registrar_class="com.sun.jini.reggie.RegistrarProxy",
            is_administrable=True,
            admin_capabilities=[
                AdminCapability(
                    name="JoinAdmin",
                    interface="net.jini.admin.JoinAdmin",
                    available=True,
                    details={"groups": ["public"]},
                ),
            ],
            services=[
                ServiceInfo(
                    service_id="abc-123",
                    class_name="com.example.MyService",
                    interfaces=["java.io.Serializable"],
                    is_administrable=False,
                ),
            ],
            total_services=1,
        )
        d = info.to_dict()
        assert d["source"] == "jvm"
        assert d["is_administrable"] is True
        assert len(d["admin_capabilities"]) == 1
        assert d["admin_capabilities"][0]["name"] == "JoinAdmin"
        assert len(d["services"]) == 1
        assert d["total_services"] == 1


# -----------------------------------------------------------------------
# RegistrarInspector._parse_result
# -----------------------------------------------------------------------

class TestRegistrarInspectorParseResult:
    """Tests for parsing JiniInspector JSON output."""

    def test_parse_success(self):
        raw = {
            "success": True,
            "registrar": {
                "class_name": "com.sun.jini.reggie.RegistrarProxy",
                "interfaces": [
                    "net.jini.core.lookup.ServiceRegistrar",
                    "net.jini.admin.Administrable",
                ],
                "service_id": "abc-def-123",
                "groups": ["public"],
                "locator": "jini://10.0.0.1:4160",
            },
            "admin": {
                "is_administrable": True,
                "class_name": "com.sun.jini.reggie.RegistrarImpl$AdminProxy",
                "interfaces": [
                    "net.jini.admin.JoinAdmin",
                    "com.sun.jini.admin.DestroyAdmin",
                ],
                "capabilities": {
                    "join_admin": {
                        "available": True,
                        "groups": ["public"],
                        "locators": [],
                        "attributes_count": 2,
                    },
                    "destroy_admin": {
                        "available": True,
                    },
                    "storage_admin": {
                        "available": False,
                    },
                },
            },
            "services": [
                {
                    "service_id": "svc-001",
                    "class_name": "com.example.MyProxy",
                    "interfaces": ["java.rmi.Remote"],
                    "is_administrable": True,
                    "attributes": ["ServiceInfo@123"],
                },
            ],
            "total_services": 1,
        }

        info = RegistrarInspector._parse_result(raw)

        assert info.source == "jvm"
        assert info.error is None
        assert info.registrar_class == "com.sun.jini.reggie.RegistrarProxy"
        assert info.service_id == "abc-def-123"
        assert info.groups == ["public"]
        assert info.locator == "jini://10.0.0.1:4160"
        assert info.is_administrable is True
        assert info.admin_class == "com.sun.jini.reggie.RegistrarImpl$AdminProxy"
        assert info.has_join_admin
        assert info.has_destroy_admin
        assert not info.has_storage_admin
        assert len(info.services) == 1
        assert info.services[0].is_administrable is True
        assert info.total_services == 1

    def test_parse_failure(self):
        raw = {
            "success": False,
            "error": "java.net.ConnectException: Connection refused",
        }
        info = RegistrarInspector._parse_result(raw)
        assert info.source == "jvm"
        assert info.error is not None
        assert "Connection refused" in info.error
        assert not info.is_administrable

    def test_parse_not_administrable(self):
        raw = {
            "success": True,
            "registrar": {
                "class_name": "com.example.CustomRegistrar",
                "interfaces": ["net.jini.core.lookup.ServiceRegistrar"],
                "groups": [],
            },
            "admin": {
                "is_administrable": False,
            },
            "services": [],
            "total_services": 0,
        }
        info = RegistrarInspector._parse_result(raw)
        assert not info.is_administrable
        assert info.admin_capabilities == []

    def test_parse_with_storage_admin(self):
        raw = {
            "success": True,
            "registrar": {
                "class_name": "com.sun.jini.reggie.RegistrarProxy",
                "interfaces": [],
            },
            "admin": {
                "is_administrable": True,
                "class_name": "SomeAdmin",
                "interfaces": [],
                "capabilities": {
                    "join_admin": {"available": False},
                    "destroy_admin": {"available": False},
                    "storage_admin": {
                        "available": True,
                        "location": "/opt/reggie/store",
                    },
                },
            },
            "services": [],
            "total_services": 0,
        }
        info = RegistrarInspector._parse_result(raw)
        assert info.has_storage_admin
        sa = next(c for c in info.admin_capabilities if c.name == "StorageLocationAdmin")
        assert sa.details["location"] == "/opt/reggie/store"


# -----------------------------------------------------------------------
# RegistrarInspector.inspect() — with mocked bridge
# -----------------------------------------------------------------------

class TestRegistrarInspectorInspect:

    def test_inspect_calls_bridge(self):
        bridge = MagicMock()
        bridge.check_prerequisites.return_value = []
        bridge.run_inspector.return_value = {
            "success": True,
            "registrar": {
                "class_name": "Proxy",
                "interfaces": [],
                "groups": [],
            },
            "admin": {"is_administrable": False},
            "services": [],
            "total_services": 0,
        }

        inspector = RegistrarInspector(bridge)
        info = inspector.inspect("10.0.0.1", 4160)

        bridge.check_prerequisites.assert_called_once()
        bridge.run_inspector.assert_called_once_with("10.0.0.1", 4160, 5000)
        assert info.source == "jvm"

    def test_inspect_raises_on_missing_prerequisites(self):
        bridge = MagicMock()
        bridge.check_prerequisites.return_value = ["Java not found"]

        inspector = RegistrarInspector(bridge)
        with pytest.raises(JvmBridgeError, match="prerequisites not met"):
            inspector.inspect("10.0.0.1", 4160)


# -----------------------------------------------------------------------
# Assessment integration
# -----------------------------------------------------------------------

class TestAssessmentWithRegistrarInfo:
    """Verify that assessment.py correctly generates admin-related vectors."""

    def test_destroy_admin_generates_high_vector(self):
        from javapwner.protocols.jini.assessment import assess_exploitation, RISK_HIGH

        info = RegistrarInfo(
            source="jvm",
            is_administrable=True,
            admin_capabilities=[
                AdminCapability(
                    name="DestroyAdmin",
                    interface="com.sun.jini.admin.DestroyAdmin",
                    available=True,
                ),
            ],
        )
        a = assess_exploitation(registrar_info=info, target="10.0.0.1")
        destroy_vectors = [v for v in a.vectors if "DestroyAdmin" in v.title]
        assert len(destroy_vectors) >= 1
        assert destroy_vectors[0].severity == RISK_HIGH

    def test_join_admin_generates_high_vector(self):
        from javapwner.protocols.jini.assessment import assess_exploitation, RISK_HIGH

        info = RegistrarInfo(
            source="jvm",
            is_administrable=True,
            admin_capabilities=[
                AdminCapability(
                    name="JoinAdmin",
                    interface="net.jini.admin.JoinAdmin",
                    available=True,
                    details={"groups": ["public"]},
                ),
            ],
        )
        a = assess_exploitation(registrar_info=info, target="10.0.0.1")
        join_vectors = [v for v in a.vectors if "JoinAdmin" in v.title]
        assert len(join_vectors) >= 1
        assert join_vectors[0].severity == RISK_HIGH

    def test_heuristic_administrable_generates_medium_vector(self):
        from javapwner.protocols.jini.assessment import assess_exploitation, RISK_MEDIUM

        info = RegistrarInfo(
            source="heuristic",
            is_administrable=True,
            admin_capabilities=[
                AdminCapability(
                    name="JoinAdmin",
                    interface="net.jini.admin.JoinAdmin",
                    available=True,
                ),
            ],
        )
        a = assess_exploitation(registrar_info=info, target="10.0.0.1")
        heuristic_vectors = [v for v in a.vectors if "heuristic" in v.title.lower()]
        assert len(heuristic_vectors) >= 1

    def test_administrable_without_capabilities(self):
        from javapwner.protocols.jini.assessment import assess_exploitation, RISK_MEDIUM

        info = RegistrarInfo(
            source="jvm",
            is_administrable=True,
            admin_capabilities=[],
        )
        a = assess_exploitation(registrar_info=info, target="10.0.0.1")
        unknown_vectors = [v for v in a.vectors if "capabilities unknown" in v.title.lower()]
        assert len(unknown_vectors) >= 1
        assert unknown_vectors[0].severity == RISK_MEDIUM

    def test_no_registrar_info_produces_no_admin_vectors(self):
        from javapwner.protocols.jini.assessment import assess_exploitation

        a = assess_exploitation(target="10.0.0.1")
        admin_vectors = [
            v for v in a.vectors
            if any(kw in v.title.lower() for kw in ("admin", "administrable", "destroy"))
        ]
        assert len(admin_vectors) == 0
