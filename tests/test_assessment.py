"""Tests for the exploitation assessment logic and reworked SUID DB."""
from __future__ import annotations

import pytest

from javapwner.core.serialization import fingerprint_java_version
from javapwner.protocols.jini.assessment import (
    RISK_CRITICAL,
    RISK_HIGH,
    RISK_INFO,
    RISK_LOW,
    RISK_MEDIUM,
    ExploitAssessment,
    assess_exploitation,
)


# -----------------------------------------------------------------------
# Reworked SUID fingerprint
# -----------------------------------------------------------------------

class TestReworkedSUIDFingerprint:
    """Verify the new SUID DB returns discriminating vs presence-only hints."""

    def test_marshalled_object_jdk8_is_discriminating(self):
        hints = fingerprint_java_version(
            {"java.rmi.MarshalledObject": 7834398015428807710}
        )
        assert len(hints) == 1
        assert hints[0]["discriminating"] == "True"
        assert "JDK 8" in hints[0]["hint"]

    def test_marshalled_object_jdk9_is_discriminating(self):
        hints = fingerprint_java_version(
            {"java.rmi.MarshalledObject": -4768799335562104920}
        )
        assert len(hints) == 1
        assert hints[0]["discriminating"] == "True"
        assert "JDK 9+" in hints[0]["hint"]

    def test_stable_suid_is_not_discriminating(self):
        hints = fingerprint_java_version(
            {"java.rmi.server.RemoteObject": -3215090123894869218}
        )
        assert len(hints) == 1
        assert hints[0]["discriminating"] == "False"
        assert "stable" in hints[0]["hint"].lower()

    def test_sun_jini_reggie_is_discriminating(self):
        hints = fingerprint_java_version(
            {"com.sun.jini.reggie.RegistrarProxy": 2}
        )
        assert len(hints) == 1
        assert hints[0]["discriminating"] == "True"
        assert "Sun Jini" in hints[0]["hint"] or "com.sun" in hints[0]["hint"]

    def test_river3_reggie_is_discriminating(self):
        hints = fingerprint_java_version(
            {"org.apache.river.reggie.RegistrarProxy": 2}
        )
        assert len(hints) == 1
        assert hints[0]["discriminating"] == "True"
        assert "River 3" in hints[0]["hint"]

    def test_discriminating_sorted_first(self):
        hints = fingerprint_java_version({
            "java.rmi.MarshalledObject": 7834398015428807710,
            "java.rmi.server.RemoteObject": -3215090123894869218,
            "java.util.HashMap": 362498820763181265,
        })
        assert len(hints) == 3
        # Discriminating entry should come first
        assert hints[0]["discriminating"] == "True"
        assert hints[0]["class"] == "java.rmi.MarshalledObject"

    def test_unknown_suid_marked_discriminating(self):
        hints = fingerprint_java_version(
            {"java.rmi.MarshalledObject": 99999999}
        )
        assert len(hints) == 1
        assert hints[0]["discriminating"] == "True"
        assert "unknown SUID" in hints[0]["hint"]


# -----------------------------------------------------------------------
# Exploitation assessment
# -----------------------------------------------------------------------

class TestAssessExploitation:

    def test_dgc_unfiltered_is_critical(self):
        """DGC unfiltered → CRITICAL risk, RCE vector."""
        a = assess_exploitation(
            dgc_reachable=True,
            jep290_active=False,
            target="10.0.0.1",
            port=4160,
        )
        assert a.risk_level == RISK_CRITICAL
        assert a.dgc_state == "unfiltered"
        assert any(v.severity == RISK_CRITICAL for v in a.vectors)
        assert any("RCE" in v.title for v in a.vectors)

    def test_dgc_filtered_suggests_bypass(self):
        """DGC filtered → MEDIUM risk, suggests registry bypass."""
        a = assess_exploitation(
            dgc_reachable=True,
            jep290_active=True,
        )
        assert a.dgc_state == "filtered"
        assert any("bypass" in v.title.lower() or "JEP 290" in v.title for v in a.vectors)

    def test_jdk8_from_suid_detected(self):
        """MarshalledObject SUID → JDK ≤ 8 estimate."""
        a = assess_exploitation(
            version_hints=[{
                "class": "java.rmi.MarshalledObject",
                "suid": "7834398015428807710",
                "hint": "JDK ≤ 8 (pre-JEP 290)",
                "discriminating": "True",
            }],
            dgc_reachable=False,
        )
        assert "JDK ≤ 8" in a.jdk_estimate
        assert a.jdk_confidence == "high"

    def test_jdk9_from_suid_detected(self):
        a = assess_exploitation(
            version_hints=[{
                "class": "java.rmi.MarshalledObject",
                "suid": "-4768799335562104920",
                "hint": "JDK 9+",
                "discriminating": "True",
            }],
        )
        assert "JDK 9+" in a.jdk_estimate
        assert a.jdk_confidence == "high"

    def test_sun_jini_namespace_detected(self):
        """com.sun.jini namespace → legacy deployment, likely JDK ≤ 8."""
        a = assess_exploitation(
            class_names=[
                "com.sun.jini.reggie.RegistrarProxy",
                "net.jini.core.lookup.ServiceRegistrar",
            ],
        )
        assert "Sun Jini" in a.framework
        assert any("Sun Jini" in v.title or "legacy" in v.title.lower() for v in a.vectors)

    def test_river3_namespace_detected(self):
        a = assess_exploitation(
            class_names=[
                "org.apache.river.reggie.RegistrarProxy",
                "net.jini.core.lookup.ServiceRegistrar",
            ],
        )
        assert "River 3" in a.framework

    def test_codebase_traversal_is_high(self):
        """Path traversal on codebase server → HIGH risk."""
        a = assess_exploitation(
            codebase_results=[{
                "server_reachable": True,
                "traversal_vulnerable": True,
            }],
        )
        assert a.codebase_traversal is True
        assert any("traversal" in v.title.lower() for v in a.vectors)
        assert any(v.severity in (RISK_HIGH, RISK_CRITICAL) for v in a.vectors)

    def test_codebase_accessible_no_traversal(self):
        a = assess_exploitation(
            codebase_results=[{
                "server_reachable": True,
                "traversal_vulnerable": False,
            }],
        )
        assert a.codebase_accessible is True
        assert a.codebase_traversal is False

    def test_class_files_found(self):
        a = assess_exploitation(
            codebase_results=[{
                "server_reachable": True,
                "downloaded_classes": [{"class_name": "test.Foo"}],
            }],
        )
        assert a.codebase_classes_found is True
        assert any("method" in v.title.lower() for v in a.vectors)

    def test_no_signals_gives_info(self):
        """No signals at all → INFO risk."""
        a = assess_exploitation()
        assert a.risk_level == RISK_INFO
        assert len(a.vectors) == 0

    def test_jrmp_open_no_other_info(self):
        """JRMP reachable but no other intel → MEDIUM, suggest exploit."""
        a = assess_exploitation(dgc_reachable=True, jep290_active=None)
        assert a.dgc_state == "unknown"
        assert any(v.severity == RISK_MEDIUM for v in a.vectors)

    def test_vectors_sorted_by_severity(self):
        """Vectors should be sorted CRITICAL first, INFO last."""
        a = assess_exploitation(
            dgc_reachable=True,
            jep290_active=False,
            codebase_results=[{
                "server_reachable": True,
                "traversal_vulnerable": True,
                "downloaded_classes": [{"class_name": "test.Foo"}],
            }],
        )
        severities = [v.severity for v in a.vectors]
        order = [RISK_CRITICAL, RISK_HIGH, RISK_MEDIUM, RISK_LOW, RISK_INFO]
        indices = [order.index(s) if s in order else 99 for s in severities]
        assert indices == sorted(indices), f"Vectors not sorted: {severities}"

    def test_to_dict(self):
        a = assess_exploitation(
            dgc_reachable=True,
            jep290_active=False,
            target="10.0.0.1",
        )
        d = a.to_dict()
        assert "risk_level" in d
        assert "vectors" in d
        assert isinstance(d["vectors"], list)
        assert all("title" in v for v in d["vectors"])

    def test_combined_jdk8_dgc_unfiltered_sun_jini(self):
        """The 'worst case' — JDK ≤ 8, DGC unfiltered, Sun Jini namespace.

        Should be CRITICAL with multiple high-severity vectors.
        """
        a = assess_exploitation(
            version_hints=[{
                "class": "java.rmi.MarshalledObject",
                "suid": "7834398015428807710",
                "hint": "JDK ≤ 8 (pre-JEP 290)",
                "discriminating": "True",
            }],
            dgc_reachable=True,
            jep290_active=False,
            class_names=[
                "com.sun.jini.reggie.RegistrarProxy",
                "net.jini.core.lookup.ServiceRegistrar",
            ],
            codebase_results=[{
                "server_reachable": True,
                "traversal_vulnerable": True,
            }],
            target="10.0.0.1",
            port=4160,
        )
        assert a.risk_level == RISK_CRITICAL
        assert a.jdk_estimate.startswith("JDK ≤ 8")
        assert "Sun Jini" in a.framework
        assert a.dgc_state == "unfiltered"
        assert a.codebase_traversal is True
        # Should have at least 3 vectors: RCE via DGC, Sun Jini legacy, traversal
        assert len(a.vectors) >= 3
        titles = " ".join(v.title for v in a.vectors)
        assert "RCE" in titles
        assert "traversal" in titles.lower()
