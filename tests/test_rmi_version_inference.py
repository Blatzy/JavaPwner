"""Tests for JDK version inference and RMI exploitability rating.

Covers:
  - infer_jdk_from_bytes() — all detection branches
  - RmiScanResult._exploitability() — all rating branches
  - SUID DB label for MarshalledObject updated (no "pre-JEP 290")
"""

from __future__ import annotations

import struct

import pytest

from javapwner.core.serialization import (
    _SUID_FINGERPRINT_DB,
    infer_jdk_from_bytes,
)
from javapwner.protocols.rmi.scanner import RmiScanResult

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_OOS_HEADER = b"\xac\xed\x00\x05"


def _make_classdesc_bytes(class_name: str, suid: int) -> bytes:
    """Build a minimal valid Java serialization stream containing a single
    TC_CLASSDESC for *class_name* with the given *suid*."""
    name_bytes = class_name.encode("utf-8")
    return (
        _OOS_HEADER
        + b"\x72"                            # TC_CLASSDESC
        + struct.pack(">H", len(name_bytes)) # name length (uint16)
        + name_bytes                         # class name
        + struct.pack(">q", suid)            # SUID (int64)
        + b"\x02"                            # flags (SC_SERIALIZABLE)
        + b"\x00\x00"                        # field count = 0
        + b"\x78"                            # TC_ENDBLOCKDATA
    )


_MARSHALLED_SUID_JDK8  =  7834398015428807710
_MARSHALLED_SUID_JDK9P = -4768799335562104920


# ---------------------------------------------------------------------------
# infer_jdk_from_bytes — filter class name signals
# ---------------------------------------------------------------------------

def test_infer_sun_misc_filter_slash():
    """sun/misc/ObjectInputFilter → jdk8u121-8u231 high."""
    data = b"some error: sun/misc/ObjectInputFilter rejected"
    hint, conf = infer_jdk_from_bytes(data)
    assert hint == "jdk8u121-8u231"
    assert conf == "high"


def test_infer_sun_misc_filter_dot():
    """sun.misc.ObjectInputFilter (dot form) → jdk8u121-8u231 high."""
    data = b"filter class: sun.misc.ObjectInputFilter"
    hint, conf = infer_jdk_from_bytes(data)
    assert hint == "jdk8u121-8u231"
    assert conf == "high"


def test_infer_java_io_filter_slash():
    """java/io/ObjectInputFilter → jdk8u232+-or-jdk9+ medium (no SUID)."""
    data = b"filter status: java/io/ObjectInputFilter REJECTED"
    hint, conf = infer_jdk_from_bytes(data)
    assert hint == "jdk8u232+-or-jdk9+"
    assert conf == "medium"


def test_infer_java_io_filter_dot():
    """java.io.ObjectInputFilter (dot form) → jdk8u232+-or-jdk9+ medium."""
    data = b"java.io.ObjectInputFilter: REJECTED"
    hint, conf = infer_jdk_from_bytes(data)
    assert hint == "jdk8u232+-or-jdk9+"
    assert conf == "medium"


# ---------------------------------------------------------------------------
# infer_jdk_from_bytes — SUID-only signals
# ---------------------------------------------------------------------------

def test_infer_marshalled_suid_jdk8():
    """MarshalledObject with JDK8 SUID → jdk8 high."""
    data = _make_classdesc_bytes("java.rmi.MarshalledObject", _MARSHALLED_SUID_JDK8)
    hint, conf = infer_jdk_from_bytes(data)
    assert hint == "jdk8"
    assert conf == "high"


def test_infer_marshalled_suid_jdk9():
    """MarshalledObject with JDK9+ SUID → jdk9+ high."""
    data = _make_classdesc_bytes("java.rmi.MarshalledObject", _MARSHALLED_SUID_JDK9P)
    hint, conf = infer_jdk_from_bytes(data)
    assert hint == "jdk9+"
    assert conf == "high"


# ---------------------------------------------------------------------------
# infer_jdk_from_bytes — combination signal
# ---------------------------------------------------------------------------

def test_infer_combined_java_io_plus_jdk8_suid():
    """java/io/ObjectInputFilter + JDK8 SUID → jdk8u232+ high (refinement)."""
    classdesc = _make_classdesc_bytes("java.rmi.MarshalledObject", _MARSHALLED_SUID_JDK8)
    # Prepend the filter class name as it would appear in an error message
    data = b"filter: java/io/ObjectInputFilter\x00" + classdesc
    hint, conf = infer_jdk_from_bytes(data)
    assert hint == "jdk8u232+"
    assert conf == "high"


# ---------------------------------------------------------------------------
# infer_jdk_from_bytes — no signal
# ---------------------------------------------------------------------------

def test_infer_empty():
    """Empty bytes → unknown none."""
    assert infer_jdk_from_bytes(b"") == ("unknown", "none")


def test_infer_no_signal():
    """Random bytes without known markers → unknown none."""
    assert infer_jdk_from_bytes(b"\x00\x01\x02Hello World") == ("unknown", "none")


# ---------------------------------------------------------------------------
# RmiScanResult._exploitability()
# ---------------------------------------------------------------------------

def test_exploitability_critical():
    """DGC reachable + no JEP290 + compatible gadgets → critical."""
    r = RmiScanResult(host="127.0.0.1", port=1099)
    r.dgc_reachable = True
    r.jep290_active = False
    r.gadgets_compatible = ["CommonsCollections6"]
    assert r._exploitability() == "critical"


def test_exploitability_high():
    """DGC reachable + no JEP290 + no gadgets confirmed → high."""
    r = RmiScanResult(host="127.0.0.1", port=1099)
    r.dgc_reachable = True
    r.jep290_active = False
    r.gadgets_compatible = []
    assert r._exploitability() == "high"


def test_exploitability_medium():
    """DGC reachable + JEP290 active → medium."""
    r = RmiScanResult(host="127.0.0.1", port=1099)
    r.dgc_reachable = True
    r.jep290_active = True
    assert r._exploitability() == "medium"


def test_exploitability_unknown_unreachable():
    """DGC unreachable → unknown."""
    r = RmiScanResult(host="127.0.0.1", port=1099)
    r.dgc_reachable = False
    assert r._exploitability() == "unknown"


def test_exploitability_unknown_jep290_none():
    """DGC reachable but jep290_active=None → unknown."""
    r = RmiScanResult(host="127.0.0.1", port=1099)
    r.dgc_reachable = True
    r.jep290_active = None
    assert r._exploitability() == "unknown"


# ---------------------------------------------------------------------------
# SUID DB label check
# ---------------------------------------------------------------------------

def test_suid_db_label_updated():
    """MarshalledObject SUID label must not contain 'pre-JEP 290' any more."""
    entry = _SUID_FINGERPRINT_DB.get("java.rmi.MarshalledObject", {})
    for _suid, (label, _discriminating) in entry.items():
        assert "pre-JEP 290" not in label, (
            f"Stale label found for MarshalledObject SUID {_suid}: {label!r}"
        )
