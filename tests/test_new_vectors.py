"""Tests for the new enumeration vectors:

- DGC JEP290 fingerprinting (probe.py)
- Java version fingerprinting from serial UIDs (serialization.py)
- .class file constant-pool parsing (codebase.py)
- Active Multicast Discovery request builder (protocol.py)
- MulticastDiscoveryResult dataclass (scanner.py)
"""
from __future__ import annotations

import struct

import pytest

from javapwner.core.serialization import fingerprint_java_version
from javapwner.protocols.jini.codebase import ClassFileInfo, CodebaseExplorer
from javapwner.protocols.jini.probe import DgcFingerprintResult, JiniProbe
from javapwner.protocols.jini.protocol import build_multicast_request_v1
from javapwner.protocols.jini.scanner import MulticastDiscoveryResult


# -----------------------------------------------------------------------
# Java version fingerprinting
# -----------------------------------------------------------------------

class TestFingerprintJavaVersion:
    def test_known_jdk8_marshalled_object(self):
        uids = {"java.rmi.MarshalledObject": 7834398015428807710}
        hints = fingerprint_java_version(uids)
        assert len(hints) == 1
        assert "JDK 8" in hints[0]["hint"]

    def test_known_jdk9_marshalled_object(self):
        uids = {"java.rmi.MarshalledObject": -4768799335562104920}
        hints = fingerprint_java_version(uids)
        assert len(hints) == 1
        assert "JDK 9+" in hints[0]["hint"]

    def test_unknown_class_returns_empty(self):
        uids = {"com.example.UnknownClass": 12345}
        hints = fingerprint_java_version(uids)
        assert hints == []

    def test_multiple_matches(self):
        uids = {
            "java.rmi.MarshalledObject": 7834398015428807710,
            "java.util.HashMap": 362498820763181265,
        }
        hints = fingerprint_java_version(uids)
        assert len(hints) == 2
        classes = {h["class"] for h in hints}
        assert "java.rmi.MarshalledObject" in classes
        assert "java.util.HashMap" in classes

    def test_empty_input(self):
        assert fingerprint_java_version({}) == []

    def test_jini_river_registrar_proxy(self):
        # Apache River 3.x uses org.apache.river.reggie.RegistrarProxy
        uids = {"org.apache.river.reggie.RegistrarProxy": 2}
        hints = fingerprint_java_version(uids)
        assert len(hints) == 1
        assert "River 3" in hints[0]["hint"]
        assert hints[0]["discriminating"] == "True"


# -----------------------------------------------------------------------
# DGC fingerprint result
# -----------------------------------------------------------------------

class TestDgcFingerprintResult:
    def test_unreachable(self):
        r = DgcFingerprintResult(dgc_reachable=False)
        d = r.to_dict()
        assert d["status"] == "unreachable"

    def test_jep290_active(self):
        r = DgcFingerprintResult(dgc_reachable=True, jep290_active=True)
        d = r.to_dict()
        assert "filtered" in d["status"].lower() or "JEP 290" in d["status"]

    def test_unfiltered(self):
        r = DgcFingerprintResult(dgc_reachable=True, jep290_active=False)
        d = r.to_dict()
        assert "unfiltered" in d["status"].lower() or "RCE" in d["status"]

    def test_unknown(self):
        r = DgcFingerprintResult(dgc_reachable=True, jep290_active=None)
        d = r.to_dict()
        assert d["status"] == "unknown"

    def test_hashmap_payload(self):
        payload = JiniProbe._build_hashmap_payload()
        # Must start with Java serialization magic
        assert payload[:4] == b"\xac\xed\x00\x05"
        # Must contain java.util.HashMap class name
        assert b"java.util.HashMap" in payload


# -----------------------------------------------------------------------
# .class file constant-pool parser
# -----------------------------------------------------------------------

def _build_minimal_class(
    class_name: str = "com/example/Test",
    super_name: str = "java/lang/Object",
    interfaces: list[str] | None = None,
    methods: list[str] | None = None,
    fields: list[str] | None = None,
) -> bytes:
    """Build a minimal valid Java .class file for testing the parser."""
    interfaces = interfaces or []
    methods = methods or []
    fields = fields or []

    cp_entries: list[bytes] = []
    cp_map: dict[str, int] = {}
    idx = 1

    def add_utf8(s: str) -> int:
        nonlocal idx
        if s in cp_map:
            return cp_map[s]
        encoded = s.encode("utf-8")
        cp_entries.append(b"\x01" + struct.pack(">H", len(encoded)) + encoded)
        cp_map[s] = idx
        result = idx
        idx += 1
        return result

    def add_class(name: str) -> int:
        nonlocal idx
        name_idx = add_utf8(name)
        key = f"CLASS:{name}"
        if key in cp_map:
            return cp_map[key]
        cp_entries.append(b"\x07" + struct.pack(">H", name_idx))
        cp_map[key] = idx
        result = idx
        idx += 1
        return result

    # Build constant pool
    this_idx = add_class(class_name)
    super_idx = add_class(super_name)
    iface_idxs = [add_class(i) for i in interfaces]

    # Methods need name + descriptor (()V as dummy)
    desc_idx = add_utf8("()V")
    method_name_idxs = [add_utf8(m) for m in methods]

    # Fields
    field_name_idxs = [add_utf8(f) for f in fields]

    # Build binary
    buf = b"\xca\xfe\xba\xbe"  # magic
    buf += struct.pack(">HH", 0, 52)  # minor=0, major=52 (Java 8)
    buf += struct.pack(">H", idx)  # constant_pool_count
    buf += b"".join(cp_entries)
    buf += struct.pack(">H", 0x21)  # ACC_PUBLIC | ACC_SUPER
    buf += struct.pack(">H", this_idx)
    buf += struct.pack(">H", super_idx)
    buf += struct.pack(">H", len(iface_idxs))
    for ii in iface_idxs:
        buf += struct.pack(">H", ii)

    # Fields
    buf += struct.pack(">H", len(field_name_idxs))
    for fi in field_name_idxs:
        buf += struct.pack(">H", 0x01)  # ACC_PUBLIC
        buf += struct.pack(">H", fi)  # name_index
        buf += struct.pack(">H", desc_idx)  # descriptor_index
        buf += struct.pack(">H", 0)  # attributes_count

    # Methods
    buf += struct.pack(">H", len(method_name_idxs))
    for mi in method_name_idxs:
        buf += struct.pack(">H", 0x01)  # ACC_PUBLIC
        buf += struct.pack(">H", mi)  # name_index
        buf += struct.pack(">H", desc_idx)  # descriptor_index
        buf += struct.pack(">H", 0)  # attributes_count

    return buf


class TestClassFileParsing:
    def test_basic_class(self):
        data = _build_minimal_class()
        info = CodebaseExplorer._parse_class_file(data)
        assert info.class_name == "com.example.Test"
        assert info.super_class == "java.lang.Object"

    def test_interfaces(self):
        data = _build_minimal_class(
            interfaces=["java/rmi/Remote", "java/io/Serializable"],
        )
        info = CodebaseExplorer._parse_class_file(data)
        assert "java.rmi.Remote" in info.interfaces
        assert "java.io.Serializable" in info.interfaces

    def test_methods(self):
        data = _build_minimal_class(methods=["lookup", "register", "notify"])
        info = CodebaseExplorer._parse_class_file(data)
        assert "lookup" in info.method_names
        assert "register" in info.method_names
        assert "notify" in info.method_names

    def test_fields(self):
        data = _build_minimal_class(fields=["serviceID", "proxy"])
        info = CodebaseExplorer._parse_class_file(data)
        assert "serviceID" in info.field_names
        assert "proxy" in info.field_names

    def test_synthetic_methods_excluded(self):
        """Methods starting with '<' (like <init>, <clinit>) should be excluded."""
        data = _build_minimal_class(methods=["<init>", "doWork"])
        info = CodebaseExplorer._parse_class_file(data)
        # <init> is in the .class but should be filtered out
        assert "<init>" not in info.method_names
        # But WAIT — our builder doesn't produce <init> correctly since it's
        # filtered by the parser. Let's just check doWork is there.
        assert "doWork" in info.method_names

    def test_invalid_data_returns_empty_info(self):
        info = CodebaseExplorer._parse_class_file(b"\x00\x00\x00\x00")
        assert info.class_name == ""
        assert info.interfaces == []

    def test_truncated_data(self):
        data = _build_minimal_class()
        info = CodebaseExplorer._parse_class_file(data[:20])
        # Should not crash — best-effort
        assert isinstance(info, ClassFileInfo)

    def test_to_dict(self):
        info = ClassFileInfo(
            url="http://example.com/Test.class",
            class_name="com.example.Test",
            super_class="java.lang.Object",
            interfaces=["java.rmi.Remote"],
            method_names=["lookup"],
            field_names=["id"],
            size=1024,
        )
        d = info.to_dict()
        assert d["class_name"] == "com.example.Test"
        assert d["interfaces"] == ["java.rmi.Remote"]
        assert d["size"] == 1024


# -----------------------------------------------------------------------
# Multicast Discovery
# -----------------------------------------------------------------------

class TestMulticastRequest:
    def test_v1_basic(self):
        data = build_multicast_request_v1(callback_port=5000)
        assert len(data) == 16  # 4 + 4 + 4 + 4
        version = struct.unpack_from(">i", data, 0)[0]
        port = struct.unpack_from(">i", data, 4)[0]
        known = struct.unpack_from(">i", data, 8)[0]
        groups = struct.unpack_from(">i", data, 12)[0]
        assert version == 1
        assert port == 5000
        assert known == 0
        assert groups == 0

    def test_v1_with_groups(self):
        data = build_multicast_request_v1(callback_port=1234, groups=["public", "test"])
        version = struct.unpack_from(">i", data, 0)[0]
        assert version == 1
        group_count = struct.unpack_from(">i", data, 12)[0]
        assert group_count == 2


class TestMulticastDiscoveryResult:
    def test_empty(self):
        r = MulticastDiscoveryResult()
        d = r.to_dict()
        assert d["sent"] is False
        assert d["responder_count"] == 0

    def test_with_responders(self):
        r = MulticastDiscoveryResult(
            sent=True,
            responders=[
                {"source": "10.0.0.1:4160", "unicast_version": 1},
                {"source": "10.0.0.2:4160", "unicast_version": 2},
            ],
        )
        d = r.to_dict()
        assert d["responder_count"] == 2
        assert d["sent"] is True
