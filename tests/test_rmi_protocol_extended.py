"""Unit tests for the extended RMI protocol module — parse_lookup_return,
build_unicastref_payload, TC_LONGSTRING, TC_REFERENCE handling."""

from __future__ import annotations

import struct

import pytest

from javapwner.protocols.rmi.protocol import (
    parse_lookup_return,
    build_unicastref_payload,
    _extract_class_name,
    _extract_tcp_endpoint,
    _extract_strings_from_return,
    MSG_RETURN,
    RETURN_VALUE,
    RETURN_EXCEPTION,
)


# ---------------------------------------------------------------------------
# _extract_strings_from_return — TC_LONGSTRING + TC_REFERENCE
# ---------------------------------------------------------------------------

class TestExtractStringsExtended:
    def test_tc_string(self):
        name = "hello"
        data = b"\x74" + struct.pack(">H", len(name)) + name.encode()
        result = _extract_strings_from_return(data)
        assert result == ["hello"]

    def test_tc_longstring(self):
        name = "longname"
        data = b"\x7C" + struct.pack(">Q", len(name)) + name.encode()
        result = _extract_strings_from_return(data)
        assert result == ["longname"]

    def test_tc_reference_back_ref(self):
        """TC_REFERENCE resolves to a previously seen TC_STRING handle."""
        name = "reftest"
        data = (
            b"\x74" + struct.pack(">H", len(name)) + name.encode()
            + b"\x71" + struct.pack(">I", 0x7E0000)  # back-ref to handle 0
        )
        result = _extract_strings_from_return(data)
        # The reference points to the same string, which is deduplicated
        assert "reftest" in result

    def test_multiple_strings(self):
        names = ["alice", "bob", "charlie"]
        data = b""
        for n in names:
            data += b"\x74" + struct.pack(">H", len(n)) + n.encode()
        result = _extract_strings_from_return(data)
        assert result == names


# ---------------------------------------------------------------------------
# parse_lookup_return
# ---------------------------------------------------------------------------

class TestParseLookupReturn:
    def test_empty_data(self):
        result = parse_lookup_return(b"")
        assert result["class_name"] is None
        assert result["endpoint"] is None

    def test_exception_return(self):
        data = bytes([MSG_RETURN, RETURN_EXCEPTION]) + b"\x00" * 10
        result = parse_lookup_return(data)
        assert "error" in result

    def test_class_name_extraction(self):
        # Build a TC_CLASSDESC with a class name
        class_name = "com.example.MyService"
        data = (
            bytes([MSG_RETURN, RETURN_VALUE])
            + b"\x00" * 4  # padding
            + b"\x72"  # TC_CLASSDESC
            + struct.pack(">H", len(class_name))
            + class_name.encode()
            + b"\x00" * 20  # serialVersionUID etc.
        )
        result = parse_lookup_return(data)
        assert result["class_name"] == "com.example.MyService"

    def test_tcp_endpoint_extraction(self):
        host = "10.0.0.5"
        port = 4444
        data = (
            bytes([MSG_RETURN, RETURN_VALUE])
            + b"\x00" * 4
            + b"\x74"  # TC_STRING
            + struct.pack(">H", len(host))
            + host.encode()
            + struct.pack(">i", port)
            + b"\x00" * 10
        )
        result = parse_lookup_return(data)
        assert result["endpoint"] is not None
        assert result["endpoint"]["host"] == "10.0.0.5"
        assert result["endpoint"]["port"] == 4444


# ---------------------------------------------------------------------------
# build_unicastref_payload
# ---------------------------------------------------------------------------

class TestBuildUnicastRefPayload:
    def test_contains_host_and_port(self):
        payload = build_unicastref_payload("attacker.local", 8888)
        # Should contain the host string
        assert b"attacker.local" in payload
        # Should contain the port
        assert struct.pack(">i", 8888) in payload

    def test_starts_with_java_magic(self):
        payload = build_unicastref_payload("1.2.3.4", 9999)
        assert payload[:2] == b"\xac\xed"
        assert payload[2:4] == b"\x00\x05"

    def test_contains_unicastref_class(self):
        payload = build_unicastref_payload("host", 1234)
        assert b"sun.rmi.server.UnicastRef" in payload


# ---------------------------------------------------------------------------
# _extract_class_name
# ---------------------------------------------------------------------------

class TestExtractClassName:
    def test_finds_java_class(self):
        name = "java.rmi.server.RemoteObject"
        data = b"\x72" + struct.pack(">H", len(name)) + name.encode() + b"\x00" * 20
        assert _extract_class_name(data) == name

    def test_returns_none_for_empty(self):
        assert _extract_class_name(b"") is None

    def test_skips_non_class_names(self):
        name = "notaclass"  # no dot, doesn't start with uppercase
        data = b"\x72" + struct.pack(">H", len(name)) + name.encode() + b"\x00" * 20
        # Should not match since it doesn't look like a Java class name
        assert _extract_class_name(data) is None


# ---------------------------------------------------------------------------
# _extract_tcp_endpoint
# ---------------------------------------------------------------------------

class TestExtractTcpEndpoint:
    def test_finds_ip_and_port(self):
        host = "192.168.1.1"
        data = b"\x74" + struct.pack(">H", len(host)) + host.encode() + struct.pack(">i", 8080)
        ep = _extract_tcp_endpoint(data)
        assert ep is not None
        assert ep["host"] == "192.168.1.1"
        assert ep["port"] == 8080

    def test_returns_none_for_invalid(self):
        assert _extract_tcp_endpoint(b"\x00\x01\x02") is None
