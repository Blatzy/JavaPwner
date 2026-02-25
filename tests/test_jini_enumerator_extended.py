"""Extended tests for JiniEnumerator — the 3 new fields added in enhanced enumeration."""

from __future__ import annotations

import struct

import pytest

from javapwner.protocols.jini.enumerator import EnumResult, JiniEnumerator
from javapwner.protocols.jini.scanner import ScanResult

_MAGIC = b"\xac\xed\x00\x05"
TC_STRING = 0x74


def _make_tc_string(s: str) -> bytes:
    enc = s.encode("utf-8")
    return bytes([TC_STRING]) + struct.pack(">H", len(enc)) + enc


def _make_scan_result(raw: bytes) -> ScanResult:
    return ScanResult(
        host="127.0.0.1",
        port=4160,
        is_open=True,
        has_unicast_response=True,
        raw_proxy_bytes=raw,
    )


# ---------------------------------------------------------------------------
# EnumResult dataclass — new fields
# ---------------------------------------------------------------------------

class TestEnumResultNewFields:
    def test_to_dict_contains_all_new_keys(self):
        r = EnumResult()
        d = r.to_dict()
        assert "codebase_urls" in d
        assert "embedded_endpoints" in d
        assert "nested_stream_count" in d

    def test_default_values(self):
        r = EnumResult()
        assert r.codebase_urls == []
        assert r.embedded_endpoints == []
        assert r.nested_stream_count == 0

    def test_to_dict_values_match_fields(self):
        r = EnumResult(
            codebase_urls=["http://x.com"],
            embedded_endpoints=[{"host": "1.2.3.4", "port": 1099}],
            nested_stream_count=2,
        )
        d = r.to_dict()
        assert d["codebase_urls"] == ["http://x.com"]
        assert d["embedded_endpoints"] == [{"host": "1.2.3.4", "port": 1099}]
        assert d["nested_stream_count"] == 2


# ---------------------------------------------------------------------------
# JiniEnumerator.enumerate() — new fields populated
# ---------------------------------------------------------------------------

class TestEnumeratorNewFieldsPopulated:
    def test_codebase_url_extracted_from_raw(self):
        raw = _MAGIC + b"http://codebase.example.com/classes" + b"\x00"
        sr = _make_scan_result(raw)
        enumerator = JiniEnumerator()
        result = enumerator.enumerate("127.0.0.1", 4160, scan_result=sr)
        assert "http://codebase.example.com/classes" in result.codebase_urls

    def test_nested_stream_count_one(self):
        raw = _MAGIC + b"\xde\xad" + _MAGIC + b"\x73"
        sr = _make_scan_result(raw)
        enumerator = JiniEnumerator()
        result = enumerator.enumerate("127.0.0.1", 4160, scan_result=sr)
        assert result.nested_stream_count == 1

    def test_nested_stream_count_zero(self):
        raw = _MAGIC + b"\x00" * 10
        sr = _make_scan_result(raw)
        enumerator = JiniEnumerator()
        result = enumerator.enumerate("127.0.0.1", 4160, scan_result=sr)
        assert result.nested_stream_count == 0

    def test_embedded_endpoint_extracted(self):
        host = "10.0.0.1"
        port = 1099
        raw = _MAGIC + _make_tc_string(host) + struct.pack(">I", port)
        sr = _make_scan_result(raw)
        enumerator = JiniEnumerator()
        result = enumerator.enumerate("127.0.0.1", 4160, scan_result=sr)
        assert {"host": host, "port": port} in result.embedded_endpoints

    def test_empty_raw_zero_counts(self):
        sr = _make_scan_result(b"")
        enumerator = JiniEnumerator()
        result = enumerator.enumerate("127.0.0.1", 4160, scan_result=sr)
        assert result.codebase_urls == []
        assert result.embedded_endpoints == []
        assert result.nested_stream_count == 0

    def test_to_dict_types_correct(self):
        raw = _MAGIC + b"http://x.com/y" + b"\x00"
        sr = _make_scan_result(raw)
        enumerator = JiniEnumerator()
        result = enumerator.enumerate("127.0.0.1", 4160, scan_result=sr)
        d = result.to_dict()
        assert isinstance(d["codebase_urls"], list)
        assert isinstance(d["embedded_endpoints"], list)
        assert isinstance(d["nested_stream_count"], int)

    def test_codebase_url_deduplication(self):
        url = b"http://example.com/cb"
        # Same URL in main stream and a nested stream
        raw = _MAGIC + url + b"\x00" + _MAGIC + url + b"\x00"
        sr = _make_scan_result(raw)
        enumerator = JiniEnumerator()
        result = enumerator.enumerate("127.0.0.1", 4160, scan_result=sr)
        assert result.codebase_urls.count("http://example.com/cb") == 1

    def test_existing_fields_unaffected(self):
        """Adding new fields must not break existing EnumResult behaviour."""
        r = EnumResult(groups=["public"], urls=["jrmi://host:1234/obj"])
        d = r.to_dict()
        assert d["groups"] == ["public"]
        assert d["urls"] == ["jrmi://host:1234/obj"]
        assert d["tier"] == 1
