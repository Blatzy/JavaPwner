"""Unit tests for javapwner.core.serialization."""

import struct

import pytest

from javapwner.core.serialization import (
    TC_EXCEPTION,
    TC_LONGSTRING,
    TC_STRING,
    detect_exception_in_stream,
    extract_endpoint_hints,
    extract_raw_urls,
    extract_strings_from_stream,
    extract_strings_with_offsets,
    find_nested_streams,
    get_stream_metadata,
    is_java_serialized,
)

_MAGIC = b"\xac\xed\x00\x05"


# ---------------------------------------------------------------------------
# is_java_serialized
# ---------------------------------------------------------------------------

class TestIsJavaSerialized:
    def test_valid_magic(self):
        assert is_java_serialized(_MAGIC + b"\x73")

    def test_wrong_magic(self):
        assert not is_java_serialized(b"\xde\xad\xbe\xef")

    def test_empty(self):
        assert not is_java_serialized(b"")

    def test_too_short(self):
        assert not is_java_serialized(b"\xac\xed")

    def test_exact_four_bytes(self):
        assert is_java_serialized(_MAGIC)


# ---------------------------------------------------------------------------
# extract_strings_from_stream
# ---------------------------------------------------------------------------

def _make_tc_string(s: str) -> bytes:
    enc = s.encode("utf-8")
    return bytes([TC_STRING]) + struct.pack(">H", len(enc)) + enc


def _make_tc_longstring(s: str) -> bytes:
    enc = s.encode("utf-8")
    return bytes([TC_LONGSTRING]) + struct.pack(">Q", len(enc)) + enc


class TestExtractStringsFromStream:
    def test_single_tc_string(self):
        data = _make_tc_string("hello")
        assert "hello" in extract_strings_from_stream(data)

    def test_multiple_tc_strings(self):
        data = _make_tc_string("foo") + _make_tc_string("bar")
        results = extract_strings_from_stream(data)
        assert "foo" in results
        assert "bar" in results

    def test_tc_longstring(self):
        data = _make_tc_longstring("longstring")
        assert "longstring" in extract_strings_from_stream(data)

    def test_empty_stream(self):
        assert extract_strings_from_stream(b"") == []

    def test_no_strings_in_magic_only(self):
        assert extract_strings_from_stream(_MAGIC) == []

    def test_jini_class_name(self):
        cls = "net.jini.core.lookup.ServiceRegistrar"
        data = _MAGIC + _make_tc_string(cls)
        results = extract_strings_from_stream(data)
        assert cls in results

    def test_string_with_preceding_noise(self):
        # Garbage bytes before a valid TC_STRING
        data = b"\x00\x01\x02" + _make_tc_string("found")
        assert "found" in extract_strings_from_stream(data)

    def test_truncated_string_length(self):
        # TC_STRING followed by length > remaining data → should not crash
        data = bytes([TC_STRING]) + struct.pack(">H", 100) + b"short"
        # Should not raise; may or may not return partial string
        extract_strings_from_stream(data)  # no exception


# ---------------------------------------------------------------------------
# detect_exception_in_stream
# ---------------------------------------------------------------------------

class TestDetectExceptionInStream:
    def test_exception_present(self):
        data = _MAGIC + bytes([TC_EXCEPTION])
        assert detect_exception_in_stream(data)

    def test_exception_absent(self):
        data = _MAGIC + bytes([TC_STRING])
        assert not detect_exception_in_stream(data)

    def test_empty(self):
        assert not detect_exception_in_stream(b"")


# ---------------------------------------------------------------------------
# get_stream_metadata
# ---------------------------------------------------------------------------

class TestGetStreamMetadata:
    def test_non_serial(self):
        meta = get_stream_metadata(b"\xde\xad\xbe\xef")
        assert not meta["is_serialized"]

    def test_valid_magic(self):
        meta = get_stream_metadata(_MAGIC + b"\x73")
        assert meta["is_serialized"]
        assert meta["stream_version"] == 5

    def test_first_typecode(self):
        meta = get_stream_metadata(_MAGIC + b"\x73")
        assert meta["first_typecode"] == 0x73

    def test_length(self):
        data = _MAGIC + b"\x00\x01\x02"
        meta = get_stream_metadata(data)
        assert meta["length"] == len(data)

    def test_too_short(self):
        meta = get_stream_metadata(b"\xac")
        assert not meta["is_serialized"]
        assert meta["first_typecode"] is None


# ---------------------------------------------------------------------------
# find_nested_streams
# ---------------------------------------------------------------------------

class TestFindNestedStreams:
    def test_no_nested(self):
        data = _MAGIC + b"\x00" * 20
        assert find_nested_streams(data) == []

    def test_one_nested(self):
        data = _MAGIC + b"\xde\xad" + _MAGIC + b"\x73"
        result = find_nested_streams(data)
        assert len(result) == 1
        assert result[0][0] == 6
        assert result[0][1].startswith(_MAGIC)

    def test_multiple_nested(self):
        data = _MAGIC + b"\x00" + _MAGIC + b"\x01" + _MAGIC + b"\x02"
        result = find_nested_streams(data)
        assert len(result) == 2

    def test_outer_header_not_returned(self):
        data = _MAGIC + b"\x00"
        assert find_nested_streams(data) == []

    def test_empty(self):
        assert find_nested_streams(b"") == []


# ---------------------------------------------------------------------------
# extract_strings_with_offsets
# ---------------------------------------------------------------------------

class TestExtractStringsWithOffsets:
    def test_single_string(self):
        data = _make_tc_string("hello")
        results = extract_strings_with_offsets(data)
        assert len(results) == 1
        s, end = results[0]
        assert s == "hello"
        assert end == len(data)

    def test_multiple_strings(self):
        data = _make_tc_string("foo") + _make_tc_string("bar")
        results = extract_strings_with_offsets(data)
        strs = [r[0] for r in results]
        assert "foo" in strs
        assert "bar" in strs

    def test_end_offset_positions_at_next_byte(self):
        host = "10.0.0.1"
        port_bytes = struct.pack(">I", 1099)
        data = _make_tc_string(host) + port_bytes
        results = extract_strings_with_offsets(data)
        assert results[0][0] == host
        # end_offset should point exactly at the start of port_bytes
        end = results[0][1]
        assert data[end: end + 4] == port_bytes

    def test_empty(self):
        assert extract_strings_with_offsets(b"") == []

    def test_longstring_offset(self):
        data = _make_tc_longstring("longval")
        results = extract_strings_with_offsets(data)
        assert len(results) == 1
        assert results[0][0] == "longval"
        assert results[0][1] == len(data)


# ---------------------------------------------------------------------------
# extract_raw_urls
# ---------------------------------------------------------------------------

class TestExtractRawUrls:
    def test_http_url(self):
        data = b"prefix " + b"http://example.com/foo" + b" suffix"
        urls = extract_raw_urls(data)
        assert "http://example.com/foo" in urls

    def test_https_url(self):
        data = b"https://secure.example.com/bar"
        urls = extract_raw_urls(data)
        assert "https://secure.example.com/bar" in urls

    def test_jrmi_url(self):
        data = b"jrmi://host:1234/service"
        urls = extract_raw_urls(data)
        assert "jrmi://host:1234/service" in urls

    def test_file_url(self):
        data = b"file:///tmp/classes"
        urls = extract_raw_urls(data)
        assert "file:///tmp/classes" in urls

    def test_rmi_url(self):
        data = b"rmi://host:1099/obj"
        urls = extract_raw_urls(data)
        assert "rmi://host:1099/obj" in urls

    def test_no_urls(self):
        assert extract_raw_urls(b"\x00\x01\x02\x03") == []

    def test_deduplication(self):
        url = b"http://example.com/a"
        data = url + b" " + url
        urls = extract_raw_urls(data)
        assert len([u for u in urls if u == "http://example.com/a"]) == 1

    def test_empty(self):
        assert extract_raw_urls(b"") == []


# ---------------------------------------------------------------------------
# extract_endpoint_hints
# ---------------------------------------------------------------------------

class TestExtractEndpointHints:
    def _hp(self, host: str, port: int) -> bytes:
        return _make_tc_string(host) + struct.pack(">I", port)

    def test_ipv4_host_and_port(self):
        data = _MAGIC + self._hp("192.168.1.1", 1099)
        hints = extract_endpoint_hints(data)
        assert {"host": "192.168.1.1", "port": 1099} in hints

    def test_hostname(self):
        data = _MAGIC + self._hp("my-host.example.com", 8080)
        hints = extract_endpoint_hints(data)
        assert {"host": "my-host.example.com", "port": 8080} in hints

    def test_port_zero_excluded(self):
        data = _MAGIC + self._hp("10.0.0.1", 0)
        hints = extract_endpoint_hints(data)
        assert not any(h["port"] == 0 for h in hints)

    def test_port_over_65535_excluded(self):
        data = _MAGIC + self._hp("10.0.0.1", 70000)
        hints = extract_endpoint_hints(data)
        assert not any(h["port"] == 70000 for h in hints)

    def test_non_host_string_ignored(self):
        data = _MAGIC + _make_tc_string("not a host!!!") + struct.pack(">I", 1099)
        hints = extract_endpoint_hints(data)
        assert len(hints) == 0

    def test_deduplication(self):
        entry = self._hp("10.0.0.1", 1099)
        data = _MAGIC + entry + entry
        hints = extract_endpoint_hints(data)
        assert len([h for h in hints if h["host"] == "10.0.0.1" and h["port"] == 1099]) == 1

    def test_empty_data(self):
        assert extract_endpoint_hints(b"") == []

    def test_nested_stream_scanned(self):
        inner = _MAGIC + self._hp("172.16.0.1", 2099)
        outer = _MAGIC + b"\xde\xad" + inner
        hints = extract_endpoint_hints(outer)
        assert {"host": "172.16.0.1", "port": 2099} in hints
