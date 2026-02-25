"""Unit tests for javapwner.core.serialization."""

import struct

import pytest

from javapwner.core.serialization import (
    TC_EXCEPTION,
    TC_LONGSTRING,
    TC_STRING,
    detect_exception_in_stream,
    extract_strings_from_stream,
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
