"""Unit tests for javapwner.protocols.jini.protocol — byte-exact verification."""

import struct

import pytest

from javapwner.protocols.jini.protocol import (
    PLAINTEXT_FORMAT_ID,
    _PLAINTEXT_FORMAT_ID_SIGNED,
    build_unicast_request_v1,
    build_unicast_request_v2,
    parse_unicast_response_v1,
    parse_unicast_response_v2,
)


# ---------------------------------------------------------------------------
# build_unicast_request_v1
# ---------------------------------------------------------------------------

class TestBuildUnicastRequestV1:
    def test_length(self):
        assert len(build_unicast_request_v1()) == 4

    def test_exact_bytes(self):
        assert build_unicast_request_v1() == b"\x00\x00\x00\x01"

    def test_is_big_endian_int_1(self):
        value = struct.unpack(">i", build_unicast_request_v1())[0]
        assert value == 1


# ---------------------------------------------------------------------------
# build_unicast_request_v2
# ---------------------------------------------------------------------------

class TestBuildUnicastRequestV2:
    def test_length_single_format_id(self):
        # 4 (version) + 2 (nb format_ids) + 8 (format_id) = 14 bytes
        assert len(build_unicast_request_v2()) == 14

    def test_version_field(self):
        data = build_unicast_request_v2()
        version = struct.unpack_from(">i", data, 0)[0]
        assert version == 2

    def test_nb_format_ids_field(self):
        data = build_unicast_request_v2()
        nb = struct.unpack_from(">H", data, 4)[0]
        assert nb == 1

    def test_format_id_field(self):
        data = build_unicast_request_v2()
        fid = struct.unpack_from(">q", data, 6)[0]
        assert fid == _PLAINTEXT_FORMAT_ID_SIGNED

    def test_exact_bytes(self):
        expected = (
            b"\x00\x00\x00\x02"          # version = 2
            b"\x00\x01"                   # 1 format_id
            b"\xc1\x10\xb0\xb8\x82\x7c\x00\x00"  # PLAINTEXT_FORMAT_ID
        )
        assert build_unicast_request_v2() == expected

    def test_custom_format_ids(self):
        data = build_unicast_request_v2(format_ids=[1, 2])
        # 4 + 2 + 2*8 = 22 bytes
        assert len(data) == 22
        nb = struct.unpack_from(">H", data, 4)[0]
        assert nb == 2


# ---------------------------------------------------------------------------
# parse_unicast_response_v1
# ---------------------------------------------------------------------------

# Minimal Java serial stream fixture: just the magic + version bytes
_JAVA_SERIAL_MAGIC = b"\xac\xed\x00\x05"

# A TC_STRING (0x74) + 2-byte length + ASCII bytes for "public"
_TC_STRING_PUBLIC = b"\x74\x00\x06public"

# Realistic-ish fixture: magic + one string
_V1_FIXTURE = _JAVA_SERIAL_MAGIC + _TC_STRING_PUBLIC


class TestParseUnicastResponseV1:
    def test_empty_data_not_valid(self):
        result = parse_unicast_response_v1(b"")
        assert not result["is_valid"]

    def test_wrong_magic_not_valid(self):
        result = parse_unicast_response_v1(b"\xde\xad\xbe\xef")
        assert not result["is_valid"]

    def test_valid_stream_detected(self):
        result = parse_unicast_response_v1(_V1_FIXTURE)
        assert result["is_valid"]

    def test_raw_bytes_preserved(self):
        result = parse_unicast_response_v1(_V1_FIXTURE)
        assert result["raw_bytes"] == _V1_FIXTURE

    def test_fingerprint_strings_extracted(self):
        result = parse_unicast_response_v1(_V1_FIXTURE)
        assert "public" in result["fingerprint_strings"]

    def test_groups_no_dots(self):
        # "public" has no dots → should appear as a potential group name
        result = parse_unicast_response_v1(_V1_FIXTURE)
        assert "public" in result["groups"]

    def test_class_names_with_dots_not_in_groups(self):
        cls_name = b"net.jini.core.lookup.ServiceRegistrar"
        stream = _JAVA_SERIAL_MAGIC + b"\x74" + struct.pack(">H", len(cls_name)) + cls_name
        result = parse_unicast_response_v1(stream)
        assert "net.jini.core.lookup.ServiceRegistrar" not in result["groups"]
        assert "net.jini.core.lookup.ServiceRegistrar" in result["fingerprint_strings"]


# ---------------------------------------------------------------------------
# parse_unicast_response_v2
# ---------------------------------------------------------------------------

def _build_v2_response(host: str = "127.0.0.1", port: int = 4160,
                       groups: list[str] | None = None,
                       selected_fid: int | None = None) -> bytes:
    """Helper to build a minimal v2 server response for testing."""
    if groups is None:
        groups = ["public"]
    if selected_fid is None:
        selected_fid = _PLAINTEXT_FORMAT_ID_SIGNED

    data = struct.pack(">i", 2)                    # version echo
    data += struct.pack(">q", selected_fid)         # selected_format_id
    # host (writeUTF)
    enc = host.encode("utf-8")
    data += struct.pack(">H", len(enc)) + enc
    data += struct.pack(">H", port)                 # port
    data += struct.pack(">H", len(groups))          # group_count
    for g in groups:
        enc_g = g.encode("utf-8")
        data += struct.pack(">H", len(enc_g)) + enc_g
    # Append a minimal serial stream as the proxy
    data += _JAVA_SERIAL_MAGIC
    return data


class TestParseUnicastResponseV2:
    def test_too_short_not_valid(self):
        result = parse_unicast_response_v2(b"\x00\x00\x00\x02")
        assert not result["is_valid"]

    def test_version_echoed(self):
        result = parse_unicast_response_v2(_build_v2_response())
        assert result["version"] == 2

    def test_host_extracted(self):
        result = parse_unicast_response_v2(_build_v2_response(host="10.0.0.1"))
        assert result["host"] == "10.0.0.1"

    def test_port_extracted(self):
        result = parse_unicast_response_v2(_build_v2_response(port=9876))
        assert result["port"] == 9876

    def test_groups_extracted(self):
        result = parse_unicast_response_v2(_build_v2_response(groups=["dev", "prod"]))
        assert "dev" in result["groups"]
        assert "prod" in result["groups"]

    def test_zero_format_id_means_rejection(self):
        data = struct.pack(">i", 2) + struct.pack(">q", 0)
        result = parse_unicast_response_v2(data)
        assert result["is_valid"]
        assert result["selected_format_id"] == 0
        assert result["host"] is None

    def test_serial_offset_points_to_magic(self):
        raw = _build_v2_response()
        result = parse_unicast_response_v2(raw)
        assert result["serial_offset"] is not None
        assert raw[result["serial_offset"]:result["serial_offset"] + 4] == _JAVA_SERIAL_MAGIC
