"""Unit tests for javapwner.protocols.rmi.protocol."""
import struct
import pytest

from javapwner.protocols.rmi.protocol import (
    _make_objid,
    REGISTRY_OBJID,
    DGC_OBJID,
    ACTIVATOR_OBJID,
    build_jrmp_handshake,
    parse_jrmp_ack,
    build_list_call,
    build_lookup_call,
    parse_registry_return,
    _extract_strings_from_return,
    MSG_CALL,
    MSG_RETURN,
    JRMP_MAGIC,
    JAVA_STREAM_MAGIC,
    JAVA_STREAM_VERSION,
    TC_ENDBLOCKDATA,
    LIST_METHOD_HASH,
    LOOKUP_METHOD_HASH,
)


class TestObjIdEncoding:
    def test_registry_objid_length(self):
        assert len(REGISTRY_OBJID) == 20

    def test_dgc_objid_length(self):
        assert len(DGC_OBJID) == 20

    def test_registry_objid_num_zero(self):
        # First 8 bytes = long 0
        assert struct.unpack_from(">q", REGISTRY_OBJID, 0)[0] == 0

    def test_dgc_objid_num_two(self):
        # First 8 bytes = long 2
        assert struct.unpack_from(">q", DGC_OBJID, 0)[0] == 2

    def test_activator_objid_num_one(self):
        assert struct.unpack_from(">q", ACTIVATOR_OBJID, 0)[0] == 1

    def test_uid_portion_zeros(self):
        # Bytes 8-19 should all be zero for well-known IDs
        assert REGISTRY_OBJID[8:] == b"\x00" * 12

    def test_make_objid_arbitrary(self):
        oid = _make_objid(42)
        assert len(oid) == 20
        assert struct.unpack_from(">q", oid, 0)[0] == 42
        assert oid[8:] == b"\x00" * 12


class TestJrmpHandshake:
    def test_handshake_bytes(self):
        hs = build_jrmp_handshake()
        assert hs == b"\x4a\x52\x4d\x49\x00\x02\x4b"

    def test_handshake_starts_with_magic(self):
        hs = build_jrmp_handshake()
        assert hs[:4] == JRMP_MAGIC


class TestParseJrmpAck:
    def test_empty_raises(self):
        with pytest.raises(ValueError):
            parse_jrmp_ack(b"")

    def test_wrong_byte_raises(self):
        with pytest.raises(ValueError):
            parse_jrmp_ack(b"\x00")

    def test_valid_ack_only(self):
        result = parse_jrmp_ack(b"\x4e")
        assert result["ack_byte"] == 0x4e
        assert result["version"] is None

    def test_ack_with_version(self):
        data = b"\x4e\x00\x02"
        result = parse_jrmp_ack(data)
        assert result["version"] == 2

    def test_ack_with_hostname(self):
        # 0x4e + version(2) + writeUTF("localhost") + port(uint32)
        hostname = b"localhost"
        data = (
            b"\x4e"
            + b"\x00\x02"
            + struct.pack(">H", len(hostname))
            + hostname
            + struct.pack(">I", 1099)
        )
        result = parse_jrmp_ack(data)
        assert result["hostname"] == "localhost"
        assert result["port"] == 1099


class TestBuildListCall:
    def test_starts_with_msg_call(self):
        call = build_list_call()
        assert call[0] == MSG_CALL

    def test_contains_registry_objid(self):
        call = build_list_call()
        assert REGISTRY_OBJID in call

    def test_contains_list_hash(self):
        call = build_list_call()
        assert struct.pack(">q", LIST_METHOD_HASH) in call

    def test_op_minus_one(self):
        call = build_list_call()
        # op -1 appears after the ObjID (1 byte MSG_CALL + 20 bytes ObjID)
        op = struct.unpack_from(">i", call, 21)[0]
        assert op == -1

    def test_ends_with_stream(self):
        call = build_list_call()
        assert JAVA_STREAM_MAGIC in call


class TestBuildLookupCall:
    def test_contains_lookup_hash(self):
        call = build_lookup_call("SomeService")
        assert struct.pack(">q", LOOKUP_METHOD_HASH) in call

    def test_contains_service_name(self):
        call = build_lookup_call("MyService")
        assert b"MyService" in call


class TestParseRegistryReturn:
    def test_empty_data(self):
        result = parse_registry_return(b"")
        assert "error" in result

    def test_wrong_message_type(self):
        result = parse_registry_return(b"\x50")
        assert "error" in result

    def test_return_exception(self):
        result = parse_registry_return(bytes([MSG_RETURN, 0x02]))
        assert "error" in result

    def test_valid_return_with_names(self):
        # Craft a minimal RETURN value with two TC_STRING entries
        name1 = b"jmxrmi"
        name2 = b"MyService"
        body = (
            bytes([MSG_RETURN, 0x01])
            + b"\x74" + struct.pack(">H", len(name1)) + name1
            + b"\x74" + struct.pack(">H", len(name2)) + name2
        )
        result = parse_registry_return(body)
        assert "jmxrmi" in result.get("names", [])
        assert "MyService" in result.get("names", [])

    def test_no_names_returns_empty_list(self):
        body = bytes([MSG_RETURN, 0x01]) + b"\xac\xed\x00\x05\x78"
        result = parse_registry_return(body)
        assert result.get("names", []) == []


class TestExtractStringsFromReturn:
    def test_basic_extraction(self):
        name = b"jmxrmi"
        data = b"\x74" + struct.pack(">H", len(name)) + name
        names = _extract_strings_from_return(data)
        assert "jmxrmi" in names

    def test_multiple_strings(self):
        def make_str(s: str) -> bytes:
            enc = s.encode()
            return b"\x74" + struct.pack(">H", len(enc)) + enc

        data = make_str("svc1") + make_str("svc2") + make_str("svc3")
        names = _extract_strings_from_return(data)
        assert set(names) == {"svc1", "svc2", "svc3"}

    def test_deduplication(self):
        name = b"duplicate"
        entry = b"\x74" + struct.pack(">H", len(name)) + name
        names = _extract_strings_from_return(entry + entry)
        assert names.count("duplicate") == 1

    def test_invalid_utf8_skipped(self):
        bad = b"\x74\x00\x02\xff\xfe"
        names = _extract_strings_from_return(bad)
        assert names == []

    def test_empty_data(self):
        assert _extract_strings_from_return(b"") == []
