"""Java RMI wire protocol primitives.

Wire format reference: JDK source ``sun/rmi/transport/`` and
``java/rmi/server/ObjID.java`` / ``sun/rmi/server/UnicastRef.java``.

ObjID encoding (20 bytes on the wire):
  - objNum  : long  (8 bytes, big-endian)
  - uid.unique : short (2 bytes)
  - uid.time   : long  (8 bytes)
  - uid.count  : short (2 bytes)

Well-known ObjIDs (all-zero UID):
  - Registry  : objNum = 0
  - Activator : objNum = 1
  - DGC        : objNum = 2

CALL message format (new-style hash dispatch, JDK 1.2+):
  0x50               MSG_CALL
  ObjID (20 bytes)
  int32  op = -1     (hash dispatch mode)
  int64  methodHash  (method-specific hash)
  [ObjectOutputStream stream with method arguments]
"""

from __future__ import annotations

import struct
from typing import Any

from javapwner.core.socket_helper import (
    read_java_utf,
    write_java_utf,
)

# ---------------------------------------------------------------------------
# JRMP constants (duplicated here so rmi/ is standalone; jrmp.py is Jini-only)
# ---------------------------------------------------------------------------

JRMP_MAGIC = b"\x4a\x52\x4d\x49"       # "JRMI"
JRMP_VERSION = b"\x00\x02"
STREAM_PROTOCOL = b"\x4b"               # StreamProtocol
PROTOCOL_ACK = 0x4E

MSG_CALL = 0x50
MSG_RETURN = 0x51
MSG_PING = 0x52
MSG_PING_ACK = 0x53
MSG_DGC_ACK = 0x54

# Return type codes embedded inside a RETURN message
RETURN_VALUE = 0x01
RETURN_EXCEPTION = 0x02

# Java serialisation magic (start of ObjectOutputStream)
JAVA_STREAM_MAGIC = b"\xac\xed"
JAVA_STREAM_VERSION = b"\x00\x05"
TC_ENDBLOCKDATA = 0x78
TC_EXCEPTION = 0x73      # first byte of an exception in the return stream


# ---------------------------------------------------------------------------
# ObjID builders
# ---------------------------------------------------------------------------

def _make_objid(obj_num: int) -> bytes:
    """Encode an ObjID with an all-zero UID as 20 wire bytes."""
    return (
        struct.pack(">q", obj_num)   # objNum: long (8 bytes)
        + struct.pack(">h", 0)       # uid.unique: short (2 bytes)
        + struct.pack(">q", 0)       # uid.time:   long (8 bytes)
        + struct.pack(">h", 0)       # uid.count:  short (2 bytes)
    )


REGISTRY_OBJID = _make_objid(0)
ACTIVATOR_OBJID = _make_objid(1)
DGC_OBJID = _make_objid(2)


# ---------------------------------------------------------------------------
# JRMP handshake
# ---------------------------------------------------------------------------

def build_jrmp_handshake() -> bytes:
    """Return the 7-byte JRMP client handshake."""
    return JRMP_MAGIC + JRMP_VERSION + STREAM_PROTOCOL


def parse_jrmp_ack(data: bytes) -> dict[str, Any]:
    """Parse a JRMP server ProtocolAck response.

    Returns ``{"ack_byte", "version", "hostname", "port"}``.
    Raises ``ValueError`` if the ack byte is wrong or data is empty.
    """
    if not data:
        raise ValueError("Empty JRMP response")
    ack = data[0]
    if ack != PROTOCOL_ACK:
        raise ValueError(
            f"Expected ProtocolAck (0x{PROTOCOL_ACK:02x}), got 0x{ack:02x}"
        )
    result: dict[str, Any] = {
        "ack_byte": ack,
        "version": None,
        "hostname": None,
        "port": None,
    }
    if len(data) < 3:
        return result
    result["version"] = struct.unpack_from(">H", data, 1)[0]
    if len(data) >= 5:
        try:
            hostname, offset = read_java_utf(data, 3)
            result["hostname"] = hostname
            if offset + 4 <= len(data):
                result["port"] = struct.unpack_from(">I", data, offset)[0]
        except (struct.error, IndexError):
            pass
    return result


# ---------------------------------------------------------------------------
# Registry interface / method hashes
# ---------------------------------------------------------------------------

# From sun/rmi/registry/RegistryImpl_Stub (interface hash for registry v1.2 stub)
REGISTRY_INTERFACE_HASH: int = 4905912898345647071

# Method hashes (from JDK, used with op=-1 in new-style dispatch)
LIST_METHOD_HASH: int = 2571371466621089378
LOOKUP_METHOD_HASH: int = -7538657168040752697
BIND_METHOD_HASH: int = 7583982177005850366
REBIND_METHOD_HASH: int = -8381844669958460146
UNBIND_METHOD_HASH: int = 7305022919901907578


# ---------------------------------------------------------------------------
# CALL builders
# ---------------------------------------------------------------------------

def _make_call(objid: bytes, method_hash: int, arg_stream: bytes) -> bytes:
    """Build a JRMP CALL message (new-style hash dispatch)."""
    return (
        bytes([MSG_CALL])
        + objid
        + struct.pack(">i", -1)           # op = -1 → hash dispatch
        + struct.pack(">q", method_hash)  # method hash
        + arg_stream
    )


def _empty_arg_stream() -> bytes:
    """ObjectOutputStream header with no objects (for no-arg methods)."""
    return JAVA_STREAM_MAGIC + JAVA_STREAM_VERSION + bytes([TC_ENDBLOCKDATA])


def build_list_call() -> bytes:
    """Build a Registry list() CALL (no arguments)."""
    return _make_call(REGISTRY_OBJID, LIST_METHOD_HASH, _empty_arg_stream())


def build_lookup_call(name: str) -> bytes:
    """Build a Registry lookup(String) CALL."""
    arg_stream = (
        JAVA_STREAM_MAGIC
        + JAVA_STREAM_VERSION
        + b"\x74"                  # TC_STRING
        + write_java_utf(name)     # writeUTF(name)
        + bytes([TC_ENDBLOCKDATA])
    )
    return _make_call(REGISTRY_OBJID, LOOKUP_METHOD_HASH, arg_stream)


# ---------------------------------------------------------------------------
# RETURN parser
# ---------------------------------------------------------------------------

def parse_registry_return(data: bytes) -> dict[str, Any]:
    """Parse a JRMP RETURN message from the Registry.

    Returns a dict with ``"names"`` (list[str]) on success, or
    ``"error"`` (str) on failure.
    """
    if not data:
        return {"error": "Empty response"}
    if data[0] != MSG_RETURN:
        return {"error": f"Expected MSG_RETURN (0x51), got 0x{data[0]:02x}"}
    if len(data) < 2:
        return {"error": "RETURN too short"}

    return_type = data[1]
    if return_type == RETURN_EXCEPTION:
        return {"error": "Registry returned an exception"}

    # The actual return value is a serialized ObjectOutputStream.
    # For list(), it is a String[] (TC_ARRAY of TC_STRING).
    # We extract strings heuristically since full deserialization would
    # require a JVM.
    names = _extract_strings_from_return(data[2:])
    return {"names": names}


def _extract_strings_from_return(data: bytes) -> list[str]:
    """Heuristically extract Java writeUTF strings from a serialised stream.

    Looks for the TC_STRING tag (0x74) followed by a 2-byte length prefix.
    This reliably extracts the bound names from a Registry list() response
    without needing a full deserialiser.
    """
    names: list[str] = []
    seen: set[str] = set()
    i = 0
    while i < len(data) - 3:
        if data[i] == 0x74:           # TC_STRING
            length = struct.unpack_from(">H", data, i + 1)[0]
            end = i + 3 + length
            if end <= len(data):
                try:
                    s = data[i + 3:end].decode("utf-8")
                    if s and s not in seen and len(s) < 512:
                        seen.add(s)
                        names.append(s)
                except UnicodeDecodeError:
                    pass
                i = end
                continue
        elif data[i] == 0x75:         # TC_ARRAY
            # Skip to find inner elements; just advance normally
            pass
        i += 1
    return names
