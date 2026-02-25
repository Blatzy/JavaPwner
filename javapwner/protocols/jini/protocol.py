"""Wire-level frames for the Jini Unicast Discovery Protocol (v1 and v2).

Reference: Apache River / Jini 2.2 specification
  com.sun.jini.discovery.internal.UnicastClient
  net.jini.discovery.LookupLocator

Unicast Discovery v1 wire format
---------------------------------
CLIENT → SERVER:
  00 00 00 01   (big-endian int32 = protocol version 1)

SERVER → CLIENT:
  AC ED 00 05   Java serialization stream containing:
    - MarshalledObject (ServiceRegistrar proxy)
    - int (group count)
    - N × writeUTF strings (group names)

Unicast Discovery v2 wire format
---------------------------------
CLIENT → SERVER: 14 bytes
  00 00 00 02           (int32 version = 2)
  00 01                 (uint16 : number of proposed format_ids = 1)
  C1 10 B0 B8 82 7C 00 00  (int64 PLAINTEXT_FORMAT_ID)

SERVER → CLIENT:
  00 00 00 02           (int32 version echo)
  [int64]               selected_format_id  (0 = refus)
  [writeUTF]            host string
  [uint16]              port
  [uint16]              group_count
  [N writeUTF]          group names
  AC ED ...             serialized MarshalledInstance (proxy ServiceRegistrar)
"""

from __future__ import annotations

import struct
from typing import Any

from javapwner.core.serialization import extract_strings_from_stream, is_java_serialized
from javapwner.core.socket_helper import (
    read_java_int,
    read_java_long,
    read_java_ushort,
    read_java_utf,
    write_java_int,
    write_java_long,
    write_java_ushort,
)
from javapwner.exceptions import ProtocolError

# The single format ID defined in the River spec for "plaintext" unicast.
PLAINTEXT_FORMAT_ID: int = 0xC110B0B8827C0000  # as unsigned; stored as signed long
# As a signed 64-bit value:
_PLAINTEXT_FORMAT_ID_SIGNED: int = struct.unpack(">q", bytes.fromhex("C110B0B8827C0000"))[0]


# ---------------------------------------------------------------------------
# Request builders
# ---------------------------------------------------------------------------

def build_unicast_request_v1() -> bytes:
    """Return the 4-byte client handshake for Unicast Discovery Protocol v1."""
    return write_java_int(1)


def build_unicast_request_v2(format_ids: list[int] | None = None) -> bytes:
    """Return the 14-byte client handshake for Unicast Discovery Protocol v2.

    *format_ids* defaults to ``[PLAINTEXT_FORMAT_ID]``.
    """
    if format_ids is None:
        format_ids = [_PLAINTEXT_FORMAT_ID_SIGNED]

    buf = write_java_int(2)                          # version = 2
    buf += write_java_ushort(len(format_ids))        # nb format_ids
    for fid in format_ids:
        buf += write_java_long(fid)
    return buf


def build_multicast_request_v1(
    callback_port: int,
    groups: list[str] | None = None,
) -> bytes:
    """Build a Multicast Discovery Request v1 datagram.

    The datagram is sent to 224.0.1.85:4160; any Reggie matching the
    requested *groups* (empty list = "any group") responds via TCP to
    the sender's IP on *callback_port*.

    Wire format::

        int32   protocol version = 1
        int32   callback port (for unicast TCP response)
        int32   count of known registrar ServiceIDs to exclude (0)
        int32   count of group names (0 = any)
        N × writeUTF  group name strings
    """
    if groups is None:
        groups = []
    buf = write_java_int(1)                # version
    buf += write_java_int(callback_port)   # callback port
    buf += write_java_int(0)               # no known service IDs to exclude
    buf += write_java_int(len(groups))     # group count
    for g in groups:
        encoded = g.encode("utf-8")
        buf += write_java_ushort(len(encoded)) + encoded
    return buf


# ---------------------------------------------------------------------------
# Response parsers
# ---------------------------------------------------------------------------

def parse_unicast_response_v1(data: bytes) -> dict[str, Any]:
    """Best-effort parse of a Unicast Discovery v1 server response.

    The response is a raw Java object stream containing:
      1. A serialised MarshalledObject (the ServiceRegistrar proxy)
      2. An int (group count)
      3. N writeUTF strings (group names)

    Because we are not running a full JVM we cannot actually deserialise the
    MarshalledObject.  Instead we use heuristic string extraction.

    Returns a dict with:
      ``is_valid``        – True if the response looks like a serial stream
      ``raw_bytes``       – the complete raw bytes
      ``groups``          – list of group names extracted heuristically
      ``fingerprint_strings`` – all strings found in the serial stream
    """
    result: dict[str, Any] = {
        "is_valid": False,
        "raw_bytes": data,
        "groups": [],
        "fingerprint_strings": [],
    }

    if not data:
        return result

    if not is_java_serialized(data):
        return result

    result["is_valid"] = True
    strings = extract_strings_from_stream(data)
    result["fingerprint_strings"] = strings

    # Heuristic: group names tend to appear early in the stream and are
    # short ASCII strings that do not look like class names (no dots).
    groups = [s for s in strings if s and "." not in s and len(s) < 64]
    result["groups"] = groups

    return result


def parse_unicast_response_v2(data: bytes) -> dict[str, Any]:
    """Parse the structured header of a Unicast Discovery v2 server response.

    Returns a dict with:
      ``is_valid``          – True if minimal header could be parsed
      ``version``           – echoed protocol version (should be 2)
      ``selected_format_id``– format id selected by server (0 = rejected)
      ``host``              – host string from server
      ``port``              – port from server
      ``groups``            – list of group name strings
      ``serial_offset``     – byte offset where the serial stream begins
      ``fingerprint_strings`` – strings extracted from the serial portion
      ``raw_bytes``         – complete raw bytes
    """
    result: dict[str, Any] = {
        "is_valid": False,
        "version": None,
        "selected_format_id": None,
        "host": None,
        "port": None,
        "groups": [],
        "serial_offset": None,
        "fingerprint_strings": [],
        "raw_bytes": data,
    }

    if len(data) < 12:
        return result

    try:
        offset = 0
        version, offset = read_java_int(data, offset)
        result["version"] = version

        selected_fid, offset = read_java_long(data, offset)
        result["selected_format_id"] = selected_fid

        if selected_fid == 0:
            # Server rejected all our format IDs — no further data expected.
            result["is_valid"] = True
            return result

        host, offset = read_java_utf(data, offset)
        result["host"] = host

        port, offset = read_java_ushort(data, offset)
        result["port"] = port

        group_count, offset = read_java_ushort(data, offset)
        groups = []
        for _ in range(group_count):
            grp, offset = read_java_utf(data, offset)
            groups.append(grp)
        result["groups"] = groups

        result["serial_offset"] = offset
        serial_data = data[offset:]
        v1_info = parse_unicast_response_v1(serial_data)
        result["fingerprint_strings"] = v1_info["fingerprint_strings"]
        result["is_valid"] = True

    except (struct.error, IndexError) as exc:
        raise ProtocolError(f"Failed to parse Unicast v2 response: {exc}") from exc

    return result
