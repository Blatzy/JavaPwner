"""Heuristic detection and parsing of Java serialization streams."""

from __future__ import annotations

import struct
from typing import Any

# Java serialization constants
STREAM_MAGIC = b"\xac\xed"
STREAM_VERSION = b"\x00\x05"
JAVA_SERIAL_HEADER = STREAM_MAGIC + STREAM_VERSION

# TypeCodes
TC_NULL = 0x70
TC_REFERENCE = 0x71
TC_CLASSDESC = 0x72
TC_OBJECT = 0x73
TC_STRING = 0x74
TC_ARRAY = 0x75
TC_CLASS = 0x76
TC_BLOCKDATA = 0x77
TC_ENDBLOCKDATA = 0x78
TC_RESET = 0x79
TC_BLOCKDATALONG = 0x7A
TC_EXCEPTION = 0x7B
TC_LONGSTRING = 0x7C
TC_PROXYCLASSDESC = 0x7D
TC_ENUM = 0x7E


def is_java_serialized(data: bytes) -> bool:
    """Return True if *data* starts with Java serialization magic bytes."""
    return data[:4] == JAVA_SERIAL_HEADER


def extract_strings_from_stream(data: bytes) -> list[str]:
    """Heuristically scan a Java serial stream for TC_STRING and TC_LONGSTRING
    tokens and return all decoded string values found.

    This is a best-effort extractor — it does not fully parse the object graph.
    Useful for pulling class names, group names, and URLs from proxy blobs.
    """
    results: list[str] = []
    i = 0
    length = len(data)

    while i < length:
        b = data[i]

        if b == TC_STRING and i + 3 <= length:
            str_len = struct.unpack_from(">H", data, i + 1)[0]
            end = i + 3 + str_len
            if end <= length:
                try:
                    s = data[i + 3: end].decode("utf-8", errors="replace")
                    results.append(s)
                except Exception:
                    pass
            i += 3 + str_len
            continue

        if b == TC_LONGSTRING and i + 9 <= length:
            str_len = struct.unpack_from(">Q", data, i + 1)[0]
            end = i + 9 + str_len
            if end <= length and str_len < 0x10000:  # sanity cap at 64 KiB
                try:
                    s = data[i + 9: end].decode("utf-8", errors="replace")
                    results.append(s)
                except Exception:
                    pass
            i += 9 + str_len
            continue

        i += 1

    return results


def detect_exception_in_stream(data: bytes) -> bool:
    """Return True if the stream contains a TC_EXCEPTION typecode (0x7b).

    Presence of TC_EXCEPTION after delivering a deserialization payload
    is a strong indicator that JEP290 / deserialization filters are active.
    """
    return TC_EXCEPTION.to_bytes(1, "big") in data


def get_stream_metadata(data: bytes) -> dict[str, Any]:
    """Return a metadata dict describing the top-level stream properties."""
    meta: dict[str, Any] = {
        "is_serialized": False,
        "stream_version": None,
        "first_typecode": None,
        "length": len(data),
    }

    if len(data) < 4:
        return meta

    if data[:2] == STREAM_MAGIC:
        meta["is_serialized"] = True
        meta["stream_version"] = struct.unpack_from(">H", data, 2)[0]
        if len(data) >= 5:
            meta["first_typecode"] = data[4]

    return meta
