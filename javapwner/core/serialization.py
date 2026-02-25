"""Heuristic detection and parsing of Java serialization streams."""

from __future__ import annotations

import re
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

# Regex for raw URL extraction from byte streams
_RAW_URL_RE = re.compile(
    rb"((?:https?|file|jrmis?|rmi)://[^\x00-\x1f\x80-\xff\s\"'<>]{4,256})"
)
_HOST_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*"
    r"|(?:\d{1,3}\.){3}\d{1,3})$"
)
_MAX_HOST_LEN = 253


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


def find_nested_streams(data: bytes) -> list[tuple[int, bytes]]:
    """Find nested Java serialization streams within *data*.

    Searches for JAVA_SERIAL_HEADER starting from offset 4 (skipping the
    outer header) and returns a list of ``(offset, data[offset:])`` tuples
    for each nested stream found.
    """
    results: list[tuple[int, bytes]] = []
    magic = JAVA_SERIAL_HEADER
    start = 4
    while True:
        idx = data.find(magic, start)
        if idx == -1:
            break
        results.append((idx, data[idx:]))
        start = idx + 1
    return results


def extract_strings_with_offsets(data: bytes) -> list[tuple[str, int]]:
    """Like :func:`extract_strings_from_stream` but returns ``(string, end_offset)`` pairs.

    *end_offset* is the byte position immediately after each string, enabling
    the caller to read a following big-endian integer (e.g. a TCPEndpoint port).
    """
    results: list[tuple[str, int]] = []
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
                    results.append((s, end))
                except Exception:
                    pass
            i += 3 + str_len
            continue

        if b == TC_LONGSTRING and i + 9 <= length:
            str_len = struct.unpack_from(">Q", data, i + 1)[0]
            end = i + 9 + str_len
            if end <= length and str_len < 0x10000:
                try:
                    s = data[i + 9: end].decode("utf-8", errors="replace")
                    results.append((s, end))
                except Exception:
                    pass
            i += 9 + str_len
            continue

        i += 1

    return results


def extract_raw_urls(data: bytes) -> list[str]:
    """Extract URLs from raw bytes using a regex scan.

    Finds URLs matching ``http/https/file/jrmi/rmi`` schemes embedded directly
    in the byte stream — including those in ``locBytes`` fields that are **not**
    wrapped as TC_STRING tokens.  Returns a deduplicated list of ASCII-decoded
    URL strings.
    """
    seen: set[str] = set()
    results: list[str] = []
    for match in _RAW_URL_RE.findall(data):
        try:
            url = match.decode("ascii")
            if url not in seen:
                seen.add(url)
                results.append(url)
        except Exception:
            pass
    return results


def extract_endpoint_hints(data: bytes) -> list[dict]:
    """Extract ``(host, port)`` hints from a Java serialization stream.

    Looks for TC_STRING values that match a valid hostname / IPv4 pattern,
    followed immediately by a big-endian ``uint32`` port in ``[1, 65535]``.
    Also scans all nested streams found within *data*.

    Returns a deduplicated list of ``{"host": str, "port": int}`` dicts.
    """
    seen: set[tuple[str, int]] = set()
    results: list[dict] = []

    def _scan(buf: bytes) -> None:
        for s, end_off in extract_strings_with_offsets(buf):
            if len(s) > _MAX_HOST_LEN:
                continue
            if not _HOST_RE.match(s):
                continue
            if end_off + 4 > len(buf):
                continue
            try:
                port = struct.unpack_from(">I", buf, end_off)[0]
            except struct.error:
                continue
            if 1 <= port <= 65535:
                key = (s, port)
                if key not in seen:
                    seen.add(key)
                    results.append({"host": s, "port": port})

    _scan(data)
    for _, sub in find_nested_streams(data):
        _scan(sub)

    return results
