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

# Regex for file system paths
_UNIX_PATH_RE = re.compile(
    r"(/(?:etc|usr|opt|var|tmp|home|root|proc|sys|boot|mnt|srv|lib|bin|sbin|run|dev)"
    r"(?:/[a-zA-Z0-9._\-]+)*)"
)
_WIN_PATH_RE = re.compile(
    r"([A-Z]:\\(?:[a-zA-Z0-9._\-]+\\)*[a-zA-Z0-9._\-]+)"
)
_CLASSPATH_RE = re.compile(
    r"(/[a-zA-Z0-9._\-/]+\.(?:jar|class|war|ear|properties|xml|conf|cfg|policy))"
)

# Regex for Java system property names
_JAVA_PROP_RE = re.compile(
    r"\b((?:java|javax|sun|os|user|file|path|line|awt|jdk|com\.sun)"
    r"\.[a-zA-Z0-9_.]+)\b"
)

# ---------------------------------------------------------------------------
# Java version fingerprinting via serial version UIDs
# ---------------------------------------------------------------------------
# Standard JDK classes have well-known serialVersionUID values that change
# across major Java versions.  Matching the UID of a class found inside a
# serialized stream lets us fingerprint the JDK version that produced it.
#
# Each entry maps class_name -> {suid: "version_hint"}.
# UIDs are signed 64-bit (as read from TC_CLASSDESC).

_SUID_FINGERPRINT_DB: dict[str, dict[int, str]] = {
    # java.rmi.MarshalledObject — changed in JDK 8→ JDK 9
    "java.rmi.MarshalledObject": {
        7834398015428807710: "JDK 1.2 – 8",
        -4768799335562104920: "JDK 9+",
    },
    # sun.rmi.server.UnicastRef — present on v1 endpoints
    "sun.rmi.server.UnicastRef": {
        -2923896440498087721: "JDK 1.2+",
    },
    # sun.rmi.server.UnicastRef2
    "sun.rmi.server.UnicastRef2": {
        1829537514995881838: "JDK 1.2+",
    },
    # net.jini.core.lookup.ServiceID / ServiceRegistrar proxy UIDs
    "net.jini.core.lookup.ServiceID": {
        -7803375959559762239: "Jini 2.0+",
    },
    # com.sun.jini.reggie.RegistrarProxy — common Reggie proxy
    "com.sun.jini.reggie.RegistrarProxy": {
        2: "Jini 2.0 / River 2.x",
    },
    # org.apache.river.reggie.RegistrarProxy
    "org.apache.river.reggie.RegistrarProxy": {
        2: "River 3.x",
    },
    # java.util.HashMap
    "java.util.HashMap": {
        362498820763181265: "JDK 1.2+",
    },
    # java.util.ArrayList
    "java.util.ArrayList": {
        8683452581122892189: "JDK 1.2+",
    },
    # java.lang.reflect.Proxy (dynamic proxy)
    "java.lang.reflect.Proxy": {
        -2222568056686623797: "JDK 1.3+",
    },
    # java.rmi.server.RemoteObject
    "java.rmi.server.RemoteObject": {
        -3215090123894869218: "JDK 1.1+",
    },
    # java.rmi.server.RemoteServer
    "java.rmi.server.RemoteServer": {
        -4100238210092549637: "JDK 1.1+",
    },
    # java.rmi.server.UnicastRemoteObject
    "java.rmi.server.UnicastRemoteObject": {
        4974527148936298033: "JDK 1.1+",
    },
}


def fingerprint_java_version(serial_uids: dict[str, int]) -> list[dict[str, str]]:
    """Match serial version UIDs against known JDK class fingerprints.

    *serial_uids* should be ``{class_name: suid}`` as returned by
    :func:`parse_class_descriptors`.

    Returns a list of ``{"class": ..., "suid": ..., "hint": ...}`` dicts.
    """
    hits: list[dict[str, str]] = []
    for cls_name, uid in serial_uids.items():
        db_entry = _SUID_FINGERPRINT_DB.get(cls_name)
        if db_entry:
            hint = db_entry.get(uid)
            if hint:
                hits.append({"class": cls_name, "suid": str(uid), "hint": hint})
            else:
                # Unknown SUID for a known class → report as interesting
                hits.append({
                    "class": cls_name,
                    "suid": str(uid),
                    "hint": f"unknown SUID (not in fingerprint DB)",
                })
    return hits


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


# ---------------------------------------------------------------------------
# Deep serial stream analysis — class descriptors, annotations, system info
# ---------------------------------------------------------------------------


def parse_class_descriptors(data: bytes) -> list[dict[str, Any]]:
    """Parse TC_CLASSDESC and TC_PROXYCLASSDESC entries from a serial stream.

    Returns a list of dicts:
      - For TC_CLASSDESC: ``{"type": "class", "name": ..., "uid": ..., "offset": ...}``
      - For TC_PROXYCLASSDESC: ``{"type": "proxy", "interfaces": [...], "offset": ...}``
    """
    results: list[dict[str, Any]] = []

    def _scan(buf: bytes, base_offset: int = 0) -> None:
        i = 0
        length = len(buf)

        while i < length:
            b = buf[i]

            # TC_CLASSDESC: 0x72 + uint16 name_len + name + int64 SUID + ...
            if b == TC_CLASSDESC and i + 3 <= length:
                try:
                    name_len = struct.unpack_from(">H", buf, i + 1)[0]
                    name_end = i + 3 + name_len
                    if name_end + 8 <= length and name_len < 512:
                        name = buf[i + 3:name_end].decode("utf-8", errors="replace")
                        uid = struct.unpack_from(">q", buf, name_end)[0]
                        # Sanity: class names should look like identifiers
                        if name and ("." in name or name[0].isupper() or name.startswith("[")):
                            results.append({
                                "type": "class",
                                "name": name,
                                "uid": uid,
                                "offset": base_offset + i,
                            })
                except (struct.error, IndexError):
                    pass
                i += 1
                continue

            # TC_PROXYCLASSDESC: 0x7D + int32 iface_count + N × writeUTF
            if b == TC_PROXYCLASSDESC and i + 5 <= length:
                try:
                    iface_count = struct.unpack_from(">I", buf, i + 1)[0]
                    if 0 < iface_count <= 64:
                        offset = i + 5
                        interfaces: list[str] = []
                        valid = True
                        for _ in range(iface_count):
                            if offset + 2 > length:
                                valid = False
                                break
                            iface_len = struct.unpack_from(">H", buf, offset)[0]
                            offset += 2
                            if offset + iface_len > length or iface_len > 512:
                                valid = False
                                break
                            iname = buf[offset:offset + iface_len].decode(
                                "utf-8", errors="replace"
                            )
                            interfaces.append(iname)
                            offset += iface_len
                        if valid and interfaces:
                            results.append({
                                "type": "proxy",
                                "interfaces": interfaces,
                                "offset": base_offset + i,
                            })
                except (struct.error, IndexError):
                    pass
                i += 1
                continue

            i += 1

    _scan(data, 0)
    for nested_off, sub in find_nested_streams(data):
        _scan(sub, nested_off)

    # Deduplicate by (type, name/interfaces)
    seen: set[str] = set()
    deduped: list[dict[str, Any]] = []
    for entry in results:
        if entry["type"] == "class":
            key = f"class:{entry['name']}"
        else:
            key = f"proxy:{','.join(entry['interfaces'])}"
        if key not in seen:
            seen.add(key)
            deduped.append(entry)

    return deduped


def extract_class_annotations(data: bytes) -> list[dict[str, Any]]:
    """Extract codebase URL annotations from class descriptors.

    In RMI serialization, each class descriptor is followed by a
    ``classAnnotation`` section that typically contains:
      TC_STRING <codebase_url> TC_ENDBLOCKDATA

    Returns a list of ``{"class_name": ..., "annotation_url": ...}`` dicts.
    """
    results: list[dict[str, Any]] = []
    i = 0
    length = len(data)

    while i < length:
        b = data[i]

        if b == TC_CLASSDESC and i + 3 <= length:
            try:
                name_len = struct.unpack_from(">H", data, i + 1)[0]
                name_end = i + 3 + name_len
                if name_end + 8 <= length and name_len < 512:
                    class_name = data[i + 3:name_end].decode("utf-8", errors="replace")
                    # Skip past SUID (8 bytes) + flags (1 byte) + field_count (2 bytes)
                    # Then scan for annotation URLs in the bytes that follow
                    scan_start = name_end + 8 + 1  # SUID + flags
                    if scan_start + 2 <= length:
                        field_count = struct.unpack_from(">H", data, scan_start)[0]
                        # Skip field descriptors (approximate — each is at least 3 bytes)
                        annot_start = scan_start + 2 + (field_count * 3)
                        # Search for TC_STRING + URL pattern in annotation area
                        scan_end = min(annot_start + 512, length)
                        for url in _RAW_URL_RE.findall(data[annot_start:scan_end]):
                            try:
                                url_str = url.decode("ascii")
                                results.append({
                                    "class_name": class_name,
                                    "annotation_url": url_str,
                                })
                            except Exception:
                                pass
            except (struct.error, IndexError):
                pass
            i += 1
            continue

        i += 1

    return results


def extract_file_paths(data: bytes) -> list[str]:
    """Extract filesystem paths embedded in a Java serialization stream.

    Scans both TC_STRING values and raw bytes for Unix and Windows paths,
    as well as classpath-style entries (``*.jar``, ``*.class``, etc.).
    """
    paths: set[str] = set()

    # From TC_STRING values
    strings = extract_strings_from_stream(data)
    for s in strings:
        for m in _UNIX_PATH_RE.findall(s):
            paths.add(m)
        for m in _WIN_PATH_RE.findall(s):
            paths.add(m)
        for m in _CLASSPATH_RE.findall(s):
            paths.add(m)

    # From raw bytes (catches paths not wrapped as TC_STRING)
    try:
        text = data.decode("ascii", errors="ignore")
        for m in _UNIX_PATH_RE.findall(text):
            paths.add(m)
        for m in _WIN_PATH_RE.findall(text):
            paths.add(m)
        for m in _CLASSPATH_RE.findall(text):
            paths.add(m)
    except Exception:
        pass

    return sorted(paths)


def extract_system_info(data: bytes) -> dict[str, Any]:
    """Extract system-level information from a serialization stream.

    Returns a dict with keys:
      ``hostnames``        — hostnames extracted from endpoints and strings
      ``java_properties``  — Java system property names found
      ``file_paths``       — filesystem paths (delegated to extract_file_paths)
      ``class_names``      — Java class names from class descriptors
      ``proxy_interfaces`` — interface names from proxy class descriptors
      ``codebase_annotations`` — codebase URLs per class
      ``serial_version_uids`` — {class_name: SUID} for fingerprinting
    """
    strings = extract_strings_from_stream(data)
    descriptors = parse_class_descriptors(data)
    annotations = extract_class_annotations(data)
    file_paths = extract_file_paths(data)
    endpoints = extract_endpoint_hints(data)

    # Hostnames from endpoints
    hostnames: list[str] = []
    seen_hosts: set[str] = set()
    for ep in endpoints:
        h = ep["host"]
        if h not in seen_hosts:
            seen_hosts.add(h)
            hostnames.append(h)

    # Java property-like strings
    java_props: set[str] = set()
    for s in strings:
        for m in _JAVA_PROP_RE.findall(s):
            java_props.add(m)

    # Class names and UIDs
    class_names: list[str] = []
    proxy_interfaces: list[str] = []
    serial_uids: dict[str, int] = {}
    for desc in descriptors:
        if desc["type"] == "class":
            class_names.append(desc["name"])
            serial_uids[desc["name"]] = desc["uid"]
        elif desc["type"] == "proxy":
            proxy_interfaces.extend(desc["interfaces"])

    # Codebase annotation URLs
    codebase_annots: list[dict[str, str]] = []
    for annot in annotations:
        codebase_annots.append({
            "class": annot["class_name"],
            "url": annot["annotation_url"],
        })

    return {
        "hostnames": hostnames,
        "java_properties": sorted(java_props),
        "file_paths": file_paths,
        "class_names": class_names,
        "proxy_interfaces": proxy_interfaces,
        "codebase_annotations": codebase_annots,
        "serial_version_uids": serial_uids,
    }
