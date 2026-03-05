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
# Standard JDK classes have well-known serialVersionUID values.  Most SUIDs
# have been **stable since JDK 1.1** and therefore do NOT discriminate
# versions.  Only a handful of SUIDs actually changed across major JDK
# boundaries — those are the only ones useful for version pinpointing.
#
# DB structure: class_name -> {suid: (hint_text, discriminating: bool)}
#   discriminating=True  → this SUID **pins** the version range
#   discriminating=False → SUID is stable; confirms class presence only

_SUID_FINGERPRINT_DB: dict[str, dict[int, tuple[str, bool]]] = {
    # ──────────────── DISCRIMINATING entries ────────────────────────────────
    # java.rmi.MarshalledObject — THE key discriminator: SUID changed JDK 9
    "java.rmi.MarshalledObject": {
        7834398015428807710:  ("JDK 8 (toutes versions — SUID stable dans tout le JDK 8)", True),
        -4768799335562104920: ("JDK 9+", True),
    },
    # com.sun.jini.reggie.RegistrarProxy — old Sun Jini namespace
    # Proves the deployment uses pre-Apache-River Jini (Sun-era).
    # Typically runs on JDK 5–8 and predates JEP 290 hardening.
    "com.sun.jini.reggie.RegistrarProxy": {
        2: ("Sun Jini 2.x / River 2.x (com.sun namespace → likely JDK ≤ 8)", True),
    },
    # org.apache.river.reggie.RegistrarProxy — Apache River 3.x namespace
    "org.apache.river.reggie.RegistrarProxy": {
        2: ("Apache River 3.x (may run on JDK 9+)", True),
    },
    # java.lang.invoke.SerializedLambda — only exists JDK 8+
    "java.lang.invoke.SerializedLambda": {
        8025925345765570181: ("JDK 8+", True),
    },
    # ──────────────── PRESENCE-ONLY entries (stable SUIDs) ─────────────────
    # These confirm the class exists but the SUID is the same across all
    # JDK versions — they do NOT help narrow down the version.
    "sun.rmi.server.UnicastRef": {
        -2923896440498087721: ("RMI UnicastRef present (SUID stable since JDK 1.2)", False),
    },
    "sun.rmi.server.UnicastRef2": {
        1829537514995881838: ("RMI UnicastRef2 present (SUID stable since JDK 1.2)", False),
    },
    "net.jini.core.lookup.ServiceID": {
        -7803375959559762239: ("Jini ServiceID present (SUID stable since Jini 2.0)", False),
    },
    "java.util.HashMap": {
        362498820763181265: ("HashMap present (SUID stable since JDK 1.2)", False),
    },
    "java.util.ArrayList": {
        8683452581122892189: ("ArrayList present (SUID stable since JDK 1.2)", False),
    },
    "java.lang.reflect.Proxy": {
        -2222568056686623797: ("Dynamic proxy present (SUID stable since JDK 1.3)", False),
    },
    "java.rmi.server.RemoteObject": {
        -3215090123894869218: ("RemoteObject present (SUID stable since JDK 1.1)", False),
    },
    "java.rmi.server.RemoteServer": {
        -4100238210092549637: ("RemoteServer present (SUID stable since JDK 1.1)", False),
    },
    "java.rmi.server.UnicastRemoteObject": {
        4974527148936298033: ("UnicastRemoteObject present (SUID stable since JDK 1.1)", False),
    },
}


def fingerprint_java_version(serial_uids: dict[str, int]) -> list[dict[str, str]]:
    """Match serial version UIDs against known JDK class fingerprints.

    *serial_uids* should be ``{class_name: suid}`` as returned by
    :func:`parse_class_descriptors`.

    Returns a list of ``{"class": ..., "suid": ..., "hint": ...,
    "discriminating": True/False}`` dicts, sorted with discriminating
    entries first.
    """
    hits: list[dict[str, str]] = []
    for cls_name, uid in serial_uids.items():
        db_entry = _SUID_FINGERPRINT_DB.get(cls_name)
        if db_entry:
            match = db_entry.get(uid)
            if match:
                hint_text, discriminating = match
                hits.append({
                    "class": cls_name,
                    "suid": str(uid),
                    "hint": hint_text,
                    "discriminating": str(discriminating),
                })
            else:
                hits.append({
                    "class": cls_name,
                    "suid": str(uid),
                    "hint": "unknown SUID (not in fingerprint DB — may indicate unusual JDK)",
                    "discriminating": "True",  # unknown SUID IS interesting
                })
    # Sort: discriminating entries first
    hits.sort(key=lambda h: h["discriminating"] != "True")
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
    """Return True if the stream contains a serialization or JRMP exception.

    Detects two canonical patterns:

    1. **JRMP RETURN_EXCEPTION** — ``MSG_RETURN (0x51) + RETURN_EXCEPTION (0x02)``
       at the start of the response.  This is the authoritative indicator for
       all JRMP-based protocols (RMI Registry, DGC, JNP).

    2. **TC_EXCEPTION in a Java serial stream** — ``TC_EXCEPTION (0x7B)``
       immediately after a Java serialization header (``ACED 0005``).  Used by
       non-JRMP protocols (e.g. JBoss Remoting 2) that embed a serialized
       Throwable inside their own framing.

    Combining both patterns avoids false positives from bare ``0x7B`` bytes
    inside class names or serialized data while still handling every protocol
    variant implemented in this tool.
    """
    if not data:
        return False

    # Pattern 1 — JRMP: MSG_RETURN (0x51) followed by the standard return frame.
    # JRMP responses always start with the message-type byte (0x51 = MSG_RETURN).
    #
    # Actual wire format:
    #   51           MSG_RETURN
    #   AC ED 00 05  OOS magic + version
    #   77 0F        TC_BLOCKDATA, length=15
    #   02           RETURN_EXCEPTION (first byte inside the blockdata)
    #   ...          callId UID (10 bytes) + exception object
    #
    # The return-value type byte is at offset 7, not 1.  We check the OOS header
    # and TC_BLOCKDATA marker to avoid false positives from embedded 0x02 bytes.
    if data[0] == 0x51:
        # Standard format: 51 ACED0005 77 LL 02...
        if (len(data) >= 8
                and data[1:5] == b"\xac\xed\x00\x05"
                and data[5] == 0x77        # TC_BLOCKDATA
                and data[7] == 0x02):      # RETURN_EXCEPTION at blockdata[0]
            return True
        # TC_BLOCKDATALONG variant: 51 ACED0005 7A LLLLLLLL 02...
        if (len(data) >= 11
                and data[1:5] == b"\xac\xed\x00\x05"
                and data[5] == 0x7a        # TC_BLOCKDATALONG
                and data[10] == 0x02):     # RETURN_EXCEPTION at blockdata[0]
            return True

    # Pattern 2 — Java serial stream with TC_EXCEPTION directly after the header.
    # Format: ACED 0005 7B ...
    # Used by JBoss Remoting 2 and other non-JRMP binary protocols that wrap a
    # raw ObjectOutputStream inside their own frame.
    magic = b"\xac\xed\x00\x05"
    idx = data.find(magic)
    while idx != -1:
        pos = idx + 4
        if pos < len(data) and data[pos] == 0x7B:  # TC_EXCEPTION
            return True
        idx = data.find(magic, idx + 1)

    return False


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

    Two strategies are applied:

    1. **TC_STRING scan** — looks for TC_STRING tokens (0x74) containing a
       valid hostname / IPv4 string, followed by a big-endian ``uint32`` port.
       This catches endpoints serialised via ``ObjectOutputStream.writeObject``.

    2. **writeUTF scan** — Java's ``DataOutput.writeUTF()`` encodes strings as
       a 2-byte big-endian length followed by UTF bytes, with NO TC_STRING
       marker.  ``TCPEndpoint.write()`` uses this format: it emits one format
       byte (0x00), then ``writeUTF(host)``, then ``writeInt(port)``.  This
       covers Jini / Apache River Reggie proxies whose embedded JRMP endpoint
       is encoded via ``writeUTF`` rather than ``TC_STRING``.

    Both strategies scan all nested streams found within *data*.

    Returns a deduplicated list of ``{"host": str, "port": int}`` dicts.
    """
    seen: set[tuple[str, int]] = set()
    results: list[dict] = []

    def _add(s: str, port: int) -> None:
        key = (s, port)
        if key not in seen:
            seen.add(key)
            results.append({"host": s, "port": port})

    def _scan_tc_string(buf: bytes) -> None:
        """Scan TC_STRING-encoded hostname followed by writeInt port."""
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
                _add(s, port)

    # Matches only dotted hostnames (FQDNs, IPv4) — not bare labels.
    # Bare labels (e.g. Java class names like "UnicastRef2") are excluded to
    # reduce false positives from writeUTF string data in the stream.
    _dotted_host_re = re.compile(
        r"^(?:(?:\d{1,3}\.){3}\d{1,3}"          # IPv4
        r"|(?:[a-zA-Z0-9\-]+\.)+[a-zA-Z0-9\-]+)$"  # FQDN (at least one dot)
    )

    def _scan_writeutf(buf: bytes) -> None:
        """Scan writeUTF-encoded hostname followed by writeInt port.

        Searches every byte offset for a 2-byte big-endian length prefix that
        could introduce a valid hostname.  This catches ``TCPEndpoint.write()``
        output where the format is: [1-byte flag] [2-byte len] [host bytes]
        [4-byte port].

        Only dotted hostnames (IPv4 or FQDN) are accepted to suppress false
        positives from Java class names and other non-hostname strings.
        """
        n = len(buf)
        for i in range(n - 6):  # need at least 2 (len) + 1 (host) + 4 (port)
            str_len = struct.unpack_from(">H", buf, i)[0]
            if str_len < 3 or str_len > _MAX_HOST_LEN:
                continue
            end = i + 2 + str_len
            if end + 4 > n:
                continue
            try:
                s = buf[i + 2: end].decode("ascii")
            except Exception:
                continue
            if not _dotted_host_re.match(s):
                continue
            try:
                port = struct.unpack_from(">I", buf, end)[0]
            except struct.error:
                continue
            if 1 <= port <= 65535:
                _add(s, port)

    for buf in [data] + [sub for _, sub in find_nested_streams(data)]:
        _scan_tc_string(buf)
        _scan_writeutf(buf)

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


def infer_jdk_from_bytes(data: bytes) -> tuple[str, str]:
    """Infer JDK sub-version from a raw bytes response.

    Inspects class filter error messages and serialised class descriptors to
    narrow down the JVM version range.  Useful for guiding the pentester on
    which bypass strategy to use.

    Returns a ``(hint, confidence)`` tuple:

    * **hint** — one of:

      - ``"jdk8u121-8u231"``       — JEP290 present, property-configurable era
      - ``"jdk8u232+"``            — JEP290 with hardcoded depth>2 check
      - ``"jdk8u232+-or-jdk9+"``   — java.io.ObjectInputFilter seen, SUID ambiguous
      - ``"jdk8"``                  — MarshalledObject SUID confirms JDK 8, no filter class
      - ``"jdk9+"``                 — MarshalledObject SUID confirms JDK 9+
      - ``"unknown"``               — not enough signal

    * **confidence** — ``"high"`` | ``"medium"`` | ``"none"``

    Detection logic (in priority order):

    1. ``sun/misc/ObjectInputFilter`` or ``sun.misc.ObjectInputFilter`` in data
       → JDK 8u121–8u231 (high confidence): the filter class used in that era
       lived in the ``sun.misc`` package.

    2. ``java/io/ObjectInputFilter`` or ``java.io.ObjectInputFilter`` in data
       → JDK 8u232+ OR JDK 9+ (medium confidence): from 8u232 the class was
       promoted to ``java.io``; JDK 9 also uses ``java.io``.

    3. ``java.rmi.MarshalledObject`` SUID in serialised class descriptors:

       - SUID ``7834398015428807710`` → JDK 8 (all sub-versions share this SUID)
       - SUID ``-4768799335562104920`` → JDK 9+

    4. Combination of (2) + JDK-8 SUID → refine to ``"jdk8u232+"`` (high).

    When JEP290 is not active (no filter rejection message), the function can
    still use SUID-based hints, though these only confirm the major version.
    """
    if not data:
        return ("unknown", "none")

    # Step 1 — sun.misc.ObjectInputFilter: JDK 8u121-8u231
    if (b"sun/misc/ObjectInputFilter" in data
            or b"sun.misc.ObjectInputFilter" in data):
        return ("jdk8u121-8u231", "high")

    # Step 2 — java.io.ObjectInputFilter: JDK 8u232+ or JDK 9+
    has_java_io_filter = (
        b"java/io/ObjectInputFilter" in data
        or b"java.io.ObjectInputFilter" in data
    )

    # Step 3 — SUID-based inference via class descriptors
    descriptors = parse_class_descriptors(data)
    suid_map: dict[str, int] = {
        d["name"]: d["uid"]
        for d in descriptors
        if d["type"] == "class"
    }
    marshalled_suid = suid_map.get("java.rmi.MarshalledObject")

    # Step 4 — Combination logic
    if has_java_io_filter:
        if marshalled_suid == 7834398015428807710:
            # java.io + JDK-8 SUID → must be 8u232+
            return ("jdk8u232+", "high")
        return ("jdk8u232+-or-jdk9+", "medium")

    if marshalled_suid == 7834398015428807710:
        return ("jdk8", "high")
    if marshalled_suid == -4768799335562104920:
        return ("jdk9+", "high")

    return ("unknown", "none")


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
