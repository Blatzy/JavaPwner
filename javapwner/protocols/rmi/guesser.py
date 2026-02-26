"""RMI method guessing — probe bound objects for known method signatures.

Technique: for a given bound name and known method hash (from a wordlist),
send ``CALL(hash, wrong_arg_type)``.  The server response reveals:
- ``java.io.UnmarshalException`` → method exists, wrong arguments
- ``java.rmi.NoSuchObjectException`` → object gone
- Connection reset / ``ClassNotFoundException`` → method does not exist

Strategy (remote-method-guesser / rmg approach):
1. Call ``Registry.lookup(name)`` → parse the stub bytes to extract the
   remote object's ``ObjID`` (20 wire bytes embedded in the ``LiveRef``).
2. Send probe CALLs to that ObjID with a deliberately invalid argument
   (TC_REFERENCE back-ref 0x71/0x00/0x7e/0x00/0x00).
3. An ``UnmarshalException`` in the response → method hash is recognised
   (method exists, wrong arg type).  Other exceptions → hash not found.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from javapwner.core.serialization import detect_exception_in_stream
from javapwner.core.socket_helper import TCPSession
from javapwner.exceptions import ConnectionError
from javapwner.protocols.rmi.protocol import (
    MSG_CALL,
    JAVA_STREAM_MAGIC,
    JAVA_STREAM_VERSION,
    TC_ENDBLOCKDATA,
    REGISTRY_OBJID,
    build_jrmp_handshake,
    parse_jrmp_ack,
    build_lookup_call,
    parse_lookup_return,
)

_RECV_TIMEOUT = 4.0

# Path to the default method wordlist shipped with JavaPwner
_DEFAULT_WORDLIST = Path(__file__).resolve().parent.parent.parent / "resources" / "rmi_methods.json"


# ---------------------------------------------------------------------------
# Result dataclass
# ---------------------------------------------------------------------------

@dataclass
class MethodGuessResult:
    """Result of method guessing for one bound name."""
    bound_name: str
    class_name: str | None = None
    confirmed_methods: list[str] = field(default_factory=list)
    rejected_methods: list[str] = field(default_factory=list)
    error: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "bound_name": self.bound_name,
            "class_name": self.class_name,
            "confirmed_methods": self.confirmed_methods,
            "rejected_methods": self.rejected_methods,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Method guesser
# ---------------------------------------------------------------------------

class RmiMethodGuesser:
    """Probe an RMI-bound object for known method signatures.

    Parameters
    ----------
    timeout:
        Network timeout in seconds.
    """

    def __init__(self, timeout: float = 5.0):
        self.timeout = timeout

    def guess(
        self,
        host: str,
        port: int,
        bound_name: str,
        wordlist: dict[str, int] | None = None,
    ) -> MethodGuessResult:
        """Probe *bound_name* for methods in *wordlist*.

        Parameters
        ----------
        host, port:
            Target RMI endpoint.
        bound_name:
            The RMI-bound name to probe.
        wordlist:
            Mapping of ``{method_name: method_hash}``.  If ``None``, the
            default wordlist is loaded.

        Returns
        -------
        MethodGuessResult
            Contains ``confirmed_methods`` (those that provoked
            ``UnmarshalException``) and ``rejected_methods`` (no response).
        """
        result = MethodGuessResult(bound_name=bound_name)

        if wordlist is None:
            wordlist = load_default_wordlist()

        # Step 1: lookup() → class name + ObjID of the remote object
        class_name, obj_id = self._lookup_stub(host, port, bound_name)
        result.class_name = class_name

        # Fall back to Registry ObjID if we couldn't extract the target's ObjID
        target_objid = obj_id if obj_id is not None else REGISTRY_OBJID

        for method_name, method_hash in wordlist.items():
            exists = self._probe_method(host, port, target_objid, method_hash)
            if exists is True:
                result.confirmed_methods.append(method_name)
            elif exists is False:
                result.rejected_methods.append(method_name)
            # exists is None → inconclusive, skip

        return result

    def _lookup_stub(
        self, host: str, port: int, name: str
    ) -> tuple[str | None, bytes | None]:
        """Call Registry.lookup(name) and return (class_name, obj_id_bytes).

        Extracts both the remote class name from TC_CLASSDESC and the
        20-byte ObjID embedded in the LiveRef of the returned stub.
        Returns ``(None, None)`` on any failure.
        """
        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack = sess.recv(512, exact=False)
                if not ack:
                    return None, None
                parse_jrmp_ack(ack)

                sess.send(build_lookup_call(name))
                raw = sess.recv_all(timeout=_RECV_TIMEOUT)
                if not raw:
                    return None, None

                parsed = parse_lookup_return(raw)
                class_name = parsed.get("class_name")
                obj_id = _extract_objid_from_stub(raw)
                return class_name, obj_id
        except (ConnectionError, ValueError):
            return None, None

    def _probe_method(
        self, host: str, port: int, target_objid: bytes, method_hash: int
    ) -> bool | None:
        """Send a CALL with *method_hash* to *target_objid* with a bad argument.

        Returns:
        - ``True``   if the response contains ``UnmarshalException``
          (method hash recognised, wrong argument type)
        - ``False``  if connection reset or no response (hash unknown)
        - ``None``   if inconclusive (other exception)
        """
        probe_call = (
            bytes([MSG_CALL])
            + target_objid                    # ObjID of the remote object
            + struct.pack(">i", -1)           # op = -1 (hash dispatch)
            + struct.pack(">q", method_hash)  # target method hash
            + JAVA_STREAM_MAGIC
            + JAVA_STREAM_VERSION
            + b"\x71\x00\x7e\x00\x00"        # TC_REFERENCE invalid back-ref → UnmarshalException
            + bytes([TC_ENDBLOCKDATA])
        )

        try:
            with TCPSession(host, port, timeout=self.timeout) as sess:
                sess.send(build_jrmp_handshake())
                ack = sess.recv(512, exact=False)
                if not ack:
                    return None
                try:
                    parse_jrmp_ack(ack)
                except ValueError:
                    return None

                sess.send(probe_call)
                response = sess.recv_all(timeout=_RECV_TIMEOUT)

                if not response:
                    return False

                # UnmarshalException → method hash is known to the server
                if b"UnmarshalException" in response or b"unmarshal" in response.lower():
                    return True

                if detect_exception_in_stream(response):
                    # Other exception (NoSuchObjectException, etc.) → not found
                    return False

                return None
        except ConnectionError:
            return False


# ---------------------------------------------------------------------------
# Wordlist loader
# ---------------------------------------------------------------------------

def load_default_wordlist() -> dict[str, int]:
    """Load the default RMI method hash wordlist."""
    if _DEFAULT_WORDLIST.is_file():
        with open(_DEFAULT_WORDLIST) as f:
            data = json.load(f)
        # Flatten: {interface: {method: hash}} → {method: hash}
        flat: dict[str, int] = {}
        for interface_name, methods in data.items():
            if isinstance(methods, dict):
                flat.update(methods)
        return flat

    # Fallback: built-in minimal wordlist
    return _BUILTIN_WORDLIST.copy()


_BUILTIN_WORDLIST: dict[str, int] = {
    "lookup": -7538657168040752697,
    "list": 2571371466621089378,
    "bind": 7583982177005850366,
    "rebind": -8381844669958460146,
    "unbind": 7305022919901907578,
}


# ---------------------------------------------------------------------------
# ObjID extractor
# ---------------------------------------------------------------------------

def _extract_objid_from_stub(data: bytes) -> bytes | None:
    """Heuristically extract the 20-byte ObjID from a lookup() RETURN.

    A ``LiveRef`` in the stub stream encodes:
      ObjID (20 bytes) + endpoint string (TC_STRING) + port (int32) + flags

    Strategy: find the first TC_STRING that looks like a hostname/IP (used as
    the TCPEndpoint host), then read the 20 bytes that precede that string
    as the ObjID.  Returns ``None`` if the pattern is not found.
    """
    import re
    host_re = re.compile(
        rb"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
        rb"(?:\.(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?))*"
        rb"|(?:\d{1,3}\.){3}\d{1,3})$"
    )
    i = 0
    while i < len(data) - 7:
        if data[i] == 0x74:  # TC_STRING
            str_len = struct.unpack_from(">H", data, i + 1)[0]
            str_end = i + 3 + str_len
            if str_end + 4 <= len(data) and str_len < 256:
                host_candidate = data[i + 3:str_end]
                if host_re.match(host_candidate):
                    # The ObjID (20 bytes) immediately precedes this TC_STRING
                    obj_start = i - 20
                    if obj_start >= 0:
                        candidate = data[obj_start:i]
                        # Sanity: the last 4 bytes (uid.count as int16 + padding) should be small
                        if len(candidate) == 20:
                            return candidate
        i += 1
    return None
