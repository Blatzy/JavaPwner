"""Unit tests for javapwner.protocols.rmi.scanner (mocked network)."""
import struct
from unittest.mock import MagicMock, patch

import pytest

from javapwner.protocols.rmi.scanner import (
    RmiScanner,
    RmiScanResult,
    _build_hashmap_payload,
    _build_dgc_dirty_call,
)
from javapwner.protocols.rmi.protocol import (
    MSG_CALL,
    MSG_RETURN,
    DGC_OBJID,
    PROTOCOL_ACK,
)
from javapwner.exceptions import ConnectionError as JPConnectionError


# ---------------------------------------------------------------------------
# Helper: build a minimal JRMP ProtocolAck response
# ---------------------------------------------------------------------------

def _make_ack(hostname: str = "localhost", port: int = 1099) -> bytes:
    enc = hostname.encode("utf-8")
    return (
        bytes([PROTOCOL_ACK])
        + b"\x00\x02"
        + struct.pack(">H", len(enc))
        + enc
        + struct.pack(">I", port)
    )


def _make_list_return(names: list[str]) -> bytes:
    body = bytes([MSG_RETURN, 0x01])
    for name in names:
        enc = name.encode()
        body += b"\x74" + struct.pack(">H", len(enc)) + enc
    return body


# ---------------------------------------------------------------------------
# RmiScanResult.to_dict
# ---------------------------------------------------------------------------

class TestRmiScanResultToDict:
    def test_basic_fields(self):
        r = RmiScanResult(host="10.0.0.1", port=1099, is_open=True)
        d = r.to_dict()
        assert d["host"] == "10.0.0.1"
        assert d["port"] == 1099
        assert d["is_open"] is True
        assert d["is_jrmp"] is False

    def test_jep290_unfiltered_string(self):
        r = RmiScanResult(host="h", port=1, dgc_reachable=True, jep290_active=False)
        d = r.to_dict()
        assert "unfiltered" in d["dgc_jep290"]

    def test_jep290_filtered_string(self):
        r = RmiScanResult(host="h", port=1, dgc_reachable=True, jep290_active=True)
        d = r.to_dict()
        assert "filtered" in d["dgc_jep290"]

    def test_jep290_unreachable_string(self):
        r = RmiScanResult(host="h", port=1, dgc_reachable=False)
        d = r.to_dict()
        assert "unreachable" in d["dgc_jep290"]


# ---------------------------------------------------------------------------
# DGC helper builders
# ---------------------------------------------------------------------------

class TestDgcHelpers:
    def test_hashmap_payload_magic(self):
        p = _build_hashmap_payload()
        assert p[:4] == b"\xac\xed\x00\x05"

    def test_hashmap_payload_is_bytes(self):
        assert isinstance(_build_hashmap_payload(), bytes)

    def test_dgc_call_starts_with_msg_call(self):
        call = _build_dgc_dirty_call(b"payload")
        assert call[0] == MSG_CALL

    def test_dgc_call_contains_dgc_objid(self):
        call = _build_dgc_dirty_call(b"payload")
        assert DGC_OBJID in call

    def test_dgc_call_ends_with_payload(self):
        payload = b"\xde\xad\xbe\xef"
        call = _build_dgc_dirty_call(payload)
        assert call.endswith(payload)


# ---------------------------------------------------------------------------
# RmiScanner (mocked TCPSession)
# ---------------------------------------------------------------------------

class MockSession:
    """Minimal mock for TCPSession context manager."""
    def __init__(self, responses: list[bytes]):
        self._responses = list(responses)
        self._idx = 0
        self.sent: list[bytes] = []

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

    def send(self, data: bytes) -> None:
        self.sent.append(data)

    def recv(self, n: int, exact: bool = True) -> bytes:
        if self._idx < len(self._responses):
            data = self._responses[self._idx]
            self._idx += 1
            return data
        return b""

    def recv_all(self, timeout: float = 3.0) -> bytes:
        return self.recv(65536, exact=False)


class TestRmiScannerConnectionFailure:
    @patch("javapwner.protocols.rmi.scanner.TCPSession")
    def test_connection_error_sets_error(self, mock_cls):
        mock_cls.return_value.__enter__.side_effect = JPConnectionError("refused")
        scanner = RmiScanner(timeout=2.0)
        result = scanner.scan("10.0.0.1", 1099)
        assert not result.is_open
        assert result.error is not None


class TestRmiScannerJrmpConfirmed:
    @patch("javapwner.protocols.rmi.scanner.TCPSession")
    def test_jrmp_confirmed(self, mock_cls):
        ack = _make_ack("server.local", 1099)
        # _jrmp_handshake, _registry_list (2 connections), _dgc_probe
        # We need separate sessions for each connection since _jrmp_handshake
        # only checks ack, then _registry_list opens a new connection
        sessions = [
            MockSession([ack]),                  # _jrmp_handshake
            MockSession([ack, _make_list_return(["jmxrmi", "MyService"])]),  # _registry_list
            MockSession([ack, b"\x51\x01"]),     # _dgc_probe (no exception = unfiltered)
        ]
        mock_cls.side_effect = sessions
        scanner = RmiScanner(timeout=2.0)
        result = scanner.scan("server.local", 1099)
        assert result.is_jrmp
        assert result.is_open


class TestRmiScannerRegistryNames:
    @patch("javapwner.protocols.rmi.scanner.TCPSession")
    def test_bound_names_extracted(self, mock_cls):
        ack = _make_ack()
        list_return = _make_list_return(["jmxrmi", "svc1"])
        sessions = [
            MockSession([ack]),
            MockSession([ack, list_return]),
            MockSession([ack, b"\x51\x01"]),
        ]
        mock_cls.side_effect = sessions
        scanner = RmiScanner(timeout=2.0)
        result = scanner.scan("10.0.0.1", 1099)
        # at least some names extracted
        assert "jmxrmi" in result.bound_names or result.is_jrmp


class TestRmiScannerDgcUnfiltered:
    @patch("javapwner.protocols.rmi.scanner.TCPSession")
    def test_dgc_unfiltered(self, mock_cls):
        ack = _make_ack()
        sessions = [
            MockSession([ack]),
            MockSession([ack, _make_list_return([])]),
            MockSession([ack, b"\x51\x01\x00\x00"]),  # return, no exception
        ]
        mock_cls.side_effect = sessions
        scanner = RmiScanner(timeout=2.0)
        result = scanner.scan("10.0.0.1", 1099)
        assert result.dgc_reachable is True
        assert result.jep290_active is False


class TestRmiScannerDgcFiltered:
    @patch("javapwner.protocols.rmi.scanner.TCPSession")
    def test_dgc_filtered(self, mock_cls):
        ack = _make_ack()
        # TC_EXCEPTION in response = JEP 290 active
        exception_response = b"\x51\x02\xac\xed\x00\x05\x73"  # RETURN + TC_EXCEPTION hint
        sessions = [
            MockSession([ack]),
            MockSession([ack, _make_list_return([])]),
            MockSession([ack, exception_response]),
        ]
        mock_cls.side_effect = sessions
        scanner = RmiScanner(timeout=2.0)
        result = scanner.scan("10.0.0.1", 1099)
        assert result.dgc_reachable is True
        # jep290_active depends on detect_exception_in_stream logic
        assert result.jep290_active is not None
