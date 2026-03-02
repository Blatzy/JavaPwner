"""Unit tests for JBoss JNP scanner and exploiter."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from javapwner.protocols.jboss.jnp import (
    JnpScanner,
    JnpExploiter,
    JnpScanResult,
    JnpExploitResult,
    _extract_jrmp_port,
    _build_dgc_dirty_call,
)
from javapwner.exceptions import ConnectionError as JPConnectionError


# ---------------------------------------------------------------------------
# Minimal JNP bootstrap bytes for testing
# bootstrap contains: OOS magic + ... + UnicastRef2 block with 127.0.0.1:4447
# ---------------------------------------------------------------------------

def _make_jnp_bootstrap(host: str = "127.0.0.1", port: int = 4447) -> bytes:
    """Build minimal JNP bootstrap bytes containing UnicastRef2 with given host:port."""
    host_bytes = host.encode("utf-8")
    unicast_block = (
        b"\x00\x0b" + b"UnicastRef2"           # writeUTF("UnicastRef2")
        + struct.pack(">H", len(host_bytes)) + host_bytes  # writeUTF(host)
        + struct.pack(">I", port)               # writeInt(port)
        + b"\x00" * 20                          # ObjID bytes (not parsed)
    )
    return b"\xac\xed\x00\x05" + b"bootstrap_junk" + unicast_block


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_mock_session(
    recv_data: bytes = b"\x4e\x00\x02\x00\x09localhost\x00\x00\x04\x4b",
    recv_all_data: bytes = b"\x51\x00\x01",  # non-empty so scan() doesn't return early
) -> MagicMock:
    """Return a mock TCPSession with preset recv / recv_all return values."""
    sess = MagicMock()
    sess.recv.return_value = recv_data
    sess.recv_all.return_value = recv_all_data
    return sess


def _setup_mock_session(MockSession: MagicMock, sess: MagicMock) -> None:
    """Wire sess into the MockSession class context-manager."""
    MockSession.return_value.__enter__ = MagicMock(return_value=sess)
    MockSession.return_value.__exit__ = MagicMock(return_value=False)


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

class TestJnpScanResult:
    def test_defaults(self):
        r = JnpScanResult(host="10.0.0.1", port=1099)
        assert r.is_open is False
        assert r.is_jnp is False
        assert r.bound_names == []

    def test_to_dict(self):
        r = JnpScanResult(host="10.0.0.1", port=1099, is_open=True, is_jnp=True)
        d = r.to_dict()
        assert d["host"] == "10.0.0.1"
        assert d["port"] == 1099
        assert d["is_jnp"] is True

    def test_to_dict_bound_names(self):
        r = JnpScanResult(
            host="10.0.0.1", port=4444,
            bound_names=["java:/DefaultDS", "jms/Queue"],
        )
        d = r.to_dict()
        assert "java:/DefaultDS" in d["bound_names"]


class TestJnpExploitResult:
    def test_defaults(self):
        r = JnpExploitResult()
        assert r.sent is False
        assert r.likely_success is False

    def test_to_dict(self):
        r = JnpExploitResult(sent=True, likely_success=True)
        d = r.to_dict()
        assert d["sent"] is True
        assert d["likely_success"] is True

    def test_to_dict_error(self):
        r = JnpExploitResult(error="Connection refused")
        assert r.to_dict()["error"] == "Connection refused"


# ---------------------------------------------------------------------------
# JnpScanner.scan
# ---------------------------------------------------------------------------

class TestJnpScanner:
    def test_init_timeout(self):
        s = JnpScanner(timeout=3.0)
        assert s.timeout == 3.0

    @patch("javapwner.protocols.jboss.jnp.parse_registry_return")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_open_jrmp_with_jboss_names(self, MockSession, mock_ack, mock_list):
        """JRMP handshake OK + JBoss JNDI names → is_jnp=True."""
        mock_ack.return_value = None
        mock_list.return_value = {"names": ["java:/DefaultDS", "jms/Queue"]}
        sess = _make_mock_session()
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("10.0.0.1", 4444)

        assert result.is_open is True
        assert result.is_jrmp is True
        assert result.is_jnp is True
        assert "java:/DefaultDS" in result.bound_names

    @patch("javapwner.protocols.jboss.jnp.parse_registry_return")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_port_4444_heuristic(self, MockSession, mock_ack, mock_list):
        """Port 4444 with generic names → is_jnp=True via port heuristic."""
        mock_ack.return_value = None
        mock_list.return_value = {"names": ["someService", "anotherService"]}
        sess = _make_mock_session()
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("10.0.0.1", 4444)

        assert result.is_open is True
        assert result.is_jnp is True  # falls back to port==4444

    @patch("javapwner.protocols.jboss.jnp.parse_registry_return")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_non_jboss_names_non_4444_port(self, MockSession, mock_ack, mock_list):
        """Generic names on port 1099 → is_jnp=False."""
        mock_ack.return_value = None
        mock_list.return_value = {"names": ["myService"]}
        sess = _make_mock_session()
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("10.0.0.1", 1099)

        assert result.is_open is True
        assert result.is_jnp is False

    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_jrmp_ack_failure(self, MockSession, mock_ack):
        """JRMP ack parse failure → error set, is_jrmp=False."""
        mock_ack.side_effect = ValueError("bad ack")
        sess = _make_mock_session()
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("10.0.0.1", 4444)

        assert result.is_open is True
        assert result.is_jrmp is False
        assert result.error is not None

    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_connection_refused(self, MockSession):
        """Connection refused → is_open=False, error set."""
        MockSession.return_value.__enter__ = MagicMock(
            side_effect=JPConnectionError("Connection refused")
        )
        MockSession.return_value.__exit__ = MagicMock(return_value=False)

        result = JnpScanner(timeout=2.0).scan("10.0.0.1", 4444)

        assert result.is_open is False
        assert result.error == "Connection refused"

    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_no_handshake_response(self, MockSession):
        """Empty JRMP handshake response → error, is_open=False."""
        sess = MagicMock()
        sess.recv.return_value = b""  # nothing received
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("10.0.0.1", 4444)

        assert result.is_open is False
        assert result.error is not None

    @patch("javapwner.protocols.jboss.jnp.parse_registry_return")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_empty_bound_names_on_4444(self, MockSession, mock_ack, mock_list):
        """Empty bound names on port 4444 → is_jnp=True (JRMP confirmed on JNP port)."""
        mock_ack.return_value = None
        mock_list.return_value = {"names": []}
        sess = _make_mock_session()
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("10.0.0.1", 4444)

        assert result.is_jrmp is True
        assert result.is_jnp is True


# ---------------------------------------------------------------------------
# JnpExploiter.exploit
# ---------------------------------------------------------------------------

class TestJnpExploiter:
    def test_init_timeout(self):
        e = JnpExploiter(timeout=3.0)
        assert e.timeout == 3.0

    @patch("javapwner.protocols.jboss.jnp.detect_exception_in_stream")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_successful_exploit(self, MockSession, mock_ack, mock_detect):
        """Payload sent, JRMP RETURN_VALUE response → likely_success=True."""
        mock_ack.return_value = None
        mock_detect.return_value = False
        # MSG_RETURN (0x51) + RETURN_VALUE (0x01) = proper JRMP success response
        sess = _make_mock_session(recv_all_data=b"\x51\x01\x00")
        _setup_mock_session(MockSession, sess)

        result = JnpExploiter(timeout=2.0).exploit(
            "10.0.0.1", 4444, b"\xac\xed\x00\x05test_payload"
        )

        assert result.sent is True
        assert result.likely_success is True

    @patch("javapwner.protocols.jboss.jnp.detect_exception_in_stream")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_exception_in_response(self, MockSession, mock_ack, mock_detect):
        """Exception in server response → likely_success=False."""
        mock_ack.return_value = None
        mock_detect.return_value = True
        sess = _make_mock_session(recv_all_data=b"exception_data")
        _setup_mock_session(MockSession, sess)

        result = JnpExploiter(timeout=2.0).exploit(
            "10.0.0.1", 4444, b"\xac\xed\x00\x05test"
        )

        assert result.sent is True
        assert result.likely_success is False

    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_connection_error_before_send(self, MockSession):
        """Connection refused before JRMP handshake → error set, sent=False."""
        MockSession.return_value.__enter__ = MagicMock(
            side_effect=JPConnectionError("Connection refused")
        )
        MockSession.return_value.__exit__ = MagicMock(return_value=False)

        result = JnpExploiter(timeout=2.0).exploit("10.0.0.1", 4444, b"payload")

        assert result.sent is False
        assert result.error == "Connection refused"

    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_no_handshake_response(self, MockSession):
        """Empty handshake response → error, sent=False."""
        sess = MagicMock()
        sess.recv.return_value = b""
        _setup_mock_session(MockSession, sess)

        result = JnpExploiter(timeout=2.0).exploit("10.0.0.1", 4444, b"payload")

        assert result.sent is False
        assert result.error is not None

    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_ack_parse_failure(self, MockSession, mock_ack):
        """JRMP ack parse failure → error set."""
        mock_ack.side_effect = ValueError("bad ack")
        sess = _make_mock_session()
        _setup_mock_session(MockSession, sess)

        result = JnpExploiter(timeout=2.0).exploit("10.0.0.1", 4444, b"payload")

        assert result.sent is False
        assert result.error is not None

    @patch("javapwner.protocols.jboss.jnp.detect_exception_in_stream")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_blind_execution_on_recv_exception(self, MockSession, mock_ack, mock_detect):
        """If recv_all raises, assume blind execution → likely_success=True."""
        mock_ack.return_value = None
        sess = _make_mock_session()
        sess.recv_all.side_effect = Exception("recv failed")
        _setup_mock_session(MockSession, sess)

        result = JnpExploiter(timeout=2.0).exploit(
            "10.0.0.1", 4444, b"\xac\xed\x00\x05payload"
        )

        assert result.sent is True
        assert result.likely_success is True


# ---------------------------------------------------------------------------
# _extract_jrmp_port helper
# ---------------------------------------------------------------------------

class TestExtractJrmpPort:
    def test_extracts_port_from_bootstrap(self):
        bootstrap = _make_jnp_bootstrap("127.0.0.1", 4447)
        assert _extract_jrmp_port(bootstrap) == 4447

    def test_returns_none_when_marker_absent(self):
        assert _extract_jrmp_port(b"\xac\xed\x00\x05no_unicast_here") is None

    def test_returns_none_for_zero_port(self):
        bootstrap = _make_jnp_bootstrap("127.0.0.1", 0)
        assert _extract_jrmp_port(bootstrap) is None

    def test_different_host_still_extracts_port(self):
        bootstrap = _make_jnp_bootstrap("192.168.1.100", 1098)
        assert _extract_jrmp_port(bootstrap) == 1098


# ---------------------------------------------------------------------------
# _build_dgc_dirty_call helper
# ---------------------------------------------------------------------------

class TestBuildDgcDirtyCall:
    def test_starts_with_msg_call(self):
        from javapwner.protocols.rmi.protocol import MSG_CALL
        call = _build_dgc_dirty_call(b"\xac\xed\x00\x05payload")
        assert call[0] == MSG_CALL

    def test_oos_header_present(self):
        call = _build_dgc_dirty_call(b"\xac\xed\x00\x05payload")
        assert call[1:5] == b"\xac\xed\x00\x05"

    def test_tc_blockdata_length_34(self):
        call = _build_dgc_dirty_call(b"\xac\xed\x00\x05payload")
        # byte[5]=0x77 (TC_BLOCKDATA), byte[6]=34
        assert call[5] == 0x77
        assert call[6] == 34

    def test_strips_oos_header_from_payload(self):
        call = _build_dgc_dirty_call(b"\xac\xed\x00\x05\xca\xfe")
        assert call.endswith(b"\xca\xfe")

    def test_raw_payload_not_stripped(self):
        payload = b"\x73\x00\x05raw"
        call = _build_dgc_dirty_call(payload)
        assert call.endswith(b"\x73\x00\x05raw")


# ---------------------------------------------------------------------------
# JnpScanner — JNP bootstrap path
# ---------------------------------------------------------------------------

class TestJnpScannerBootstrap:
    @patch("javapwner.protocols.jboss.jnp.parse_registry_return")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_bootstrap_detection_sets_is_jnp(self, MockSession, mock_ack, mock_list):
        """JNP bootstrap (ACED response) on port 4444 → is_jnp=True, is_jrmp=False."""
        mock_ack.return_value = None
        mock_list.return_value = {"names": ["java:/DefaultDS"]}
        bootstrap = _make_jnp_bootstrap("127.0.0.1", 4447)
        sess = MagicMock()
        # Phase 1: bootstrap bytes; Phase 2: JRMP ack
        sess.recv.side_effect = [
            bootstrap,
            b"\x4e\x00\x02\x00\x09localhost\x00\x00\x04\x4b",
        ]
        sess.recv_all.return_value = b"\x51\x00\x01"
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("127.0.0.1", 4444)

        assert result.is_open is True
        assert result.is_jnp is True
        assert result.is_jrmp is False

    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_bootstrap_no_unicast_ref_yields_error(self, MockSession):
        """Bootstrap bytes without UnicastRef2 → is_jnp=True but error set."""
        sess = MagicMock()
        sess.recv.return_value = b"\xac\xed\x00\x05no_unicast_ref_here"
        sess.recv_all.return_value = b""
        _setup_mock_session(MockSession, sess)

        result = JnpScanner(timeout=2.0).scan("127.0.0.1", 4444)

        assert result.is_open is True
        assert result.is_jnp is True
        assert result.error is not None


# ---------------------------------------------------------------------------
# JnpExploiter — JNP bootstrap path
# ---------------------------------------------------------------------------

class TestJnpExploiterBootstrap:
    @patch("javapwner.protocols.jboss.jnp.detect_exception_in_stream")
    @patch("javapwner.protocols.jboss.jnp.parse_jrmp_ack")
    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_exploit_via_bootstrap_redirects_to_jrmp_port(
        self, MockSession, mock_ack, mock_detect
    ):
        """Bootstrap detection → DGC delivered to embedded JRMP port → sent=True."""
        mock_ack.return_value = None
        mock_detect.return_value = False
        bootstrap = _make_jnp_bootstrap("127.0.0.1", 4447)
        sess = MagicMock()
        sess.recv.side_effect = [
            bootstrap,
            b"\x4e\x00\x02\x00\x09localhost\x00\x00\x04\x4b",
        ]
        sess.recv_all.return_value = b"\x51\x01\x00"
        _setup_mock_session(MockSession, sess)

        result = JnpExploiter(timeout=2.0).exploit(
            "127.0.0.1", 4444, b"\xac\xed\x00\x05payload"
        )

        assert result.sent is True

    @patch("javapwner.protocols.jboss.jnp.TCPSession")
    def test_exploit_bootstrap_no_unicast_ref_yields_error(self, MockSession):
        """Bootstrap without UnicastRef2 → sent=False, error set."""
        sess = MagicMock()
        sess.recv.return_value = b"\xac\xed\x00\x05no_unicast_ref"
        sess.recv_all.return_value = b""
        _setup_mock_session(MockSession, sess)

        result = JnpExploiter(timeout=2.0).exploit(
            "127.0.0.1", 4444, b"\xac\xed\x00\x05payload"
        )

        assert result.sent is False
        assert result.error is not None
