"""Unit tests for JBoss Remoting 2 exploiter."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch

import pytest

from javapwner.protocols.jboss.remoting import (
    JBossRemoting2Exploiter,
    Remoting2ExploitResult,
    _REMOTING2_MAGIC,
    _REMOTING2_VERSION,
    _REQUEST_HEADER,
)


# ---------------------------------------------------------------------------
# Remoting2ExploitResult
# ---------------------------------------------------------------------------

class TestRemoting2ExploitResult:
    def test_defaults(self):
        r = Remoting2ExploitResult()
        assert r.sent is False
        assert r.likely_success is False
        assert r.greeting_received is False
        assert r.error is None
        assert r.response_bytes == b""

    def test_to_dict(self):
        r = Remoting2ExploitResult(sent=True, likely_success=True, greeting_received=True)
        d = r.to_dict()
        assert d["sent"] is True
        assert d["likely_success"] is True
        assert d["greeting_received"] is True
        assert "response_bytes" not in d  # repr=False shouldn't appear in dict


# ---------------------------------------------------------------------------
# JBossRemoting2Exploiter
# ---------------------------------------------------------------------------

class TestJBossRemoting2Exploiter:
    def test_not_remoting2_endpoint(self):
        """Non-Remoting2 greeting should fail gracefully."""
        exploiter = JBossRemoting2Exploiter(timeout=2.0)

        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x00\x00\x00\x00"  # not remoting2 magic
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            result = exploiter.exploit("10.0.0.1", 4446, b"\xde\xad")
        assert result.greeting_received is False
        assert result.error == "Not a JBoss Remoting 2 endpoint"

    def test_successful_exploit(self):
        """Valid greeting + no exception = likely success."""
        exploiter = JBossRemoting2Exploiter(timeout=2.0)

        greeting = _REMOTING2_MAGIC + b"\x00" * 10
        response = b"\x00\x01\x02\x03"

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [greeting, response]
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            with patch(
                "javapwner.protocols.jboss.remoting.detect_exception_in_stream",
                return_value=False,
            ):
                result = exploiter.exploit("10.0.0.1", 4446, b"\xde\xad")

        assert result.greeting_received is True
        assert result.sent is True
        assert result.likely_success is True

    def test_exception_in_response(self):
        """Exception detected in response should mark likely_success=False."""
        exploiter = JBossRemoting2Exploiter(timeout=2.0)

        greeting = _REMOTING2_MAGIC + b"\x00" * 10
        response = b"\xac\xed\x00\x05..." + b"java.lang.Exception" + b"..."

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [greeting, response]
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            with patch(
                "javapwner.protocols.jboss.remoting.detect_exception_in_stream",
                return_value=True,
            ):
                result = exploiter.exploit("10.0.0.1", 4446, b"\xde\xad")

        assert result.greeting_received is True
        assert result.sent is True
        assert result.likely_success is False

    def test_timeout_after_send_likely_success(self):
        """Socket timeout after sending (blind exec) = likely success."""
        import socket

        exploiter = JBossRemoting2Exploiter(timeout=2.0)

        greeting = _REMOTING2_MAGIC + b"\x00" * 10

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [greeting, socket.timeout("timed out")]
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            result = exploiter.exploit("10.0.0.1", 4446, b"\xde\xad")

        assert result.sent is True
        assert result.likely_success is True

    def test_connection_error_before_send(self):
        """OS error before sending should report error."""
        exploiter = JBossRemoting2Exploiter(timeout=2.0)

        with patch("socket.create_connection", side_effect=OSError("Connection refused")):
            result = exploiter.exploit("10.0.0.1", 4446, b"\xde\xad")

        assert result.sent is False
        assert result.error == "Connection refused"

    def test_frame_format(self):
        """Verify the frame sent has length-prefixed payload."""
        exploiter = JBossRemoting2Exploiter(timeout=2.0)

        greeting = _REMOTING2_MAGIC + b"\x00" * 10
        payload = b"\xac\xed\x00\x05test_payload"

        mock_sock = MagicMock()
        mock_sock.recv.side_effect = [greeting, b"\x00"]
        mock_sock.__enter__ = MagicMock(return_value=mock_sock)
        mock_sock.__exit__ = MagicMock(return_value=False)

        with patch("socket.create_connection", return_value=mock_sock):
            with patch(
                "javapwner.protocols.jboss.remoting.detect_exception_in_stream",
                return_value=False,
            ):
                exploiter.exploit("10.0.0.1", 4446, payload)

        # Second sendall call should be the frame
        calls = mock_sock.sendall.call_args_list
        assert len(calls) == 2

        # First call: client hello
        hello = calls[0][0][0]
        assert hello[:4] == _REMOTING2_MAGIC

        # Second call: frame = len(body) + REQUEST_HEADER + payload
        frame = calls[1][0][0]
        expected_body = _REQUEST_HEADER + payload
        expected_frame = struct.pack(">I", len(expected_body)) + expected_body
        assert frame == expected_frame
