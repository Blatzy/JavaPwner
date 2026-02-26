"""Unit tests for JBoss Remoting 3 fingerprinter."""

from __future__ import annotations

from unittest.mock import MagicMock, patch, call
import socket

import pytest

from javapwner.protocols.jboss.remoting3 import (
    JBossRemoting3Fingerprinter,
    Remoting3Fingerprint,
)


# ---------------------------------------------------------------------------
# Remoting3Fingerprint
# ---------------------------------------------------------------------------

class TestRemoting3Fingerprint:
    def test_defaults(self):
        fp = Remoting3Fingerprint()
        assert fp.is_remoting3 is False
        assert fp.server_name is None
        assert fp.channel_type is None
        assert fp.error is None

    def test_to_dict(self):
        fp = Remoting3Fingerprint(
            is_remoting3=True,
            server_name="WildFly Full 26.1.3",
            channel_type="jboss-remoting",
        )
        d = fp.to_dict()
        assert d["is_remoting3"] is True
        assert d["server_name"] == "WildFly Full 26.1.3"
        assert d["channel_type"] == "jboss-remoting"


# ---------------------------------------------------------------------------
# JBossRemoting3Fingerprinter
# ---------------------------------------------------------------------------

class TestJBossRemoting3Fingerprinter:
    def _mock_sock(self, recv_data):
        """Create a mock socket that returns recv_data on first recv, then raises timeout."""
        mock = MagicMock()
        if isinstance(recv_data, list):
            mock.recv.side_effect = recv_data
        else:
            mock.recv.return_value = recv_data
        mock.__enter__ = MagicMock(return_value=mock)
        mock.__exit__ = MagicMock(return_value=False)
        return mock

    def test_remoting3_greeting_detected(self):
        """Greeting frame type=0x00 should be detected as Remoting 3."""
        fingerprinter = JBossRemoting3Fingerprinter(timeout=2.0)

        # Frame type 0x00 + 3 bytes length + capability data
        # Cap 0x00 (server name) + len 5 + "WFull"
        cap_data = b"\x00\x05WFull\x01\x03ejb"
        response = b"\x00" + len(cap_data).to_bytes(3, "big") + cap_data

        mock_sock = self._mock_sock(response)

        with patch("socket.create_connection", return_value=mock_sock):
            result = fingerprinter.fingerprint("10.0.0.1", 4447)

        assert result.is_remoting3 is True
        assert result.server_name == "WFull"
        assert result.channel_type == "ejb"

    def test_empty_response(self):
        """Empty response should report error."""
        fingerprinter = JBossRemoting3Fingerprinter(timeout=2.0)

        mock_sock = self._mock_sock(b"")

        with patch("socket.create_connection", return_value=mock_sock):
            result = fingerprinter.fingerprint("10.0.0.1", 4447)

        assert result.is_remoting3 is False
        assert result.error == "Empty response"

    def test_timeout_response(self):
        """Socket timeout should report error."""
        fingerprinter = JBossRemoting3Fingerprinter(timeout=2.0)

        mock_sock = self._mock_sock(b"")
        mock_sock.recv.side_effect = socket.timeout("timed out")

        with patch("socket.create_connection", return_value=mock_sock):
            result = fingerprinter.fingerprint("10.0.0.1", 4447)

        assert result.is_remoting3 is False
        assert "timeout" in result.error.lower()

    def test_http_response_triggers_upgrade(self):
        """HTTP response should trigger HTTP Upgrade attempt."""
        fingerprinter = JBossRemoting3Fingerprinter(timeout=2.0)

        # First connection: HTTP response (starts with "GET " → 0x47 0x45 0x54 0x20)
        http_response = b"\x47\x45\x54\x20some http stuff"

        # Second connection (upgrade attempt): 101 Switching Protocols
        upgrade_response = b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: jboss-remoting\r\n\r\n"

        mock_sock1 = self._mock_sock(http_response)
        mock_sock2 = self._mock_sock(upgrade_response)

        with patch(
            "socket.create_connection",
            side_effect=[mock_sock1, mock_sock2],
        ):
            result = fingerprinter.fingerprint("10.0.0.1", 8080)

        assert result.is_remoting3 is True
        assert result.channel_type == "http-upgrade"

    def test_connection_refused(self):
        """OS error should set error."""
        fingerprinter = JBossRemoting3Fingerprinter(timeout=2.0)

        with patch(
            "socket.create_connection",
            side_effect=OSError("Connection refused"),
        ):
            result = fingerprinter.fingerprint("10.0.0.1", 4447)

        assert result.is_remoting3 is False
        assert result.error == "Connection refused"

    def test_non_remoting3_no_http_upgrade(self):
        """Non-Remoting3, non-HTTP response → not detected."""
        fingerprinter = JBossRemoting3Fingerprinter(timeout=2.0)

        # Frame type != 0x00 and not HTTP
        response = b"\x05\x00\x00\x10" + b"\x00" * 16

        # Upgrade attempt also fails (connection refused)
        mock_sock = self._mock_sock(response)
        mock_sock_upgrade = MagicMock()
        mock_sock_upgrade.__enter__ = MagicMock(return_value=mock_sock_upgrade)
        mock_sock_upgrade.__exit__ = MagicMock(return_value=False)
        mock_sock_upgrade.recv.side_effect = socket.timeout("timeout")

        with patch(
            "socket.create_connection",
            side_effect=[mock_sock, mock_sock_upgrade],
        ):
            result = fingerprinter.fingerprint("10.0.0.1", 4447)

        assert result.is_remoting3 is False

    def test_parse_greeting_truncated_data(self):
        """Truncated capability data should not crash."""
        fingerprinter = JBossRemoting3Fingerprinter(timeout=2.0)
        fp = Remoting3Fingerprint()

        # cap_type=0x00, cap_len=100, but only 3 bytes of actual data
        data = b"\x00\x64abc"
        fingerprinter._parse_greeting(data, fp)

        # Should not crash, and no server_name extracted (truncated)
        assert fp.server_name is None
