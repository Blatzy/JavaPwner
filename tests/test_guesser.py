"""Unit tests for javapwner.protocols.rmi.guesser (mocked network)."""

from __future__ import annotations

import struct
from unittest.mock import MagicMock, patch, PropertyMock

import pytest

from javapwner.protocols.rmi.guesser import (
    RmiMethodGuesser,
    MethodGuessResult,
    load_default_wordlist,
    _BUILTIN_WORDLIST,
)
from javapwner.protocols.rmi.protocol import PROTOCOL_ACK, MSG_RETURN


# ---------------------------------------------------------------------------
# Helpers
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


# ---------------------------------------------------------------------------
# MethodGuessResult
# ---------------------------------------------------------------------------

class TestMethodGuessResult:
    def test_to_dict(self):
        r = MethodGuessResult(
            bound_name="myService",
            class_name="com.example.MyService",
            confirmed_methods=["lookup", "list"],
            rejected_methods=["bind"],
        )
        d = r.to_dict()
        assert d["bound_name"] == "myService"
        assert d["class_name"] == "com.example.MyService"
        assert "lookup" in d["confirmed_methods"]
        assert "bind" in d["rejected_methods"]

    def test_default_empty(self):
        r = MethodGuessResult(bound_name="x")
        assert r.confirmed_methods == []
        assert r.rejected_methods == []
        assert r.class_name is None
        assert r.error is None


# ---------------------------------------------------------------------------
# Wordlist loader
# ---------------------------------------------------------------------------

class TestLoadWordlist:
    def test_builtin_has_standard_methods(self):
        assert "lookup" in _BUILTIN_WORDLIST
        assert "list" in _BUILTIN_WORDLIST
        assert "bind" in _BUILTIN_WORDLIST

    def test_load_default_returns_dict(self):
        wl = load_default_wordlist()
        assert isinstance(wl, dict)
        assert len(wl) > 0
        # All values should be ints
        for v in wl.values():
            assert isinstance(v, int)


# ---------------------------------------------------------------------------
# RmiMethodGuesser
# ---------------------------------------------------------------------------

class TestRmiMethodGuesser:
    def test_init_default_timeout(self):
        g = RmiMethodGuesser()
        assert g.timeout == 5.0

    def test_init_custom_timeout(self):
        g = RmiMethodGuesser(timeout=10.0)
        assert g.timeout == 10.0

    @patch("javapwner.protocols.rmi.guesser.TCPSession")
    def test_probe_method_unmarshal_exception_returns_true(self, MockSession):
        """When server responds with UnmarshalException, method exists."""
        mock_sess = MagicMock()
        MockSession.return_value.__enter__ = MagicMock(return_value=mock_sess)
        MockSession.return_value.__exit__ = MagicMock(return_value=False)

        mock_sess.recv.return_value = _make_ack()
        mock_sess.recv_all.return_value = b"\x51\x02" + b"UnmarshalException" + b"\x00" * 10

        g = RmiMethodGuesser(timeout=2.0)
        result = g._probe_method("127.0.0.1", 1099, b"\x00" * 20, -7538657168040752697)
        assert result is True

    @patch("javapwner.protocols.rmi.guesser.TCPSession")
    def test_probe_method_no_response_returns_false(self, MockSession):
        """When server sends no response, method likely doesn't exist."""
        mock_sess = MagicMock()
        MockSession.return_value.__enter__ = MagicMock(return_value=mock_sess)
        MockSession.return_value.__exit__ = MagicMock(return_value=False)

        mock_sess.recv.return_value = _make_ack()
        mock_sess.recv_all.return_value = b""

        g = RmiMethodGuesser(timeout=2.0)
        result = g._probe_method("127.0.0.1", 1099, b"\x00" * 20, 12345)
        assert result is False

    @patch("javapwner.protocols.rmi.guesser.TCPSession")
    def test_probe_method_connection_error(self, MockSession):
        """When connection fails, return False."""
        from javapwner.exceptions import ConnectionError as JPConnectionError

        MockSession.return_value.__enter__ = MagicMock(
            side_effect=JPConnectionError("refused")
        )
        MockSession.return_value.__exit__ = MagicMock(return_value=False)

        g = RmiMethodGuesser(timeout=2.0)
        result = g._probe_method("127.0.0.1", 1099, b"\x00" * 20, 12345)
        assert result is False

    def test_guess_with_custom_wordlist(self):
        """Test guess() with explicit wordlist, mocking network."""
        g = RmiMethodGuesser(timeout=1.0)
        # Mock _probe_method and _lookup_stub
        g._probe_method = MagicMock(side_effect=[True, False, None])
        g._lookup_stub = MagicMock(return_value=("com.Test", None))

        wordlist = {"method1": 111, "method2": 222, "method3": 333}
        result = g.guess("127.0.0.1", 1099, "myObj", wordlist=wordlist)

        assert result.bound_name == "myObj"
        assert result.class_name == "com.Test"
        assert result.confirmed_methods == ["method1"]
        assert result.rejected_methods == ["method2"]
