"""Unit tests for javapwner.protocols.jini.probe."""

from __future__ import annotations

import struct
import urllib.error
from unittest.mock import MagicMock, patch

import pytest

from javapwner.protocols.jini.probe import (
    CodebaseProbeResult,
    EndpointProbeResult,
    JiniProbe,
)
from javapwner.protocols.jini.scanner import ScanResult

_MAGIC = b"\xac\xed\x00\x05"
TC_STRING = 0x74


def _make_tc_string(s: str) -> bytes:
    enc = s.encode("utf-8")
    return bytes([TC_STRING]) + struct.pack(">H", len(enc)) + enc


def _make_scan_result(raw: bytes) -> ScanResult:
    return ScanResult(host="127.0.0.1", port=4160, raw_proxy_bytes=raw)


# ---------------------------------------------------------------------------
# CodebaseProbeResult
# ---------------------------------------------------------------------------

class TestCodebaseProbeResultToDict:
    def test_keys_present(self):
        r = CodebaseProbeResult(
            urls=["http://example.com"],
            reachable={"http://example.com": True},
            content_hints={"http://example.com": "<!doctype html>"},
        )
        d = r.to_dict()
        assert "urls" in d
        assert "reachable" in d
        assert "content_hints" in d

    def test_defaults_empty(self):
        r = CodebaseProbeResult()
        d = r.to_dict()
        assert d["urls"] == []
        assert d["reachable"] == {}
        assert d["content_hints"] == {}


# ---------------------------------------------------------------------------
# EndpointProbeResult
# ---------------------------------------------------------------------------

class TestEndpointProbeResultToDict:
    def test_keys_present(self):
        r = EndpointProbeResult(
            candidates=[{"host": "10.0.0.1", "port": 1099}],
            confirmed={"host": "10.0.0.1", "port": 1099},
        )
        d = r.to_dict()
        assert "candidates" in d
        assert "confirmed" in d

    def test_confirmed_none_by_default(self):
        r = EndpointProbeResult()
        assert r.to_dict()["confirmed"] is None


# ---------------------------------------------------------------------------
# JiniProbe.probe_codebase
# ---------------------------------------------------------------------------

class TestProbeCodebase:
    def test_http_reachable(self):
        raw = b"http://example.com/codebase"
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_response = MagicMock()
        mock_response.read.return_value = b"<html>Hello</html>"

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)

        assert "http://example.com/codebase" in result.urls
        assert result.reachable.get("http://example.com/codebase") is True

    def test_http_content_hint_captured(self):
        raw = b"http://example.com/classes"
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_response = MagicMock()
        mock_response.read.return_value = b"package com.example;"

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)

        assert "http://example.com/classes" in result.content_hints

    def test_http_unreachable(self):
        raw = b"http://unreachable.example.com/"
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("timeout")):
            result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)

        assert result.reachable.get("http://unreachable.example.com/") is False

    def test_file_url_not_probed(self):
        raw = b"file:///tmp/classes"
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        with patch("urllib.request.urlopen") as mock_urlopen:
            result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)
            mock_urlopen.assert_not_called()

        assert result.reachable.get("file:///tmp/classes") is False

    def test_jrmi_url_not_probed(self):
        raw = b"jrmi://host:1234/service"
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        with patch("urllib.request.urlopen") as mock_urlopen:
            result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)
            mock_urlopen.assert_not_called()

        assert result.reachable.get("jrmi://host:1234/service") is False

    def test_rmi_url_not_probed(self):
        raw = b"rmi://host:1099/obj"
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        with patch("urllib.request.urlopen") as mock_urlopen:
            result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)
            mock_urlopen.assert_not_called()

        assert result.reachable.get("rmi://host:1099/obj") is False

    def test_empty_raw_returns_empty_result(self):
        sr = _make_scan_result(b"")
        probe = JiniProbe()
        result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)
        assert result.urls == []
        assert result.reachable == {}

    def test_deduplication_across_nested(self):
        url = b"http://example.com/shared"
        # Same URL appears in main stream and a nested stream
        raw = url + b"\x00" + _MAGIC + url + b"\x00"
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_response = MagicMock()
        mock_response.read.return_value = b""

        with patch("urllib.request.urlopen", return_value=mock_response):
            result = probe.probe_codebase("127.0.0.1", 4160, scan_result=sr)

        assert result.urls.count("http://example.com/shared") == 1


# ---------------------------------------------------------------------------
# JiniProbe.probe_endpoint
# ---------------------------------------------------------------------------

class TestProbeEndpoint:
    def _raw_with_endpoint(self, host: str, port: int) -> bytes:
        return _MAGIC + _make_tc_string(host) + struct.pack(">I", port)

    def test_confirmed_on_ack(self):
        raw = self._raw_with_endpoint("10.0.0.1", 1099)
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.recv.return_value = b"\x4e"

        with patch("javapwner.protocols.jini.probe.TCPSession", return_value=mock_sess):
            result = probe.probe_endpoint("127.0.0.1", 4160, scan_result=sr)

        assert result.confirmed is not None
        assert result.confirmed["host"] == "10.0.0.1"
        assert result.confirmed["port"] == 1099

    def test_no_ack_byte(self):
        raw = self._raw_with_endpoint("10.0.0.1", 1099)
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.recv.return_value = b"\x00"

        with patch("javapwner.protocols.jini.probe.TCPSession", return_value=mock_sess):
            result = probe.probe_endpoint("127.0.0.1", 4160, scan_result=sr)

        assert result.confirmed is None

    def test_empty_response(self):
        raw = self._raw_with_endpoint("10.0.0.1", 1099)
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.recv.return_value = b""

        with patch("javapwner.protocols.jini.probe.TCPSession", return_value=mock_sess):
            result = probe.probe_endpoint("127.0.0.1", 4160, scan_result=sr)

        assert result.confirmed is None

    def test_connection_error_skipped(self):
        from javapwner.exceptions import ConnectionError as JPConnectionError

        raw = self._raw_with_endpoint("10.0.0.1", 1099)
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        with patch(
            "javapwner.protocols.jini.probe.TCPSession",
            side_effect=JPConnectionError("refused"),
        ):
            result = probe.probe_endpoint("127.0.0.1", 4160, scan_result=sr)

        assert result.confirmed is None

    def test_candidates_populated(self):
        raw = self._raw_with_endpoint("10.0.0.1", 1099)
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.recv.return_value = b"\x00"

        with patch("javapwner.protocols.jini.probe.TCPSession", return_value=mock_sess):
            result = probe.probe_endpoint("127.0.0.1", 4160, scan_result=sr)

        assert len(result.candidates) >= 1

    def test_empty_raw(self):
        sr = _make_scan_result(b"")
        probe = JiniProbe()
        result = probe.probe_endpoint("127.0.0.1", 4160, scan_result=sr)
        assert result.candidates == []
        assert result.confirmed is None

    def test_first_confirmed_wins(self):
        """When two candidates respond, only the first is confirmed."""
        host1, port1 = "10.0.0.1", 1099
        host2, port2 = "10.0.0.2", 1100
        raw = (
            _MAGIC
            + _make_tc_string(host1) + struct.pack(">I", port1)
            + _make_tc_string(host2) + struct.pack(">I", port2)
        )
        sr = _make_scan_result(raw)
        probe = JiniProbe()

        mock_sess = MagicMock()
        mock_sess.__enter__ = MagicMock(return_value=mock_sess)
        mock_sess.__exit__ = MagicMock(return_value=False)
        mock_sess.recv.return_value = b"\x4e"

        with patch("javapwner.protocols.jini.probe.TCPSession", return_value=mock_sess):
            result = probe.probe_endpoint("127.0.0.1", 4160, scan_result=sr)

        assert result.confirmed["host"] == host1
        assert result.confirmed["port"] == port1
