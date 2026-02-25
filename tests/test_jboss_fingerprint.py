"""Unit tests for javapwner.protocols.jboss.fingerprint (mocked HTTP + socket)."""
import socket
from unittest.mock import MagicMock, patch
from io import BytesIO

import pytest

from javapwner.protocols.jboss.fingerprint import (
    JBossFingerprint,
    JBossFingerprinter,
    JBossProtocol,
    _extract_version,
    _version_from_path,
    _REMOTING2_MAGIC,
)


class TestJBossFingerprint:
    def test_default_values(self):
        fp = JBossFingerprint()
        assert fp.protocol == JBossProtocol.UNKNOWN
        assert fp.is_jboss is False
        assert fp.invoker_paths == []

    def test_to_dict_keys(self):
        fp = JBossFingerprint()
        d = fp.to_dict()
        assert "protocol" in d
        assert "is_jboss" in d
        assert "invoker_paths" in d
        assert "remoting2_confirmed" in d

    def test_to_dict_protocol_value(self):
        fp = JBossFingerprint(protocol=JBossProtocol.HTTP_INVOKER)
        assert fp.to_dict()["protocol"] == "http_invoker"


class TestExtractVersion:
    def test_wildfly(self):
        v = _extract_version("wildfly 10.1.0")
        assert v and "WildFly" in v and "10" in v

    def test_jboss_as(self):
        v = _extract_version("jboss as 6.1.0")
        assert v and "AS" in v and "6" in v

    def test_jboss_eap(self):
        v = _extract_version("jboss eap 6.4")
        assert v and "EAP" in v

    def test_jboss_bare(self):
        v = _extract_version("jboss 4.2")
        assert v is not None

    def test_none_on_no_match(self):
        v = _extract_version("apache tomcat")
        assert v is None


class TestVersionFromPath:
    def test_jmx_invoker(self):
        v = _version_from_path("/invoker/JMXInvokerServlet")
        assert v and "4.x" in v

    def test_readonly(self):
        v = _version_from_path("/invoker/readonly")
        assert v and "6" in v

    def test_unknown_path(self):
        v = _version_from_path("/unknown/path")
        assert v is None


class TestFingerprinterHttpBanner:
    """Mock urllib to test HTTP banner parsing."""

    def _make_resp(self, body: bytes, headers: dict[str, str] | None = None):
        resp = MagicMock()
        resp.read.return_value = body
        resp.status = 200
        mock_headers = MagicMock()
        mock_headers.items.return_value = list((headers or {}).items())
        resp.headers = mock_headers
        return resp

    @patch("javapwner.protocols.jboss.fingerprint.urllib.request.urlopen")
    def test_jboss_in_server_header(self, mock_urlopen):
        resp = self._make_resp(b"<html></html>", {"Server": "JBoss/6.1.0", "X-Powered-By": ""})
        mock_urlopen.return_value.__enter__ = lambda s: resp
        mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = resp

        fp = JBossFingerprint()
        fingerprinter = JBossFingerprinter(timeout=2.0)
        fingerprinter._probe_http_banner("http://10.0.0.1:8080", fp)
        assert fp.is_jboss

    @patch("javapwner.protocols.jboss.fingerprint.urllib.request.urlopen")
    def test_wildfly_in_body(self, mock_urlopen):
        resp = self._make_resp(b"WildFly 10 Application Server", {"Server": "Apache", "X-Powered-By": ""})
        mock_urlopen.return_value = resp

        fp = JBossFingerprint()
        fingerprinter = JBossFingerprinter(timeout=2.0)
        fingerprinter._probe_http_banner("http://10.0.0.1:8080", fp)
        assert fp.is_jboss

    @patch("javapwner.protocols.jboss.fingerprint.urllib.request.urlopen")
    def test_tomcat_not_jboss(self, mock_urlopen):
        resp = self._make_resp(b"Apache Tomcat 9.0", {"Server": "Apache-Coyote/1.1", "X-Powered-By": ""})
        mock_urlopen.return_value = resp

        fp = JBossFingerprint()
        fingerprinter = JBossFingerprinter(timeout=2.0)
        fingerprinter._probe_http_banner("http://10.0.0.1:8080", fp)
        assert not fp.is_jboss

    @patch("javapwner.protocols.jboss.fingerprint.urllib.request.urlopen",
           side_effect=Exception("connection refused"))
    def test_http_error_graceful(self, mock_urlopen):
        fp = JBossFingerprint()
        fingerprinter = JBossFingerprinter(timeout=2.0)
        fingerprinter._probe_http_banner("http://10.0.0.1:8080", fp)
        assert not fp.is_jboss


class TestFingerprinterRemoting2:
    @patch("javapwner.protocols.jboss.fingerprint.socket.create_connection")
    def test_remoting2_magic_detected(self, mock_conn):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = _REMOTING2_MAGIC + b"\x00\x00\x00\x00"
        mock_conn.return_value.__enter__ = lambda s: mock_sock
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        fp = JBossFingerprint()
        fingerprinter = JBossFingerprinter(timeout=2.0)
        fingerprinter._probe_remoting2("10.0.0.1", 4446, fp)
        assert fp.remoting2_confirmed
        assert fp.is_jboss

    @patch("javapwner.protocols.jboss.fingerprint.socket.create_connection")
    def test_no_magic_not_remoting2(self, mock_conn):
        mock_sock = MagicMock()
        mock_sock.recv.return_value = b"\x48\x54\x54\x50"  # "HTTP"
        mock_conn.return_value.__enter__ = lambda s: mock_sock
        mock_conn.return_value.__exit__ = MagicMock(return_value=False)

        fp = JBossFingerprint()
        fingerprinter = JBossFingerprinter(timeout=2.0)
        fingerprinter._probe_remoting2("10.0.0.1", 4446, fp)
        assert not fp.remoting2_confirmed

    @patch("javapwner.protocols.jboss.fingerprint.socket.create_connection",
           side_effect=OSError("refused"))
    def test_connection_refused_graceful(self, mock_conn):
        fp = JBossFingerprint()
        fingerprinter = JBossFingerprinter(timeout=2.0)
        fingerprinter._probe_remoting2("10.0.0.1", 4446, fp)
        assert not fp.remoting2_confirmed


class TestJBossProtocolEnum:
    def test_str_values(self):
        assert JBossProtocol.UNKNOWN.value == "unknown"
        assert JBossProtocol.HTTP_INVOKER.value == "http_invoker"
        assert JBossProtocol.REMOTING2.value == "jboss_remoting2"
