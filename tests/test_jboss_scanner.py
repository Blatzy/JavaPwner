"""Unit tests for javapwner.protocols.jboss.scanner and invoker (mocked)."""
from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from javapwner.protocols.jboss.scanner import JBossScanner, JBossScanResult
from javapwner.protocols.jboss.invoker import HttpInvoker, InvokerExploitResult
from javapwner.protocols.jboss.fingerprint import JBossFingerprint, JBossProtocol


# ---------------------------------------------------------------------------
# JBossScanResult
# ---------------------------------------------------------------------------

class TestJBossScanResult:
    def test_to_dict_keys(self):
        r = JBossScanResult(host="10.0.0.1", port=8080)
        d = r.to_dict()
        assert "host" in d
        assert "port" in d
        assert "is_open" in d
        assert "invoker_endpoints" in d
        assert "fingerprint" in d

    def test_to_dict_with_fingerprint(self):
        fp = JBossFingerprint(is_jboss=True, version="JBoss 6.x")
        r = JBossScanResult(host="h", port=8080, fingerprint=fp)
        d = r.to_dict()
        assert d["fingerprint"]["is_jboss"] is True

    def test_to_dict_no_fingerprint(self):
        r = JBossScanResult(host="h", port=8080)
        d = r.to_dict()
        assert d["fingerprint"] is None


# ---------------------------------------------------------------------------
# InvokerExploitResult
# ---------------------------------------------------------------------------

class TestInvokerExploitResult:
    def test_default_values(self):
        r = InvokerExploitResult()
        assert not r.sent
        assert not r.likely_success
        assert r.http_status is None

    def test_to_dict(self):
        r = InvokerExploitResult(sent=True, http_status=500, likely_success=True)
        d = r.to_dict()
        assert d["sent"] is True
        assert d["http_status"] == 500


# ---------------------------------------------------------------------------
# HttpInvoker.probe_endpoints (mocked)
# ---------------------------------------------------------------------------

class TestHttpInvokerProbeEndpoints:
    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen")
    def test_all_200(self, mock_urlopen):
        resp = MagicMock()
        resp.status = 200
        mock_urlopen.return_value = resp
        invoker = HttpInvoker(timeout=2.0)
        found = invoker.probe_endpoints("10.0.0.1", 8080)
        assert len(found) > 0

    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen",
           side_effect=urllib.error.HTTPError(None, 500, "Server Error", {}, None))
    def test_http500_included(self, mock_urlopen):
        invoker = HttpInvoker(timeout=2.0)
        found = invoker.probe_endpoints("10.0.0.1", 8080)
        assert len(found) > 0

    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen",
           side_effect=urllib.error.HTTPError(None, 404, "Not Found", {}, None))
    def test_http404_excluded(self, mock_urlopen):
        invoker = HttpInvoker(timeout=2.0)
        found = invoker.probe_endpoints("10.0.0.1", 8080)
        assert found == []

    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen",
           side_effect=urllib.error.URLError("refused"))
    def test_refused_excluded(self, mock_urlopen):
        invoker = HttpInvoker(timeout=2.0)
        found = invoker.probe_endpoints("10.0.0.1", 8080)
        assert found == []


# ---------------------------------------------------------------------------
# HttpInvoker.exploit (mocked)
# ---------------------------------------------------------------------------

class TestHttpInvokerExploit:
    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen")
    def test_http200_likely_success(self, mock_urlopen):
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b"OK"
        mock_urlopen.return_value = resp
        invoker = HttpInvoker(timeout=2.0)
        result = invoker.exploit("10.0.0.1", 8080, b"\xac\xed\x00\x05test")
        assert result.sent
        assert result.likely_success

    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen",
           side_effect=urllib.error.HTTPError(None, 500, "Internal Server Error", {}, None))
    def test_http500_likely_success(self, mock_urlopen):
        invoker = HttpInvoker(timeout=2.0)
        result = invoker.exploit("10.0.0.1", 8080, b"\xac\xed\x00\x05test")
        assert result.sent
        assert result.likely_success
        assert result.http_status == 500

    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen",
           side_effect=urllib.error.URLError("refused"))
    def test_refused_on_all_paths(self, mock_urlopen):
        invoker = HttpInvoker(timeout=2.0)
        result = invoker.exploit("10.0.0.1", 8080, b"\xac\xed\x00\x05test")
        assert not result.sent
        assert result.error is not None

    @patch("javapwner.protocols.jboss.invoker.urllib.request.urlopen")
    def test_specific_path_used(self, mock_urlopen):
        resp = MagicMock()
        resp.status = 200
        resp.read.return_value = b""
        mock_urlopen.return_value = resp
        invoker = HttpInvoker(timeout=2.0)
        result = invoker.exploit(
            "10.0.0.1", 8080, b"\xac\xed",
            path="/invoker/readonly",
        )
        assert result.sent
        assert "/invoker/readonly" in result.endpoint


# ---------------------------------------------------------------------------
# JBossScanner (mocked fingerprinter + invoker)
# ---------------------------------------------------------------------------

class TestJBossScannerMocked:
    @patch.object(HttpInvoker, "probe_endpoints", return_value=["/invoker/JMXInvokerServlet"])
    @patch.object(JBossFingerprinter := __import__(
        "javapwner.protocols.jboss.fingerprint", fromlist=["JBossFingerprinter"]
    ).JBossFingerprinter, "fingerprint",
                  return_value=JBossFingerprint(
                      is_jboss=True, version="JBoss 6.x",
                      protocol=JBossProtocol.HTTP_INVOKER,
                  ))
    def test_is_open_when_jboss(self, mock_fp, mock_inv):
        scanner = JBossScanner(timeout=2.0)
        result = scanner.scan("10.0.0.1", 8080)
        assert result.is_open
        assert result.fingerprint.is_jboss

    @patch.object(HttpInvoker, "probe_endpoints", return_value=[])
    @patch(
        "javapwner.protocols.jboss.scanner.JBossFingerprinter.fingerprint",
        return_value=JBossFingerprint(is_jboss=False),
    )
    @patch("javapwner.protocols.jboss.scanner.socket.create_connection",
           side_effect=OSError("refused"))
    def test_closed_port(self, mock_sock, mock_fp, mock_inv):
        scanner = JBossScanner(timeout=2.0)
        result = scanner.scan("10.0.0.1", 9999)
        assert not result.is_open

    @patch.object(HttpInvoker, "probe_endpoints",
                  return_value=["/invoker/JMXInvokerServlet", "/invoker/readonly"])
    @patch(
        "javapwner.protocols.jboss.scanner.JBossFingerprinter.fingerprint",
        return_value=JBossFingerprint(
            is_jboss=True,
            invoker_paths=["/invoker/JMXInvokerServlet"],
            protocol=JBossProtocol.HTTP_INVOKER,
        ),
    )
    def test_cves_populated(self, mock_fp, mock_inv):
        scanner = JBossScanner(timeout=2.0)
        result = scanner.scan("10.0.0.1", 8080)
        assert "CVE-2015-7501" in result.invoker_cves
        assert "CVE-2017-12149" in result.invoker_cves
