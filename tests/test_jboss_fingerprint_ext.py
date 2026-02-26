"""Unit tests for JBoss fingerprint extensions — HTTPS, edition, auth detection."""

from __future__ import annotations

from unittest.mock import MagicMock, patch
import urllib.error

import pytest

from javapwner.protocols.jboss.fingerprint import (
    JBossFingerprinter,
    JBossFingerprint,
    JBossProtocol,
    InvokerPathProbe,
    _extract_version,
    _extract_edition,
    _version_from_path,
)


# ---------------------------------------------------------------------------
# InvokerPathProbe
# ---------------------------------------------------------------------------

class TestInvokerPathProbe:
    def test_to_dict(self):
        p = InvokerPathProbe(
            path="/invoker/JMXInvokerServlet",
            reachable=True,
            http_status=500,
            requires_auth=False,
            cve="CVE-2015-7501",
        )
        d = p.to_dict()
        assert d["path"] == "/invoker/JMXInvokerServlet"
        assert d["reachable"] is True
        assert d["cve"] == "CVE-2015-7501"

    def test_auth_required(self):
        p = InvokerPathProbe(path="/invoker/readonly", requires_auth=True)
        assert p.requires_auth is True


# ---------------------------------------------------------------------------
# JBossFingerprint extended fields
# ---------------------------------------------------------------------------

class TestJBossFingerprintExtended:
    def test_edition_field(self):
        fp = JBossFingerprint(edition="EAP")
        d = fp.to_dict()
        assert d["edition"] == "EAP"

    def test_scheme_field(self):
        fp = JBossFingerprint(scheme="https")
        d = fp.to_dict()
        assert d["scheme"] == "https"

    def test_invoker_probes_in_dict(self):
        fp = JBossFingerprint(
            invoker_probes=[
                InvokerPathProbe(path="/test", reachable=True, http_status=200),
            ]
        )
        d = fp.to_dict()
        assert len(d["invoker_probes"]) == 1
        assert d["invoker_probes"][0]["path"] == "/test"


# ---------------------------------------------------------------------------
# _extract_edition
# ---------------------------------------------------------------------------

class TestExtractEdition:
    def test_wildfly(self):
        assert _extract_edition("WildFly 10") == "WildFly"

    def test_eap(self):
        assert _extract_edition("jboss eap 6.4") == "EAP"

    def test_as(self):
        assert _extract_edition("JBoss AS 6.1") == "AS"

    def test_jboss_generic(self):
        assert _extract_edition("JBoss blah") == "JBoss"

    def test_none(self):
        assert _extract_edition("apache tomcat") is None


# ---------------------------------------------------------------------------
# _extract_version
# ---------------------------------------------------------------------------

class TestExtractVersionExtended:
    def test_eap_version(self):
        v = _extract_version("jboss eap 7.2")
        assert v == "JBoss EAP 7.2"

    def test_wildfly_version(self):
        v = _extract_version("wildfly 26")
        assert v == "WildFly 26"


# ---------------------------------------------------------------------------
# JBossFingerprinter HTTPS
# ---------------------------------------------------------------------------

class TestJBossFingerprinterHTTPS:
    def test_scheme_passed_to_fingerprint(self):
        """HTTPS scheme should propagate to the fingerprint result."""
        fp_er = JBossFingerprinter(timeout=1.0, scheme="https")
        # Mock all probes to avoid network calls
        fp_er._probe_http_banner = MagicMock()
        fp_er._probe_invoker_paths = MagicMock()
        fp_er._probe_remoting2 = MagicMock()

        result = fp_er.fingerprint("10.0.0.1", 8443)
        assert result.scheme == "https"
        # Verify banner probe was called with https URL
        call_args = fp_er._probe_http_banner.call_args[0]
        assert call_args[0].startswith("https://")

    def test_scheme_override(self):
        """scheme= parameter on fingerprint() overrides instance default."""
        fp_er = JBossFingerprinter(timeout=1.0, scheme="http")
        fp_er._probe_http_banner = MagicMock()
        fp_er._probe_invoker_paths = MagicMock()
        fp_er._probe_remoting2 = MagicMock()

        result = fp_er.fingerprint("10.0.0.1", 8443, scheme="https")
        assert result.scheme == "https"

    @patch("urllib.request.urlopen")
    def test_auth_detection_401(self, mock_urlopen):
        """HTTP 401 on invoker path should set requires_auth."""
        # Banner probe succeeds
        mock_resp = MagicMock()
        mock_resp.read.return_value = b"JBoss Application Server"
        mock_resp.headers = {"Server": "JBoss", "X-Powered-By": ""}
        mock_resp.status = 200

        # First call (banner) succeeds, invoker calls raise 401
        def urlopen_side_effect(req, timeout=None, context=None):
            if "/invoker/" in req.full_url or "/web-console/" in req.full_url:
                raise urllib.error.HTTPError(req.full_url, 401, "Unauthorized", {}, None)
            return mock_resp

        mock_urlopen.side_effect = urlopen_side_effect

        fp_er = JBossFingerprinter(timeout=1.0)
        fp_er._probe_remoting2 = MagicMock()

        fp = JBossFingerprint()
        fp_er._probe_invoker_paths("http://10.0.0.1:8080", fp)

        auth_probes = [p for p in fp.invoker_probes if p.requires_auth]
        assert len(auth_probes) > 0
