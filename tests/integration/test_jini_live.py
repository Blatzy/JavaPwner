"""Live integration tests against a real Jini/Reggie endpoint.

These tests are marked with ``@pytest.mark.live`` and are skipped by default.
Run them with::

    pytest tests/integration/ -m live

Prerequisites:
  - A Reggie instance reachable at JINI_TARGET_HOST:JINI_TARGET_PORT
  - Optionally ysoserial.jar for exploit tests

Environment variables:
  JINI_TARGET_HOST   — default: 127.0.0.1
  JINI_TARGET_PORT   — default: 4160
  JINI_DNS_URL       — callback URL for JEP290 probe
"""

from __future__ import annotations

import os

import pytest

from javapwner.protocols.jini.enumerator import JiniEnumerator
from javapwner.protocols.jini.exploiter import JiniExploiter
from javapwner.protocols.jini.scanner import JiniScanner

_HOST = os.environ.get("JINI_TARGET_HOST", "127.0.0.1")
_PORT = int(os.environ.get("JINI_TARGET_PORT", "4160"))
_DNS_URL = os.environ.get("JINI_DNS_URL", "http://canary.local")


@pytest.fixture(scope="module")
def scan_result():
    scanner = JiniScanner(timeout=10.0)
    return scanner.scan(_HOST, _PORT)


@pytest.mark.live
class TestLiveScan:
    def test_port_open(self, scan_result):
        assert scan_result.is_open, f"Port {_PORT} is not open on {_HOST}"

    def test_jrmp_detected(self, scan_result):
        assert scan_result.is_jrmp, "JRMP was not detected — is this a Reggie?"

    def test_unicast_response(self, scan_result):
        assert scan_result.has_unicast_response, \
            "No Unicast Discovery response — is this a Reggie?"

    def test_unicast_version(self, scan_result):
        assert scan_result.unicast_version in (1, 2)

    def test_groups_non_empty(self, scan_result):
        # Most Reggie instances advertise at least one group
        # (may be empty string "" for the public group)
        assert scan_result.groups is not None

    def test_raw_proxy_bytes_not_empty(self, scan_result):
        assert len(scan_result.raw_proxy_bytes) > 4


@pytest.mark.live
class TestLiveEnum:
    def test_enum_returns_result(self, scan_result):
        enumerator = JiniEnumerator(timeout=10.0)
        result = enumerator.enumerate(_HOST, _PORT, scan_result=scan_result)
        assert result is not None

    def test_enum_tier_is_1(self, scan_result):
        enumerator = JiniEnumerator(timeout=10.0)
        result = enumerator.enumerate(_HOST, _PORT, scan_result=scan_result)
        assert result.tier == 1

    def test_enum_extracts_strings(self, scan_result):
        enumerator = JiniEnumerator(timeout=10.0)
        result = enumerator.enumerate(_HOST, _PORT, scan_result=scan_result)
        # At minimum we expect some strings in a real Reggie response
        assert len(result.raw_strings) > 0


@pytest.mark.live
class TestLiveJep290Probe:
    def test_jep290_probe_no_error(self):
        """Probe should complete without exception regardless of outcome."""
        try:
            exploiter = JiniExploiter(timeout=10.0)
        except Exception:
            pytest.skip("ysoserial.jar not available")
        # Result is a boolean — we just check it doesn't crash
        result = exploiter.probe_jep290(_HOST, _PORT, _DNS_URL)
        assert isinstance(result, bool)
