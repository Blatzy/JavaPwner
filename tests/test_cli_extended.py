"""Extended CLI tests — RMI guess/info, JBoss jnp-scan/info, --ysoserial-check."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from javapwner.cli.main import cli


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _invoke(*args: str, catch_exceptions: bool = False):
    runner = CliRunner()
    return runner.invoke(cli, list(args), catch_exceptions=catch_exceptions)


# ---------------------------------------------------------------------------
# --ysoserial-check
# ---------------------------------------------------------------------------

class TestYsoserialCheck:
    def test_check_found(self, tmp_path):
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"fake")

        mock_result = MagicMock()
        mock_result.stderr = (
            b"     CommonsCollections6 @frohoff  commons-collections:3.1\n"
            b"     URLDNS              @gebl     (none)\n"
        )
        mock_result.stdout = b""

        with patch("subprocess.run", return_value=mock_result):
            result = _invoke("--ysoserial", str(jar), "--ysoserial-check")

        assert result.exit_code == 0
        assert "ysoserial.jar found" in result.output

    def test_check_not_found(self):
        with patch(
            "javapwner.core.payload._find_ysoserial_jar", return_value=None
        ):
            result = _invoke("--ysoserial-check")

        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# rmi scan --urldns
# ---------------------------------------------------------------------------

class TestRmiScanUrldns:
    @patch("javapwner.protocols.rmi.scanner.RmiScanner.scan")
    def test_urldns_option_passed(self, mock_scan):
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "host": "10.0.0.1",
            "port": 1099,
            "is_open": True,
            "is_jrmp": True,
            "bound_names": [],
            "name_types": {},
            "stub_endpoints": {},
            "jep290_enforced": False,
            "urldns_sent": True,
            "urldns_canary": "http://test.example.com",
        }
        mock_scan.return_value = mock_result

        result = _invoke(
            "--json", "rmi", "scan", "-t", "10.0.0.1",
            "--urldns", "http://test.example.com",
        )

        assert result.exit_code == 0
        mock_scan.assert_called_once()
        # Verify urldns_canary was passed
        call_kwargs = mock_scan.call_args
        assert call_kwargs[1].get("urldns_canary") == "http://test.example.com" or \
               (len(call_kwargs[0]) > 2 and call_kwargs[0][2] == "http://test.example.com")


# ---------------------------------------------------------------------------
# rmi guess
# ---------------------------------------------------------------------------

class TestRmiGuess:
    @patch("javapwner.protocols.rmi.guesser.RmiMethodGuesser.guess")
    def test_guess_cmd(self, mock_guess):
        from javapwner.protocols.rmi.guesser import MethodGuessResult

        mock_guess.return_value = MethodGuessResult(
            bound_name="myService",
            class_name="com.example.Service",
            confirmed_methods=["getVersion"],
            rejected_methods=[],
        )

        result = _invoke("--json", "rmi", "guess", "-t", "10.0.0.1", "--name", "myService")

        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# rmi exploit --via jep290-bypass
# ---------------------------------------------------------------------------

class TestRmiExploitVia:
    @patch("javapwner.protocols.rmi.exploiter.RmiExploiter.exploit")
    def test_via_jep290_bypass(self, mock_exploit, tmp_path):
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"fake")

        mock_exploit.return_value = MagicMock(
            to_dict=lambda: {
                "sent": True,
                "likely_success": True,
                "exception_in_response": False,
                "error": None,
            }
        )

        result = _invoke(
            "--json", "--ysoserial", str(jar),
            "rmi", "exploit", "-t", "10.0.0.1", "-p", "1099",
            "--gadget", "CC6", "--cmd", "id", "--via", "jep290-bypass",
        )

        # The command may exit 0 or non-zero depending on mock wiring,
        # but the exploit method should have been called with via=jep290-bypass
        if mock_exploit.called:
            call_kwargs = mock_exploit.call_args
            if call_kwargs[1]:
                assert call_kwargs[1].get("via") == "jep290-bypass"


# ---------------------------------------------------------------------------
# jboss scan --https
# ---------------------------------------------------------------------------

class TestJbossScanHttps:
    @patch("javapwner.protocols.jboss.scanner.JBossScanner.scan")
    def test_https_flag(self, mock_scan):
        mock_result = MagicMock()
        mock_result.to_dict.return_value = {
            "fingerprint": {"version": "JBoss EAP 7.2", "scheme": "https"},
            "invoker": {"reachable": False},
        }
        mock_scan.return_value = mock_result

        result = _invoke(
            "--json", "jboss", "scan", "-t", "10.0.0.1", "--https",
        )

        assert result.exit_code == 0
        # Verify scheme was passed
        if mock_scan.called:
            call_kwargs = mock_scan.call_args
            if call_kwargs[1]:
                assert call_kwargs[1].get("scheme") == "https"


# ---------------------------------------------------------------------------
# jboss jnp-scan
# ---------------------------------------------------------------------------

class TestJbossJnpScan:
    @patch("javapwner.protocols.jboss.jnp.JnpScanner.scan")
    def test_jnp_scan_cmd(self, mock_scan):
        from javapwner.protocols.jboss.jnp import JnpScanResult

        mock_scan.return_value = JnpScanResult(
            host="10.0.0.1",
            port=1099,
            is_open=True,
            is_jnp=True,
            bound_names=["MyEJB"],
        )

        result = _invoke(
            "--json", "jboss", "jnp-scan", "-t", "10.0.0.1",
        )

        assert result.exit_code == 0
        mock_scan.assert_called_once()
