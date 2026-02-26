"""Extended unit tests for YsoserialWrapper — new methods from Phase I."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch, call

import pytest

from javapwner.core.payload import YsoserialWrapper
from javapwner.exceptions import PayloadError


def _make_wrapper(tmp_path: Path) -> YsoserialWrapper:
    jar = tmp_path / "ysoserial.jar"
    jar.write_bytes(b"fake")
    return YsoserialWrapper(jar_path=str(jar))


# ---------------------------------------------------------------------------
# LRU cache (I.2)
# ---------------------------------------------------------------------------

class TestPayloadCache:
    def test_cached_result_reused(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        wrapper._cache.clear()  # ensure clean state (class-level cache)
        mock_result = MagicMock()
        mock_result.stdout = b"\xac\xed\x00\x05payload"
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            p1 = wrapper.generate("CC6", "id")
            p2 = wrapper.generate("CC6", "id")
            assert p1 == p2
            # subprocess.run called only once thanks to cache
            assert mock_run.call_count == 1

    def test_different_keys_not_cached(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        wrapper._cache.clear()
        mock_result = MagicMock()
        mock_result.stdout = b"\xac\xed\x00\x05payload"
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            wrapper.generate("CC6_a", "id")
            wrapper.generate("CC6_a", "whoami")
            assert mock_run.call_count == 2


# ---------------------------------------------------------------------------
# generate_jrmp_client_gadget (I.3)
# ---------------------------------------------------------------------------

class TestGenerateJrmpClientGadget:
    def test_calls_generate_with_jrmpclient(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stdout = b"\xac\xed\x00\x05jrmp_gadget"

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            data = wrapper.generate_jrmp_client_gadget("10.0.0.1", 8888)

        assert data == b"\xac\xed\x00\x05jrmp_gadget"
        cmd = mock_run.call_args[0][0]
        assert cmd[2] == str(tmp_path / "ysoserial.jar")
        assert cmd[3] == "JRMPClient"
        assert cmd[4] == "10.0.0.1:8888"


# ---------------------------------------------------------------------------
# generate_spray (I.4)
# ---------------------------------------------------------------------------

class TestGenerateSpray:
    def test_multiple_gadgets(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        wrapper._cache.clear()
        mock_result = MagicMock()
        mock_result.stdout = b"\xac\xed\x00\x05data"

        with patch("subprocess.run", return_value=mock_result):
            results = wrapper.generate_spray(["SprayCC6", "SprayCB1"], "id")

        assert "SprayCC6" in results
        assert "SprayCB1" in results
        assert isinstance(results["SprayCC6"], bytes)

    def test_failed_gadget_records_error(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        wrapper._cache.clear()
        mock_ok = MagicMock()
        mock_ok.stdout = b"\xac\xed\x00\x05data"

        mock_fail = MagicMock()
        mock_fail.stdout = b""
        mock_fail.stderr = b"Unknown gadget"

        with patch("subprocess.run", side_effect=[mock_ok, mock_fail]):
            results = wrapper.generate_spray(["GoodGadget1", "BadGadget1"], "spray_id")

        assert isinstance(results["GoodGadget1"], bytes)
        assert isinstance(results["BadGadget1"], str)
        assert "ERROR" in results["BadGadget1"]


# ---------------------------------------------------------------------------
# run_jrmp_listener (I.1)
# ---------------------------------------------------------------------------

class TestRunJrmpListener:
    def test_blocking_mode(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        mock_completed = MagicMock(spec=subprocess.CompletedProcess)
        mock_completed.stdout = b"Listening..."
        mock_completed.stderr = b""

        with patch("subprocess.run", return_value=mock_completed) as mock_run:
            result = wrapper.run_jrmp_listener(8888, "CC6", "id")

        assert result is mock_completed
        cmd = mock_run.call_args[0][0]
        assert "ysoserial.exploit.JRMPListener" in cmd
        assert "8888" in cmd

    def test_fork_mode(self, tmp_path):
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"fake")
        wrapper = YsoserialWrapper(jar_path=str(jar), fork=True)

        mock_popen = MagicMock(spec=subprocess.Popen)

        with patch("subprocess.Popen", return_value=mock_popen) as mock_cls:
            result = wrapper.run_jrmp_listener(8888, "CC6", "id")

        assert result is mock_popen
        assert mock_popen in wrapper._background_procs


# ---------------------------------------------------------------------------
# run_jrmp_client (I.1)
# ---------------------------------------------------------------------------

class TestRunJrmpClient:
    def test_invocation(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        mock_completed = MagicMock(spec=subprocess.CompletedProcess)

        with patch("subprocess.run", return_value=mock_completed) as mock_run:
            result = wrapper.run_jrmp_client("10.0.0.1", 1099, "CC6", "id")

        assert result is mock_completed
        cmd = mock_run.call_args[0][0]
        assert "ysoserial.exploit.JRMPClient" in cmd
        assert "10.0.0.1" in cmd


# ---------------------------------------------------------------------------
# run_rmi_registry_exploit (I.1)
# ---------------------------------------------------------------------------

class TestRunRmiRegistryExploit:
    def test_invocation(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        mock_completed = MagicMock(spec=subprocess.CompletedProcess)

        with patch("subprocess.run", return_value=mock_completed) as mock_run:
            result = wrapper.run_rmi_registry_exploit("10.0.0.1", 1099, "CC6", "id")

        assert result is mock_completed
        cmd = mock_run.call_args[0][0]
        assert "ysoserial.exploit.RMIRegistryExploit" in cmd

    def test_timeout_raises(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)

        with patch(
            "subprocess.run",
            side_effect=subprocess.TimeoutExpired("cmd", 30),
        ):
            with pytest.raises(PayloadError, match="timed out"):
                wrapper.run_rmi_registry_exploit("10.0.0.1", 1099, "CC6", "id")

    def test_java_not_found(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)

        with patch("subprocess.run", side_effect=FileNotFoundError("java")):
            with pytest.raises(PayloadError, match="java"):
                wrapper.run_rmi_registry_exploit("10.0.0.1", 1099, "CC6", "id")


# ---------------------------------------------------------------------------
# cleanup (I.5)
# ---------------------------------------------------------------------------

class TestCleanup:
    def test_terminates_background_procs(self, tmp_path):
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"fake")
        wrapper = YsoserialWrapper(jar_path=str(jar), fork=True)

        mock_proc = MagicMock(spec=subprocess.Popen)
        wrapper._background_procs.append(mock_proc)

        wrapper.cleanup()

        mock_proc.terminate.assert_called_once()
        assert len(wrapper._background_procs) == 0

    def test_cleanup_kills_if_terminate_fails(self, tmp_path):
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"fake")
        wrapper = YsoserialWrapper(jar_path=str(jar), fork=True)

        mock_proc = MagicMock(spec=subprocess.Popen)
        mock_proc.terminate.side_effect = Exception("term failed")
        mock_proc.wait.side_effect = Exception("wait failed")
        wrapper._background_procs.append(mock_proc)

        wrapper.cleanup()  # should not raise
        mock_proc.kill.assert_called_once()


# ---------------------------------------------------------------------------
# jar_path property
# ---------------------------------------------------------------------------

class TestJarPathProperty:
    def test_returns_resolved_path(self, tmp_path):
        wrapper = _make_wrapper(tmp_path)
        assert wrapper.jar_path == tmp_path / "ysoserial.jar"
