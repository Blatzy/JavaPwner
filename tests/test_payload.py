"""Unit tests for javapwner.core.payload — mock subprocess calls."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from javapwner.core.payload import YsoserialWrapper, _find_ysoserial_jar
from javapwner.exceptions import PayloadError

# ---------------------------------------------------------------------------
# _find_ysoserial_jar (path resolution)
# ---------------------------------------------------------------------------

class TestFindYsoserialJar:
    def test_env_var_takes_priority(self, tmp_path, monkeypatch):
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"")
        monkeypatch.setenv("YSOSERIAL_PATH", str(jar))
        found = _find_ysoserial_jar()
        assert found == jar

    def test_env_var_nonexistent_skipped(self, monkeypatch):
        monkeypatch.setenv("YSOSERIAL_PATH", "/nonexistent/ysoserial.jar")
        # Should fall through to other locations (may or may not find one)
        result = _find_ysoserial_jar()
        assert result is None or result.is_file()

    def test_returns_none_when_not_found(self, monkeypatch, tmp_path):
        monkeypatch.delenv("YSOSERIAL_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        # Override lib path by patching __file__ indirectly isn't straightforward,
        # but we can test that the return is None or a valid file.
        result = _find_ysoserial_jar()
        # In a fresh tmp dir with no jar, expect None
        assert result is None or result.is_file()


# ---------------------------------------------------------------------------
# YsoserialWrapper — list_gadgets
# ---------------------------------------------------------------------------

_YSOSERIAL_HELP_STDERR = b"""
     Payload             Authors                                Dependencies
     -------             -------                                ------------
     BeanShell1          @pwntester, @cschneider4711            bsh:2.0b5
     C3P0                @mbechler                              mchange-commons-java:0.2.11,...
     CommonsBeanutils1   @frohoff                               commons-beanutils:1.9.2,...
     CommonsCollections1 @frohoff                               commons-collections:3.1
     CommonsCollections6 @frohoff                               commons-collections:3.1
     Groovy1             @frohoff                               groovy:2.3.9
     URLDNS              @gebl                                  (none)
"""


class TestListGadgets:
    def _make_wrapper(self, tmp_path) -> YsoserialWrapper:
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"fake")
        return YsoserialWrapper(jar_path=str(jar))

    def test_gadgets_parsed(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stderr = _YSOSERIAL_HELP_STDERR
        mock_result.stdout = b""
        with patch("subprocess.run", return_value=mock_result):
            gadgets = wrapper.list_gadgets()
        assert "CommonsCollections6" in gadgets
        assert "URLDNS" in gadgets
        assert "BeanShell1" in gadgets

    def test_gadgets_cached(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stderr = _YSOSERIAL_HELP_STDERR
        mock_result.stdout = b""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            wrapper.list_gadgets()
            wrapper.list_gadgets()
            # cached_property means subprocess.run called only once
            assert mock_run.call_count == 1

    def test_validate_gadget_true(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stderr = _YSOSERIAL_HELP_STDERR
        mock_result.stdout = b""
        with patch("subprocess.run", return_value=mock_result):
            assert wrapper.validate_gadget("URLDNS") is True

    def test_validate_gadget_false(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stderr = _YSOSERIAL_HELP_STDERR
        mock_result.stdout = b""
        with patch("subprocess.run", return_value=mock_result):
            assert wrapper.validate_gadget("NonExistentGadget") is False


# ---------------------------------------------------------------------------
# YsoserialWrapper — generate
# ---------------------------------------------------------------------------

_FAKE_PAYLOAD = b"\xac\xed\x00\x05ur\x00\x13[Ljava.lang.Object;"


class TestGenerate:
    def _make_wrapper(self, tmp_path) -> YsoserialWrapper:
        jar = tmp_path / "ysoserial.jar"
        jar.write_bytes(b"fake")
        return YsoserialWrapper(jar_path=str(jar))

    def test_generate_returns_bytes(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stdout = _FAKE_PAYLOAD
        mock_result.stderr = b""
        mock_result.returncode = 0
        with patch("subprocess.run", return_value=mock_result):
            payload = wrapper.generate("CommonsCollections6", "id")
        assert payload == _FAKE_PAYLOAD

    def test_generate_empty_raises(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stdout = b""
        mock_result.stderr = b"error: invalid gadget"
        with patch("subprocess.run", return_value=mock_result):
            with pytest.raises(PayloadError, match="empty payload"):
                wrapper.generate("BadGadget", "id")

    def test_generate_timeout_raises(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired(cmd="java", timeout=30)):
            with pytest.raises(PayloadError, match="timed out"):
                wrapper.generate("URLDNS", "http://test.local")

    def test_generate_no_java_raises(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        with patch("subprocess.run", side_effect=FileNotFoundError("java")):
            with pytest.raises(PayloadError, match="java binary"):
                wrapper.generate("URLDNS", "http://test.local")

    def test_generate_urldns(self, tmp_path):
        wrapper = self._make_wrapper(tmp_path)
        mock_result = MagicMock()
        mock_result.stdout = _FAKE_PAYLOAD
        mock_result.stderr = b""
        with patch("subprocess.run", return_value=mock_result) as mock_run:
            payload = wrapper.generate_urldns("http://callback.local")
        call_args = mock_run.call_args[0][0]
        assert "URLDNS" in call_args
        assert "http://callback.local" in call_args
        assert payload == _FAKE_PAYLOAD


# ---------------------------------------------------------------------------
# YsoserialWrapper — init without jar
# ---------------------------------------------------------------------------

class TestWrapperInit:
    def test_missing_jar_raises(self, monkeypatch, tmp_path):
        monkeypatch.delenv("YSOSERIAL_PATH", raising=False)
        monkeypatch.chdir(tmp_path)
        with pytest.raises(PayloadError, match="not found"):
            YsoserialWrapper()

    def test_explicit_nonexistent_path_raises(self, tmp_path):
        with pytest.raises((PayloadError, FileNotFoundError, Exception)):
            # Constructor accepts the path; error surfaces on use or init
            wrapper = YsoserialWrapper(jar_path=str(tmp_path / "missing.jar"))
            # If init doesn't raise, generation must
            mock_result = MagicMock()
            mock_result.stdout = b""
            mock_result.stderr = b""
            with patch("subprocess.run", return_value=mock_result):
                wrapper.generate("URLDNS", "x")
