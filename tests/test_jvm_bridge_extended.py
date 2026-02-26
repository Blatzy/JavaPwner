"""Extended unit tests for JvmBridge — Maven fat JAR, _find_fat_jar."""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from javapwner.core.jvm_bridge import (
    JvmBridge,
    _find_fat_jar,
    _FAT_JAR_DIR,
    _FAT_JAR_GLOB,
    _POM_XML,
)
from javapwner.exceptions import JvmBridgeError


# ---------------------------------------------------------------------------
# _find_fat_jar
# ---------------------------------------------------------------------------

class TestFindFatJar:
    def test_returns_none_when_no_target_dir(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            "javapwner.core.jvm_bridge._FAT_JAR_DIR", tmp_path / "nonexistent"
        )
        assert _find_fat_jar() is None

    def test_returns_none_when_no_jars(self, tmp_path, monkeypatch):
        target = tmp_path / "target"
        target.mkdir()
        monkeypatch.setattr("javapwner.core.jvm_bridge._FAT_JAR_DIR", target)
        assert _find_fat_jar() is None

    def test_returns_jar_when_present(self, tmp_path, monkeypatch):
        target = tmp_path / "target"
        target.mkdir()
        jar = target / "javapwner-jini-helper-1.0-jar-with-dependencies.jar"
        jar.write_bytes(b"PK\x00\x00")
        monkeypatch.setattr("javapwner.core.jvm_bridge._FAT_JAR_DIR", target)
        monkeypatch.setattr(
            "javapwner.core.jvm_bridge._FAT_JAR_GLOB", _FAT_JAR_GLOB
        )
        result = _find_fat_jar()
        assert result == jar


# ---------------------------------------------------------------------------
# JvmBridge.mvn_available / fat_jar_available
# ---------------------------------------------------------------------------

class TestJvmBridgeProperties:
    def test_mvn_available_true(self):
        with patch("javapwner.core.jvm_bridge._find_executable") as mock_find:
            mock_find.side_effect = lambda name: (
                "/usr/bin/mvn" if name == "mvn" else None
            )
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=None):
                bridge = JvmBridge()
        assert bridge.mvn_available is True

    def test_mvn_available_false(self):
        with patch("javapwner.core.jvm_bridge._find_executable", return_value=None):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=None):
                bridge = JvmBridge()
        assert bridge.mvn_available is False

    def test_fat_jar_available_true(self, tmp_path):
        jar = tmp_path / "helper.jar"
        jar.write_bytes(b"PK")
        with patch("javapwner.core.jvm_bridge._find_executable", return_value=None):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=jar):
                bridge = JvmBridge()
        assert bridge.fat_jar_available is True

    def test_fat_jar_available_false(self):
        with patch("javapwner.core.jvm_bridge._find_executable", return_value=None):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=None):
                bridge = JvmBridge()
        assert bridge.fat_jar_available is False


# ---------------------------------------------------------------------------
# JvmBridge.build_fat_jar
# ---------------------------------------------------------------------------

class TestBuildFatJar:
    def test_returns_existing_jar_if_available(self, tmp_path):
        jar = tmp_path / "helper.jar"
        jar.write_bytes(b"PK")
        with patch("javapwner.core.jvm_bridge._find_executable", return_value=None):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=jar):
                bridge = JvmBridge()
        result = bridge.build_fat_jar()
        assert result == jar

    def test_raises_if_no_mvn(self):
        with patch("javapwner.core.jvm_bridge._find_executable", return_value=None):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=None):
                bridge = JvmBridge()
        with pytest.raises(JvmBridgeError, match="Maven"):
            bridge.build_fat_jar(force=True)

    def test_raises_if_no_pom(self, tmp_path):
        with patch(
            "javapwner.core.jvm_bridge._find_executable",
            side_effect=lambda name: "/usr/bin/mvn" if name == "mvn" else None,
        ):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=None):
                bridge = JvmBridge()

        with patch("javapwner.core.jvm_bridge._POM_XML", tmp_path / "missing.xml"):
            with pytest.raises(JvmBridgeError, match="pom.xml"):
                bridge.build_fat_jar(force=True)

    def test_successful_build(self, tmp_path):
        pom = tmp_path / "pom.xml"
        pom.write_text("<project/>")
        target = tmp_path / "target"
        target.mkdir()
        built_jar = target / "javapwner-jini-helper-1.0-jar-with-dependencies.jar"
        built_jar.write_bytes(b"PK")

        with patch(
            "javapwner.core.jvm_bridge._find_executable",
            side_effect=lambda name: "/usr/bin/mvn" if name == "mvn" else None,
        ):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=None):
                bridge = JvmBridge()

        mock_proc = MagicMock()
        mock_proc.returncode = 0
        mock_proc.stderr = ""

        with patch("javapwner.core.jvm_bridge._POM_XML", pom):
            with patch("subprocess.run", return_value=mock_proc):
                with patch(
                    "javapwner.core.jvm_bridge._find_fat_jar",
                    return_value=built_jar,
                ):
                    result = bridge.build_fat_jar(force=True)

        assert result == built_jar

    def test_build_failure_raises(self, tmp_path):
        pom = tmp_path / "pom.xml"
        pom.write_text("<project/>")

        with patch(
            "javapwner.core.jvm_bridge._find_executable",
            side_effect=lambda name: "/usr/bin/mvn" if name == "mvn" else None,
        ):
            with patch("javapwner.core.jvm_bridge._find_fat_jar", return_value=None):
                bridge = JvmBridge()

        mock_proc = MagicMock()
        mock_proc.returncode = 1
        mock_proc.stderr = "BUILD FAILURE"

        with patch("javapwner.core.jvm_bridge._POM_XML", pom):
            with patch("subprocess.run", return_value=mock_proc):
                with pytest.raises(JvmBridgeError, match="BUILD FAILURE"):
                    bridge.build_fat_jar(force=True)
