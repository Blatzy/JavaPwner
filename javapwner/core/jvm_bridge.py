"""JVM Bridge — find, compile, and run the Java helper for Tier 2 operations.

The bridge locates a JDK (``java`` / ``javac``), discovers Jini/River JARs
on the classpath, compiles ``lib/JiniInspector.java`` on demand, and
executes it as a subprocess.  Communication uses JSON over stdout.

Classpath resolution order:

1. Explicit *classpath* argument (list of paths).
2. ``JINI_CLASSPATH`` environment variable (``':'``-separated on Linux,
   ``';'``-separated on Windows).
3. JARs found in ``<project>/lib/`` matching known patterns.
4. ``RIVER_HOME`` / ``JINI_HOME`` environment variables.

All JVM operations are optional — the bridge gracefully degrades with
:class:`~javapwner.exceptions.JvmBridgeError` when prerequisites are
missing.
"""

from __future__ import annotations

import json
import logging
import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

from javapwner.exceptions import JvmBridgeError

logger = logging.getLogger(__name__)

# The Java helper lives alongside the JARs in lib/ at the project root.
# Path: javapwner/core/jvm_bridge.py → parent = javapwner/core/
#       parent.parent = javapwner/  → parent.parent.parent = project root
_LIB_DIR = Path(__file__).resolve().parent.parent.parent / "lib"
_INSPECTOR_SOURCE = _LIB_DIR / "JiniInspector.java"
_INSPECTOR_CLASS = _LIB_DIR / "JiniInspector.class"
_SECURITY_POLICY = _LIB_DIR / "security.policy"
_POM_XML = _LIB_DIR / "pom.xml"
_FAT_JAR_DIR = _LIB_DIR / "target"
_FAT_JAR_GLOB = "javapwner-jini-helper-*-jar-with-dependencies.jar"

_PATH_SEP = ";" if platform.system() == "Windows" else ":"


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _find_executable(name: str) -> str | None:
    """Find *name* on PATH or via JAVA_HOME."""
    # 1. JAVA_HOME
    java_home = os.environ.get("JAVA_HOME")
    if java_home:
        candidate = Path(java_home) / "bin" / name
        if candidate.is_file():
            return str(candidate)

    # 2. PATH
    return shutil.which(name)


def _find_fat_jar() -> Path | None:
    """Locate the pre-built fat JAR in lib/target/."""
    if _FAT_JAR_DIR.is_dir():
        jars = list(_FAT_JAR_DIR.glob(_FAT_JAR_GLOB))
        if jars:
            return jars[0]
    return None


def _discover_jars(extra_dirs: list[Path] | None = None) -> list[Path]:
    """Collect JAR files from lib/ and optional extra directories."""
    jars: list[Path] = []
    seen: set[str] = set()

    search_dirs = [_LIB_DIR]
    if extra_dirs:
        search_dirs.extend(extra_dirs)

    # RIVER_HOME / JINI_HOME
    for env in ("RIVER_HOME", "JINI_HOME"):
        val = os.environ.get(env)
        if val:
            p = Path(val)
            if p.is_dir():
                search_dirs.append(p / "lib")
                search_dirs.append(p / "lib-dl")
                search_dirs.append(p)

    for d in search_dirs:
        if not d.is_dir():
            continue
        for jar in sorted(d.glob("*.jar")):
            real = str(jar.resolve())
            if real not in seen:
                seen.add(real)
                jars.append(jar)

    return jars


def _build_classpath(
    explicit: list[str] | None = None,
    extra_dirs: list[Path] | None = None,
) -> str:
    """Build a ``':'``-separated classpath string.

    Resolution order:
      1. *explicit* list (user-provided)
      2. ``JINI_CLASSPATH`` env var
      3. Auto-discovered JARs
    """
    parts: list[str] = []

    # Explicit
    if explicit:
        parts.extend(explicit)

    # Environment
    env_cp = os.environ.get("JINI_CLASSPATH", "")
    if env_cp:
        parts.extend(env_cp.split(_PATH_SEP))

    # Auto-discover
    for jar in _discover_jars(extra_dirs):
        parts.append(str(jar))

    # Always include lib/ itself (for compiled .class files)
    parts.append(str(_LIB_DIR))

    # Deduplicate while preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for p in parts:
        if p not in seen:
            seen.add(p)
            unique.append(p)

    return _PATH_SEP.join(unique)


# ---------------------------------------------------------------------------
# JVM Bridge
# ---------------------------------------------------------------------------

class JvmBridge:
    """Manages the lifecycle of Java subprocess calls for Tier 2 operations.

    Parameters
    ----------
    classpath:
        Explicit list of JAR paths / directories.  Merged with env and
        auto-discovered JARs.
    java_home:
        Override for JAVA_HOME.
    timeout:
        Maximum seconds to wait for the Java subprocess.
    """

    def __init__(
        self,
        classpath: list[str] | None = None,
        java_home: str | None = None,
        timeout: float = 30.0,
    ):
        self._java_home = java_home

        # Build per-subprocess environment (never mutate os.environ)
        self._env = os.environ.copy()
        if java_home:
            self._env["JAVA_HOME"] = java_home

        self._java = _find_executable("java")
        self._javac = _find_executable("javac")
        self._mvn = _find_executable("mvn")
        self._classpath_parts = classpath
        self._timeout = timeout

        # Resolved lazily
        self._classpath: str | None = None
        self._compiled = False
        self._fat_jar: Path | None = _find_fat_jar()
        self._java_major_version_cache: int | None = None

    # ------------------------------------------------------------------
    # Status queries
    # ------------------------------------------------------------------

    @property
    def java_available(self) -> bool:
        return self._java is not None

    @property
    def javac_available(self) -> bool:
        return self._javac is not None

    @property
    def mvn_available(self) -> bool:
        return self._mvn is not None

    @property
    def fat_jar_available(self) -> bool:
        return self._fat_jar is not None and self._fat_jar.is_file()

    @property
    def classpath(self) -> str:
        if self._classpath is None:
            self._classpath = _build_classpath(self._classpath_parts)
        return self._classpath

    @property
    def api_classpath(self) -> str:
        """Classpath with only API JARs (no implementation proxies).

        Excludes ``reggie*.jar`` so that RMI is forced to download the
        correct proxy classes from the target's codebase.  This avoids
        ``serialVersionUID`` mismatches when the target runs a different
        Jini/River version than the local JARs.
        """
        parts = self.classpath.split(_PATH_SEP)
        filtered = [
            p for p in parts
            if not Path(p).name.startswith("reggie")
        ]
        return _PATH_SEP.join(filtered)

    @property
    def java_major_version(self) -> int:
        """Return the JVM major version (8, 11, 17, 21…), or 0 if unknown.

        The result is cached after the first call.
        """
        if self._java_major_version_cache is not None:
            return self._java_major_version_cache
        version = 0
        if self._java is not None:
            try:
                proc = subprocess.run(
                    [self._java, "-version"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                    env=self._env,
                )
                # java -version writes to stderr: 'java version "17.0.4"' or
                # 'openjdk version "11.0.16"'
                output = proc.stderr or proc.stdout
                # "1.8.0_xyz" → 8;  "11.0.x" → 11;  "17.0.x" → 17
                m = re.search(r'"(\d+)\.(\d+)', output)
                if m:
                    major = int(m.group(1))
                    version = int(m.group(2)) if major == 1 else major
            except Exception:
                pass
        self._java_major_version_cache = version
        return version

    def has_jini_jars(self) -> bool:
        """Return True if at least one Jini/River JAR was found."""
        jars = _discover_jars()
        return any(
            j.name != ".gitkeep"
            and j.suffix == ".jar"
            for j in jars
        )

    def check_prerequisites(self) -> list[str]:
        """Return a list of missing prerequisites (empty = all OK)."""
        issues: list[str] = []
        if not self.java_available:
            issues.append(
                "Java runtime not found. Install a JDK and ensure 'java' is on PATH "
                "or set JAVA_HOME."
            )
        if not self.javac_available:
            issues.append(
                "Java compiler (javac) not found. Install a JDK (not just JRE). "
                "Alternatively, pre-compile JiniInspector.java."
            )
        if not self.has_jini_jars():
            issues.append(
                "No Jini/River JARs found. Place Apache River JARs in lib/ "
                "or set JINI_CLASSPATH / RIVER_HOME."
            )
        if not _INSPECTOR_SOURCE.is_file():
            issues.append(f"JiniInspector.java not found at {_INSPECTOR_SOURCE}")
        return issues

    # ------------------------------------------------------------------
    # Compilation
    # ------------------------------------------------------------------

    def compile_inspector(self, force: bool = False) -> Path:
        """Compile ``JiniInspector.java`` if the .class file is stale or missing.

        Returns the path to the compiled ``.class`` file.

        Raises :class:`JvmBridgeError` on failure.
        """
        if not force and _INSPECTOR_CLASS.is_file():
            # Re-compile only if source is newer
            if _INSPECTOR_CLASS.stat().st_mtime >= _INSPECTOR_SOURCE.stat().st_mtime:
                self._compiled = True
                return _INSPECTOR_CLASS

        if not self._javac:
            raise JvmBridgeError(
                "javac not found — cannot compile JiniInspector.java. "
                "Install a JDK or pre-compile the class."
            )

        if not _INSPECTOR_SOURCE.is_file():
            raise JvmBridgeError(f"Source file not found: {_INSPECTOR_SOURCE}")

        cmd = [
            self._javac,
            "-cp", self.classpath,
            "-d", str(_LIB_DIR),
            str(_INSPECTOR_SOURCE),
        ]

        logger.debug("Compiling: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                env=self._env,
            )
        except subprocess.TimeoutExpired as exc:
            raise JvmBridgeError(f"javac timed out after {self._timeout}s") from exc
        except FileNotFoundError as exc:
            raise JvmBridgeError(f"javac not found: {exc}") from exc

        if proc.returncode != 0:
            stderr = proc.stderr.strip()
            raise JvmBridgeError(
                f"javac compilation failed (rc={proc.returncode}):\n{stderr}"
            )

        self._compiled = True
        return _INSPECTOR_CLASS

    # ------------------------------------------------------------------
    # Maven fat JAR build
    # ------------------------------------------------------------------

    def build_fat_jar(self, force: bool = False) -> Path:
        """Build the fat JAR using Maven (``mvn package -f lib/pom.xml``).

        Returns the path to the built fat JAR.
        Raises :class:`JvmBridgeError` on failure.
        """
        if not force and self.fat_jar_available:
            return self._fat_jar  # type: ignore[return-value]

        if not self._mvn:
            raise JvmBridgeError(
                "Maven (mvn) not found — cannot build fat JAR. "
                "Install Maven or build manually: mvn package -f lib/pom.xml"
            )

        if not _POM_XML.is_file():
            raise JvmBridgeError(f"pom.xml not found at {_POM_XML}")

        cmd = [
            self._mvn,
            "package",
            "-f", str(_POM_XML),
            "-q",                  # quiet mode
            "-DskipTests",
        ]

        logger.info("Building fat JAR: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120,  # Maven builds can be slow
                env=self._env,
            )
        except subprocess.TimeoutExpired as exc:
            raise JvmBridgeError("Maven build timed out after 120s") from exc
        except FileNotFoundError as exc:
            raise JvmBridgeError(f"mvn not found: {exc}") from exc

        if proc.returncode != 0:
            stderr = proc.stderr.strip()[:500]
            raise JvmBridgeError(
                f"Maven build failed (rc={proc.returncode}):\n{stderr}"
            )

        # Locate the built fat JAR
        fat_jar = _find_fat_jar()
        if fat_jar is None:
            raise JvmBridgeError("Maven build succeeded but fat JAR not found in target/")

        self._fat_jar = fat_jar
        return fat_jar

    # ------------------------------------------------------------------
    # Execution
    # ------------------------------------------------------------------

    def run_inspector(
        self,
        host: str,
        port: int,
        timeout_ms: int = 5000,
    ) -> dict[str, Any]:
        """Run ``JiniInspector`` and return the parsed JSON result.

        Uses a **two-pass strategy** to handle ``serialVersionUID``
        mismatches across Jini/River versions:

        1. **Pass 1 — API-only classpath** (no ``reggie*.jar``).  RMI
           downloads the correct proxy classes from the target's
           codebase via ``SecurityManager``.  Works when the target
           advertises a codebase URL.
        2. **Pass 2 — full classpath** (includes local ``reggie*.jar``).
           Fallback when the target has no codebase.  May fail with
           ``InvalidClassException`` if the local JAR version doesn't
           match the remote one.

        Raises :class:`JvmBridgeError` on infrastructure failures
        (missing JDK, compilation error, JSON parse error).
        The returned dict always has a ``"success"`` key.
        """
        self.compile_inspector()

        if not self._java:
            raise JvmBridgeError("java not found — cannot run JiniInspector")

        # If a fat JAR exists, prefer it (single classpath entry, all deps bundled)
        if self.fat_jar_available:
            logger.info("Using fat JAR: %s", self._fat_jar)
            fat_cp = str(self._fat_jar)
            result = self._execute_inspector(fat_cp, host, port, timeout_ms)
            if result.get("success"):
                return result
            # Fall through to the two-pass strategy if fat JAR fails

        # Pass 1: API-only classpath — let RMI download the right proxy
        logger.info("Pass 1: API-only classpath (RMI codebase loading)")
        result = self._execute_inspector(
            self.api_classpath, host, port, timeout_ms,
        )

        if result.get("success"):
            return result

        error = result.get("error", "")
        needs_retry = (
            "ClassNotFoundException" in error
            or "class loader disabled" in error
            or "NoClassDefFoundError" in error
        )

        if not needs_retry:
            # Non-classloading error (timeout, connection refused, etc.)
            return result

        # Pass 2: full classpath with local proxy JARs.
        # JiniInspector will attempt SUID-patching via reflection when it
        # catches InvalidClassException from getRegistrar().
        logger.info(
            "Pass 1 failed (%s) — retrying with local proxy JARs (SUID-patch enabled)",
            error[:120],
        )
        result_full = self._execute_inspector(
            self.classpath, host, port, timeout_ms,
        )

        if result_full.get("success"):
            return result_full

        # Both passes failed.
        # If Pass 2 error is an InvalidClassException SUID mismatch and the
        # reflection patch couldn't run (e.g. --add-opens not effective),
        # annotate the error with an actionable message.
        error2 = result_full.get("error", "")
        if "InvalidClassException" in error2 and "serialVersionUID" in error2:
            import re as _re
            m = _re.search(
                r"stream classdesc serialVersionUID = (\d+).*?local class serialVersionUID = (\d+)",
                error2,
                _re.DOTALL,
            )
            if m:
                stream_suid, local_suid = m.group(1), m.group(2)
                result_full["error"] = (
                    f"{error2}\n"
                    f"[javapwner] SUID mismatch: target has {stream_suid}, "
                    f"local reggie.jar has {local_suid}. "
                    f"Place a reggie.jar with SUID={stream_suid} in lib/ "
                    f"or set JINI_CLASSPATH to override. "
                    f"(SUID {stream_suid} is typical for Sun Jini 2.x / early River.)"
                )

        return result_full

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _execute_inspector(
        self,
        classpath: str,
        host: str,
        port: int,
        timeout_ms: int,
    ) -> dict[str, Any]:
        """Low-level: launch JiniInspector with the given *classpath*."""
        cmd = [
            self._java,
            "-cp", classpath,
        ]

        # Security policy for RMI codebase class loading.
        if _SECURITY_POLICY.is_file():
            cmd.append(f"-Djava.security.policy={_SECURITY_POLICY}")
        cmd.append("-Djava.rmi.server.useCodebaseOnly=false")
        # 'allow' lets JiniInspector call System.setSecurityManager()
        # on Java 17-23; ignored on < 17, harmless on 24+.
        cmd.append("-Djava.security.manager=allow")

        # On JDK 9+ strong encapsulation blocks reflective access to
        # java.io.ObjectStreamClass.suid (needed for SUID-patching retry).
        # On JDK 8 this flag is unknown and must NOT be passed.
        if self.java_major_version >= 9:
            cmd.append("--add-opens=java.base/java.io=ALL-UNNAMED")

        cmd.extend(["JiniInspector", host, str(port), str(timeout_ms)])

        logger.debug("Running: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self._timeout,
                cwd=str(_LIB_DIR),
                env=self._env,
            )
        except subprocess.TimeoutExpired as exc:
            raise JvmBridgeError(
                f"JiniInspector timed out after {self._timeout}s "
                f"(target may be unreachable)"
            ) from exc
        except FileNotFoundError as exc:
            raise JvmBridgeError(f"java not found: {exc}") from exc

        stdout = proc.stdout.strip()
        stderr = proc.stderr.strip()

        if not stdout:
            detail = stderr if stderr else f"exit code {proc.returncode}"
            raise JvmBridgeError(f"JiniInspector produced no output: {detail}")

        try:
            result = json.loads(stdout)
        except json.JSONDecodeError as exc:
            raise JvmBridgeError(
                f"JiniInspector returned invalid JSON: {exc}\n"
                f"stdout: {stdout[:500]}\n"
                f"stderr: {stderr[:500]}"
            ) from exc

        # Attach stderr for debugging even on success
        if stderr:
            result["_stderr"] = stderr

        return result
