"""OutputFormatter — rich-based output with normal/verbose/json/quiet modes."""

from __future__ import annotations

import json
import sys
from contextlib import contextmanager
from typing import Any, Generator

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from javapwner import VERSION


class OutputFormatter:
    """Unified output handler for all JavaPwner commands."""

    def __init__(self, verbose: bool = False, json_mode: bool = False,
                 quiet: bool = False):
        self.verbose = verbose
        self.json_mode = json_mode
        self.quiet = quiet
        self._console = Console(stderr=False, highlight=False)
        self._err = Console(stderr=True, highlight=False)

    # ------------------------------------------------------------------
    # Low-level message methods
    # ------------------------------------------------------------------

    def info(self, msg: str) -> None:
        if not self.quiet and not self.json_mode:
            self._console.print(f"[cyan][*][/cyan] {msg}")

    def success(self, msg: str) -> None:
        if not self.quiet and not self.json_mode:
            self._console.print(f"[green][+][/green] {msg}")

    def warning(self, msg: str) -> None:
        if not self.json_mode:
            self._console.print(f"[yellow][!][/yellow] {msg}")

    def error(self, msg: str) -> None:
        self._err.print(f"[red][-][/red] {msg}")

    def debug(self, msg: str) -> None:
        if self.verbose and not self.json_mode:
            self._console.print(f"[dim][~][/dim] [dim]{msg}[/dim]")

    # ------------------------------------------------------------------
    # Structured output
    # ------------------------------------------------------------------

    @property
    def console(self) -> Console:
        """Direct access to the Rich Console (for Status, Live, etc.)."""
        return self._console

    @contextmanager
    def status(self, msg: str) -> Generator[None, None, None]:
        """Context manager: display a Rich spinner while work is in progress.

        In JSON or quiet mode the spinner is suppressed.
        """
        if self.json_mode or self.quiet:
            yield
            return
        with self._console.status(f"[cyan]{msg}[/cyan]"):
            yield

    def section(self, title: str) -> None:
        """Print a section rule to visually separate output phases."""
        if self.json_mode or self.quiet:
            return
        self._console.print()
        self._console.rule(f"[bold cyan]{title}[/bold cyan]", style="cyan")

    def print_banner(self) -> None:
        if self.quiet or self.json_mode:
            return
        banner = Text()
        banner.append("JavaPwner", style="bold red")
        banner.append(f" v{VERSION}", style="bold white")
        banner.append("  —  Java Middleware Pentest Toolkit", style="dim")
        self._console.print(Panel(banner, expand=False, border_style="red"))

    def print_scan_result(self, result: dict[str, Any]) -> None:
        if self.json_mode:
            self.print_json(result)
            return

        host = result.get("host", "?")
        port = result.get("port", "?")
        is_open = result.get("is_open", False)
        is_jrmp = result.get("is_jrmp", False)
        has_unicast = result.get("has_unicast_response", False)
        groups = result.get("groups", [])
        fingerprint = result.get("fingerprint_strings", [])
        jrmp_version = result.get("jrmp_version")
        jrmp_host = result.get("jrmp_host")
        jrmp_port = result.get("jrmp_port")
        unicast_ver = result.get("unicast_version")

        self._console.print()
        self._console.rule(f"[bold]Scan Result — {host}:{port}[/bold]")

        status = "[green]OPEN[/green]" if is_open else "[red]CLOSED[/red]"
        self._console.print(f"  Port status   : {status}")

        if is_jrmp:
            jrmp_info = f"[green]YES[/green]  (version={jrmp_version}, reported={jrmp_host}:{jrmp_port})"
        else:
            jrmp_info = "[red]NO[/red]"
        self._console.print(f"  JRMP detected : {jrmp_info}")

        if has_unicast:
            self._console.print(
                f"  Unicast reply : [green]YES[/green]  (protocol v{unicast_ver})"
            )
        else:
            self._console.print("  Unicast reply : [red]NO[/red]")

        if groups:
            self._console.print(f"  Groups        : {', '.join(groups)}")

        if self.verbose and fingerprint:
            self._console.print("  Fingerprint strings:")
            for s in fingerprint:
                self._console.print(f"    [dim]{s}[/dim]")

        self._console.print()

    def print_services_table(self, services: list[dict[str, Any]]) -> None:
        if self.json_mode:
            self.print_json(services)
            return

        table = Table(title="Enumerated Services", border_style="cyan")
        table.add_column("Class / Interface", style="cyan", no_wrap=False)
        table.add_column("Source", style="dim")

        for svc in services:
            table.add_row(svc.get("name", "?"), svc.get("source", "heuristic"))

        self._console.print(table)

    def print_hex_dump(self, data: bytes, label: str = "") -> None:
        if not self.verbose or self.json_mode:
            return
        if label:
            self._console.print(f"[dim]--- {label} ---[/dim]")
        for i in range(0, len(data), 16):
            chunk = data[i: i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk)
            asc_part = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            self._console.print(
                f"[dim]{i:04x}  {hex_part:<47}  {asc_part}[/dim]"
            )

    def print_json(self, data: Any) -> None:
        print(json.dumps(data, indent=2, default=str))

    # ------------------------------------------------------------------
    # Deep enumeration display
    # ------------------------------------------------------------------

    def print_class_descriptors(self, descriptors: list[dict[str, Any]]) -> None:
        """Print a table of class descriptors (TC_CLASSDESC / TC_PROXYCLASSDESC)."""
        if self.json_mode:
            self.print_json(descriptors)
            return
        if not descriptors:
            return

        table = Table(title="Class Descriptors", border_style="cyan")
        table.add_column("Type", style="dim", width=7)
        table.add_column("Name / Interfaces", style="cyan", no_wrap=False)
        table.add_column("Serial UID", style="dim", width=22)

        for desc in descriptors:
            if desc["type"] == "class":
                table.add_row("class", desc["name"], str(desc.get("uid", "")))
            elif desc["type"] == "proxy":
                ifaces = ", ".join(desc.get("interfaces", []))
                table.add_row("proxy", ifaces, "")

        self._console.print(table)

    def print_system_info(self, info: dict[str, Any]) -> None:
        """Print extracted system information."""
        if self.json_mode:
            self.print_json(info)
            return

        if info.get("hostnames"):
            self._console.print(
                f"  Hostnames       : [cyan]{', '.join(info['hostnames'])}[/cyan]"
            )
        if info.get("java_properties"):
            self._console.print("  Java properties :")
            for prop in info["java_properties"]:
                self._console.print(f"    [dim]{prop}[/dim]")
        if info.get("file_paths"):
            self._console.print("  File paths      :")
            for path in info["file_paths"]:
                self._console.print(f"    [yellow]{path}[/yellow]")
        if info.get("codebase_annotations"):
            self._console.print("  Codebase annotations:")
            for annot in info["codebase_annotations"]:
                self._console.print(
                    f"    [cyan]{annot['class']}[/cyan] → [green]{annot['url']}[/green]"
                )

    def print_codebase_exploit(self, result: dict[str, Any]) -> None:
        """Print results of HTTP codebase server exploitation."""
        if self.json_mode:
            self.print_json(result)
            return

        url = result.get("base_url", "?")
        reachable = result.get("server_reachable", False)
        server = result.get("server_header", "")

        if not reachable:
            self._console.print(f"  [red]UNREACHABLE[/red] {url}")
            return

        self._console.print(f"  [green]REACHABLE[/green] {url}")
        if server:
            self._console.print(f"    Server: [dim]{server}[/dim]")

        entries = result.get("directory_listing", [])
        if entries:
            self._console.print(f"    Directory listing ({len(entries)} entries):")
            for entry in entries[:20]:
                self._console.print(f"      [cyan]{entry}[/cyan]")
            if len(entries) > 20:
                self._console.print(f"      [dim]... and {len(entries) - 20} more[/dim]")

        probed = result.get("probed_paths", [])
        if probed:
            self._console.print("    Accessible codebase paths:")
            for p in probed:
                self._console.print(
                    f"      [green]{p['path']}[/green] "
                    f"({p['content_length']} bytes)"
                )

        if result.get("traversal_vulnerable"):
            technique = result.get("working_traversal", "?")
            depth = result.get("working_depth", "?")
            self._console.print(
                f"    [bold red]!! PATH TRAVERSAL VULNERABLE !![/bold red]"
                f"  (technique: {technique} × {depth})"
            )

        files = result.get("readable_files", [])
        if files:
            self._console.print(
                f"    [bold red]Readable files ({len(files)}):[/bold red]"
            )
            for f in files:
                self._console.print(
                    f"      [red]{f['path']}[/red] "
                    f"({f['content_length']} bytes, {f['technique']})"
                )

    def print_file_content(self, path: str, content: str, technique: str = "") -> None:
        """Print the content of a file read from the target."""
        if self.json_mode:
            self.print_json({"path": path, "content": content, "technique": technique})
            return

        tech_info = f" [dim](via {technique})[/dim]" if technique else ""
        self._console.print(
            Panel(
                Text(content),
                title=f"{path}{tech_info}",
                border_style="red",
                expand=False,
            )
        )

    def print_assessment(self, assessment: dict[str, Any]) -> None:
        """Print an exploitation assessment with coloured risk panel."""
        if self.json_mode:
            self.print_json(assessment)
            return

        risk = assessment.get("risk_level", "INFO")
        risk_colors = {
            "CRITICAL": "bold red",
            "HIGH": "red",
            "MEDIUM": "yellow",
            "LOW": "cyan",
            "INFO": "dim",
        }
        risk_style = risk_colors.get(risk, "dim")

        # Header
        self._console.print()
        jdk = assessment.get("jdk_estimate", "unknown")
        fw = assessment.get("framework", "unknown")
        dgc = assessment.get("dgc_state", "unknown")
        confidence = assessment.get("jdk_confidence", "none")

        lines = Text()
        lines.append(f"Risk Level  : ", style="bold")
        lines.append(f"{risk}\n", style=risk_style)
        lines.append(f"JDK Version : ", style="bold")
        lines.append(f"{jdk}", style="cyan")
        lines.append(f" (confidence: {confidence})\n", style="dim")
        lines.append(f"Framework   : ", style="bold")
        lines.append(f"{fw}\n", style="cyan")
        lines.append(f"DGC State   : ", style="bold")
        dgc_style = "green" if dgc == "unfiltered" else "yellow" if dgc == "filtered" else "dim"
        lines.append(f"{dgc}", style=dgc_style)

        self._console.print(Panel(
            lines,
            title="[bold]Exploitation Assessment[/bold]",
            border_style=risk_style,
            expand=False,
        ))

        # Attack vectors
        vectors = assessment.get("vectors", [])
        if not vectors:
            self._console.print("  [dim]No specific attack vectors identified.[/dim]")
            return

        for i, v in enumerate(vectors, 1):
            sev = v.get("severity", "INFO")
            sev_style = risk_colors.get(sev, "dim")
            self._console.print(
                f"\n  [{sev_style}][{sev}][/{sev_style}] "
                f"[bold]{v.get('title', '?')}[/bold]"
            )
            self._console.print(f"    {v.get('detail', '')}")
            action = v.get("action", "")
            if action:
                for line in action.split("\n"):
                    self._console.print(f"    [green]→ {line}[/green]")
