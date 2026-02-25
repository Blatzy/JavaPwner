"""OutputFormatter — rich-based output with normal/verbose/json/quiet modes."""

from __future__ import annotations

import json
import sys
from typing import Any

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
