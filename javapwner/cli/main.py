"""Root Click group and global options for JavaPwner."""

import sys

import click

from javapwner.cli import jini_cmds, rmi_cmds, jboss_cmds
from javapwner.core.output import OutputFormatter


# Shared context object key
_CTX_KEY = "formatter"


@click.group(invoke_without_command=True)
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable verbose output (hex dumps, debug messages).")
@click.option("--json", "json_mode", is_flag=True, default=False,
              help="Output results as JSON.")
@click.option("--timeout", "-T", type=float, default=5.0, show_default=True,
              metavar="FLOAT", help="Network timeout in seconds.")
@click.option("--ysoserial", "ysoserial_path", default=None, metavar="PATH",
              help="Path to ysoserial-all.jar (overrides YSOSERIAL_PATH env var).")
@click.option("--ysoserial-check", is_flag=True, default=False,
              help="Verify ysoserial.jar is available and list gadgets, then exit.")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, json_mode: bool,
        timeout: float, ysoserial_path: str | None,
        ysoserial_check: bool) -> None:
    """JavaPwner — Java middleware pentest toolkit."""
    ctx.ensure_object(dict)
    fmt = OutputFormatter(verbose=verbose, json_mode=json_mode)
    ctx.obj["formatter"] = fmt
    ctx.obj["timeout"] = timeout
    ctx.obj["ysoserial_path"] = ysoserial_path

    if ysoserial_check:
        _do_ysoserial_check(fmt, ysoserial_path)
        ctx.exit(0)

    if not json_mode:
        fmt.print_banner()


def _do_ysoserial_check(fmt: OutputFormatter, jar_path: str | None) -> None:
    """Verify ysoserial.jar availability and print gadget list."""
    from javapwner.core.payload import YsoserialWrapper
    from javapwner.exceptions import PayloadError

    try:
        wrapper = YsoserialWrapper(jar_path=jar_path)
    except PayloadError as exc:
        fmt.error(str(exc))
        sys.exit(1)

    fmt.success(f"ysoserial.jar found: {wrapper.jar_path}")
    try:
        gadgets = wrapper.list_gadgets()
        if gadgets:
            fmt.success(f"{len(gadgets)} gadget chain(s) available:")
            for g in gadgets:
                fmt.info(f"  {g}")
        else:
            fmt.warning("No gadgets found — check ysoserial.jar version.")
    except PayloadError as exc:
        fmt.error(f"Failed to list gadgets: {exc}")
        sys.exit(1)


cli.add_command(jini_cmds.jini)
cli.add_command(rmi_cmds.rmi)
cli.add_command(jboss_cmds.jboss)
