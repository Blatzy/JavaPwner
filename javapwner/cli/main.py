"""Root Click group and global options for JavaPwner."""

import click

from javapwner.cli import jini_cmds
from javapwner.core.output import OutputFormatter


# Shared context object key
_CTX_KEY = "formatter"


@click.group()
@click.option("--verbose", "-v", is_flag=True, default=False,
              help="Enable verbose output (hex dumps, debug messages).")
@click.option("--json", "json_mode", is_flag=True, default=False,
              help="Output results as JSON.")
@click.option("--timeout", "-T", type=float, default=5.0, show_default=True,
              metavar="FLOAT", help="Network timeout in seconds.")
@click.option("--ysoserial", "ysoserial_path", default=None, metavar="PATH",
              help="Path to ysoserial-all.jar (overrides YSOSERIAL_PATH env var).")
@click.pass_context
def cli(ctx: click.Context, verbose: bool, json_mode: bool,
        timeout: float, ysoserial_path: str | None) -> None:
    """JavaPwner — Java middleware pentest toolkit."""
    ctx.ensure_object(dict)
    fmt = OutputFormatter(verbose=verbose, json_mode=json_mode)
    ctx.obj["formatter"] = fmt
    ctx.obj["timeout"] = timeout
    ctx.obj["ysoserial_path"] = ysoserial_path

    if not json_mode:
        fmt.print_banner()


cli.add_command(jini_cmds.jini)


# Stub groups for future modules
@cli.group()
def rmi() -> None:
    """RMI/JMX protocol commands (stub)."""


@rmi.command("scan")
@click.option("-t", "--target", required=True, metavar="HOST")
@click.option("-p", "--port", default=8282, show_default=True, type=int)
def rmi_scan(target: str, port: int) -> None:
    """Scan a Java RMI/JMX endpoint (not yet implemented)."""
    click.echo("[!] RMI scanner is not yet implemented.")


@cli.group()
def jboss() -> None:
    """JBoss protocol commands (stub)."""


@jboss.command("scan")
@click.option("-t", "--target", required=True, metavar="HOST")
@click.option("-p", "--port", default=4444, show_default=True, type=int)
def jboss_scan(target: str, port: int) -> None:
    """Scan a JBoss JNP endpoint (not yet implemented)."""
    click.echo("[!] JBoss scanner is not yet implemented.")
