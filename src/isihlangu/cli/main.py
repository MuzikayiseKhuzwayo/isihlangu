"""Isihlangu CLI: Command-line interface for the Agentic SaaS Security Evaluation Harness."""

import asyncio
import json

import click
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from isihlangu import __version__
from isihlangu.core.config import settings
from isihlangu.core.guardrails import ScopeGuardrail
from isihlangu.core.types import TargetSpec, TargetType
from isihlangu.oracle.canary_server import CanaryManager, CanaryServer
from isihlangu.orchestrator.graph import EvaluationOrchestrator
from isihlangu.recon.mcp_inspector import MCPInspector
from isihlangu.remediation.sarif_exporter import SARIFExporter
from isihlangu.storage.database import DatabaseManager

console = Console()


@click.group()
@click.version_option(version=__version__, prog_name="isihlangu")
def main() -> None:
    """Isihlangu: The Shield - Deterministic Agentic SaaS Security Evaluation Harness."""


@main.command(name="init-db")
@click.option(
    "--db-url",
    default=None,
    help="Database connection string (defaults to ISIHLANGU_DATABASE_URL)",
)
def init_db(db_url: str | None) -> None:
    """Applies DDL migrations and verifies live schema in the datastore."""
    url = db_url or settings.database_url
    console.print(f"[bold cyan]Initializing Isihlangu Datastore at:[/bold cyan] {url}")

    async def _init() -> None:
        db = DatabaseManager(url)
        await db.apply_migrations()
        console.print("[bold green]Success:[/bold green] DDL migrations applied and verified.")

    asyncio.run(_init())


@main.command(name="inspect-mcp")
@click.argument("tools_file", type=click.Path(exists=True))
def inspect_mcp(tools_file: str) -> None:
    """Introspects an MCP server tools definition JSON file and audits schemas."""
    console.print(f"[bold cyan]Inspecting MCP Tools from:[/bold cyan] {tools_file}")

    with open(tools_file, encoding="utf-8") as f:
        data = json.load(f)

    inspector = MCPInspector()
    tools = inspector.parse_tools_response(data)

    table = Table(title=f"Discovered MCP Tools ({len(tools)})")
    table.add_column("Tool Name", style="bold")
    table.add_column("Sensitive", justify="center")
    table.add_column("Schema Deficiencies", style="yellow")

    for tool in tools:
        deficiencies = inspector.identify_schema_deficiencies(tool)
        def_str = "\n".join(f"- {d}" for d in deficiencies) if deficiencies else "[green]None[/green]"
        sens_str = "[red]YES[/red]" if tool.is_sensitive else "[dim]No[/dim]"
        table.add_row(tool.name, sens_str, def_str)

    console.print(table)


@main.command(name="canary")
@click.option("--host", default=None, help="Canary server host")
@click.option("--port", default=None, type=int, help="Canary server port")
def run_canary(host: str | None, port: int | None) -> None:
    """Runs the standalone Out-of-Band (OOB) Canary HTTP callback listener."""
    server_host = host or settings.canary_host
    server_port = port or settings.canary_port

    db = DatabaseManager(settings.database_url)
    server = CanaryServer(server_host, server_port, db)

    console.print(
        Panel(
            f"[bold green]Isihlangu OOB Canary Server Running[/bold green]\n"
            f"Host: {server_host}:{server_port}\n"
            f"Listening for cryptographic UUID callbacks at: http://{server_host}:{server_port}/c/<uuid>",
            title="Canary Listener",
        )
    )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    server.start(loop)

    try:
        loop.run_forever()
    except KeyboardInterrupt:
        console.print("[yellow]Shutting down canary server...[/yellow]")
        server.stop()


@main.command(name="scan")
@click.argument("target_file", type=click.Path(exists=True))
@click.option("--target-id", default="target_default", help="Unique ID for the target")
@click.option("--target-name", default="Agentic SaaS Target", help="Target human-readable name")
@click.option("--output-sarif", type=click.Path(), default=None, help="Output SARIF 2.1.0 file path")
def run_scan(
    target_file: str,
    target_id: str,
    target_name: str,
    output_sarif: str | None,
) -> None:
    """Executes the full evaluation pipeline against an MCP target definition."""
    console.print(f"[bold cyan]Starting Isihlangu Security Evaluation on:[/bold cyan] {target_name}")

    with open(target_file, encoding="utf-8") as f:
        tools_data = json.load(f)

    async def _scan() -> None:
        db = DatabaseManager(settings.database_url)
        await db.apply_migrations()

        guardrail = ScopeGuardrail(settings.allowed_cidrs, settings.allowed_domains)
        canary_mgr = CanaryManager(db, settings.canary_public_url)
        orchestrator = EvaluationOrchestrator(db, guardrail, canary_mgr)

        target = TargetSpec(
            id=target_id,
            name=target_name,
            target_type=TargetType.MCP_SERVER,
            base_url="http://127.0.0.1:8000",
            allowed_domains=settings.allowed_domains,
            allowed_cidrs=settings.allowed_cidrs,
        )

        findings = await orchestrator.run_mcp_evaluation(
            target=target, tools_response=tools_data, simulate_execution=True
        )

        table = Table(title=f"Deterministic Findings ({len(findings)})")
        table.add_column("Severity", justify="center")
        table.add_column("Finding Title", style="bold")
        table.add_column("OWASP Category", style="cyan")

        for f in findings:
            sev_color = "red" if f.severity.value in ["CRITICAL", "HIGH"] else "yellow"
            table.add_row(f"[{sev_color}]{f.severity.value}[/{sev_color}]", f.title, f.owasp_category.value)

        console.print(table)

        if output_sarif:
            sarif = SARIFExporter.to_sarif(findings, target_name)
            with open(output_sarif, "w", encoding="utf-8") as sf:
                json.dump(sarif, sf, indent=2)
            console.print(f"[bold green]SARIF report exported to:[/bold green] {output_sarif}")

    asyncio.run(_scan())


if __name__ == "__main__":
    main()
