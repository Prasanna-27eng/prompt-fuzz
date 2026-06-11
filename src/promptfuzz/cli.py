"""prompt-fuzz CLI - async LLM jailbreak / guardrail-bypass fuzzer."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.table import Table

from . import payloads as payload_lib
from .engine import FuzzEngine, FuzzResult, summarize

app = typer.Typer(
    name="prompt-fuzz",
    help="Async LLM jailbreak / guardrail-bypass fuzzer for OpenAI-compatible chat endpoints.",
    no_args_is_help=True,
)
console = Console()


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Chat completions endpoint, e.g. http://localhost:8000/v1/chat/completions"),
    model: str = typer.Option("gpt-4", "--model", "-m", help="Model name sent in the request body"),
    api_key: Optional[str] = typer.Option(None, "--api-key", "-k", help="Bearer token for the Authorization header", envvar="PROMPT_FUZZ_API_KEY"),
    concurrency: int = typer.Option(10, "--concurrency", "-c", help="Number of concurrent requests"),
    timeout: float = typer.Option(30.0, "--timeout", help="Per-request timeout in seconds"),
    payloads_file: Optional[Path] = typer.Option(None, "--payloads", help="Custom payload library JSON (defaults to the built-in library)"),
    categories: Optional[str] = typer.Option(None, "--categories", help="Comma-separated category filter, e.g. jailbreak,exfiltration"),
    no_system_prompt: bool = typer.Option(False, "--no-system-prompt", help="Don't inject the canary system prompt; rely on refusal/marker detection only"),
    output_json: Optional[Path] = typer.Option(None, "--output", "-o", help="Write full results as JSON to this path"),
    aegistrace_url: Optional[str] = typer.Option(None, "--aegistrace-url", envvar="AEGISTRACE_URL", help="AegisTrace base URL to report bypassed payloads to"),
    aegistrace_key: Optional[str] = typer.Option(None, "--aegistrace-key", envvar="AEGISTRACE_INGEST_KEY", help="AegisTrace ingest API key"),
    show_responses: bool = typer.Option(False, "--show-responses", help="Print full response text for bypassed payloads"),
):
    """Fuzz TARGET with the jailbreak/prompt-injection payload library and report bypasses."""
    payload_set = (
        payload_lib.load_payloads_from_file(payloads_file)
        if payloads_file
        else payload_lib.load_builtin_payloads()
    )

    if categories:
        payload_set = payload_lib.filter_by_category(payload_set, categories.split(","))
        if not payload_set:
            console.print(f"[red]No payloads match categories: {categories}[/red]")
            raise typer.Exit(1)

    canary = None
    system_prompt = None
    if not no_system_prompt:
        canary = payload_lib.make_canary()
        system_prompt = payload_lib.make_system_prompt(canary)

    console.print(f"[*] Loading {len(payload_set)} payload(s)...")
    console.print(f"[*] Target: {target}  (model={model}, concurrency={concurrency})")
    if canary:
        console.print(f"[*] Canary system prompt active (token={canary})")

    engine = FuzzEngine(
        target=target,
        model=model,
        api_key=api_key,
        concurrency=concurrency,
        timeout=timeout,
        system_prompt=system_prompt,
        canary=canary,
    )

    results = asyncio.run(engine.run(payload_set))

    _print_results(results, show_responses=show_responses)
    stats = summarize(results)
    _print_summary(stats)

    if output_json:
        output_json.write_text(json.dumps([r.to_dict() for r in results], indent=2))
        console.print(f"[*] Full results written to {output_json}")

    if aegistrace_url and aegistrace_key:
        from . import reporter

        report = asyncio.run(reporter.send_to_aegistrace(aegistrace_url, aegistrace_key, target, results))
        console.print(
            f"[*] AegisTrace: reported {report['sent']} bypassed payload(s)"
            + (f", {report['failed']} failed" if report["failed"] else "")
        )

    if stats["bypassed"] > 0:
        raise typer.Exit(1)


@app.command(name="list-payloads")
def list_payloads_cmd(
    payloads_file: Optional[Path] = typer.Option(None, "--payloads", help="Custom payload library JSON (defaults to the built-in library)"),
    categories: Optional[str] = typer.Option(None, "--categories", help="Comma-separated category filter"),
):
    """List available payloads (id, category, severity, name)."""
    payload_set = (
        payload_lib.load_payloads_from_file(payloads_file)
        if payloads_file
        else payload_lib.load_builtin_payloads()
    )
    if categories:
        payload_set = payload_lib.filter_by_category(payload_set, categories.split(","))

    table = Table(title=f"prompt-fuzz payload library ({len(payload_set)} payloads)")
    table.add_column("ID", style="cyan")
    table.add_column("Category", style="magenta")
    table.add_column("Severity")
    table.add_column("Name")

    for p in payload_set:
        table.add_row(p["id"], p.get("category", ""), p.get("severity", ""), p.get("name", ""))

    console.print(table)
    console.print(f"\nCategories: {', '.join(payload_lib.list_categories(payload_set))}")


def _print_results(results: list[FuzzResult], show_responses: bool = False) -> None:
    for r in results:
        if r.error:
            console.print(f"[yellow][ERROR][/yellow]   {r.payload_id:<28} {r.error}")
        elif r.bypassed:
            console.print(f"[red][BYPASSED][/red] {r.payload_id:<28} reasons={','.join(r.reasons)}")
            if show_responses:
                console.print(f"           [dim]{r.response_text.strip()[:300]}[/dim]")
        else:
            console.print(f"[green][BLOCKED][/green]  {r.payload_id:<28} reasons={','.join(r.reasons)}")


def _print_summary(stats: dict) -> None:
    console.print("\n[bold]SCAN COMPLETE[/bold]")
    table = Table(show_header=True, header_style="bold")
    table.add_column("Metric")
    table.add_column("Value", justify="right")
    table.add_row("Total payloads", str(stats["total"]))
    table.add_row("Errors", str(stats["errors"]))
    table.add_row("Guardrails held (blocked)", str(stats["blocked"]))
    table.add_row("Bypassed", f"{stats['bypassed']} ({stats['bypass_rate'] * 100:.1f}%)")
    console.print(table)

    if stats["by_category"]:
        cat_table = Table(title="By category", show_header=True, header_style="bold")
        cat_table.add_column("Category")
        cat_table.add_column("Bypassed/Total", justify="right")
        for cat, c in sorted(stats["by_category"].items()):
            cat_table.add_row(cat, f"{c['bypassed']}/{c['total']}")
        console.print(cat_table)


if __name__ == "__main__":
    app()
