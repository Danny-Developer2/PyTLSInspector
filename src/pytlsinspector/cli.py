"""Interfaz de línea de comandos de PyTLSInspector (Typer + Rich)."""

from __future__ import annotations

import asyncio
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from pytlsinspector import __version__
from pytlsinspector.config import AuditConfig
from pytlsinspector.core.auditor import Auditor
from pytlsinspector.exceptions import PyTLSInspectorError
from pytlsinspector.export import export_result
from pytlsinspector.models import Severity, TLSAuditResult
from pytlsinspector.utils.logger import setup_logger
from pytlsinspector.utils.validators import (
    ensure_authorized,
    ensure_path_writable,
    load_scope_file,
    validate_target,
)

app = typer.Typer(
    name="pytlsinspector",
    help="PyTLSInspector — auditoría de configuración SSL/TLS (solo auditorías autorizadas).",
    add_completion=False,
    no_args_is_help=True,
)
console = Console()
err_console = Console(stderr=True)

AVISO_LEGAL = (
    "[yellow]AVISO:[/yellow] esta herramienta está pensada exclusivamente para "
    "auditorías autorizadas. Comprueba que dispones de autorización expresa."
)

SEVERITY_ORDER = [
    Severity.CONFIRMADO,
    Severity.PROBABLE,
    Severity.POTENCIAL,
    Severity.INDICIO,
    Severity.RECOMENDACION,
]


@app.command()
def scan(
    target: str = typer.Argument(..., help="Host o host:puerto del objetivo autorizado."),
    scope_file: Path | None = typer.Option(
        None, "--scope", help="Fichero JSON con el alcance autorizado."
    ),
    confirm_authorized: bool = typer.Option(
        False, "--confirm-authorized", help="Declara que se dispone de autorización expresa."
    ),
    port: int | None = typer.Option(None, "--port", "-p", help="Puerto TLS (por defecto 443)."),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Tiempo de espera en segundos."),
    concurrency: int = typer.Option(4, "--concurrency", "-c", help="Pruebas simultáneas."),
    rate_limit: float = typer.Option(8.0, "--rate-limit", help="Peticiones por segundo."),
    max_ciphers: int = typer.Option(32, "--max-ciphers", help="Límite de conjuntos a probar."),
    output: Path | None = typer.Option(
        None, "--output", "-o", help="Ruta del informe (se añade la extensión)."
    ),
    format: str = typer.Option("json", "--format", "-f", help="Formato: json, csv o html."),
    log_file: Path | None = typer.Option(None, "--log-file", help="Volcar el registro a fichero."),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Registro detallado."),
    no_ciphers: bool = typer.Option(
        False, "--no-ciphers", help="No enumerar conjuntos de cifrado."
    ),
    ignore_tls_errors: bool = typer.Option(
        False, "--ignore-tls-errors", help="No verificar el certificado (solo laboratorio)."
    ),
) -> None:
    """Ejecuta una auditoría TLS sobre el objetivo autorizado."""
    setup_logger("DEBUG" if verbose else "INFO", log_file)
    console.print(AVISO_LEGAL)

    try:
        endpoint = validate_target(target)
        scope = load_scope_file(scope_file)
        ensure_authorized(endpoint.host, endpoint.port, scope, confirm_authorized)
        config = AuditConfig(
            target=endpoint.host,
            port=port or endpoint.port,
            timeout=timeout,
            concurrency=concurrency,
            rate_limit=rate_limit,
            max_ciphers=max_ciphers,
            scope=scope,
            scope_file=str(scope_file) if scope_file else None,
            confirm_authorized=confirm_authorized,
            probe_ciphers=not no_ciphers,
            verify_tls=not ignore_tls_errors,
        )
        if output is not None:
            ensure_path_writable(output)
    except PyTLSInspectorError as exc:
        err_console.print(f"[red]Error de validación:[/red] {exc}")
        raise typer.Exit(code=2) from exc

    try:
        result = asyncio.run(Auditor(config).run())
    except KeyboardInterrupt:  # pragma: no cover - interrupción manual
        err_console.print("\n[yellow]Ejecución interrumpida por el usuario.[/yellow]")
        raise typer.Exit(code=130) from None
    except PyTLSInspectorError as exc:
        err_console.print(f"[red]Error durante la auditoría:[/red] {exc}")
        raise typer.Exit(code=1) from exc

    _print_summary(result)

    if output is not None:
        try:
            written = export_result(result, output, format)
        except PyTLSInspectorError as exc:
            err_console.print(f"[red]Error al exportar:[/red] {exc}")
            raise typer.Exit(code=1) from exc
        console.print(f"[green]Informe guardado en:[/green] {written}")


def _print_summary(result: TLSAuditResult) -> None:
    """Muestra un resumen en tabla por consola."""
    console.print(f"\n[bold]PyTLSInspector[/bold] — objetivo: {result.target}:{result.port}")
    console.print(
        f"Conexión: {'establecida' if result.connected else 'no establecida'} · "
        f"Duración: {result.duration_seconds:.2f}s"
    )
    if result.negotiated_protocol:
        console.print(
            f"Protocolo negociado: {result.negotiated_protocol} · "
            f"Cifrado: {result.negotiated_cipher or '—'}"
        )
    if result.chain and result.chain.leaf:
        leaf = result.chain.leaf
        console.print(
            f"Certificado: {leaf.common_name or leaf.subject} · "
            f"caduca en {leaf.days_until_expiry} días"
        )

    table = Table(title="Hallazgos por severidad")
    table.add_column("Severidad", style="cyan")
    table.add_column("Cantidad", justify="right")
    for severity in SEVERITY_ORDER:
        table.add_row(severity.value, str(len(result.findings_by_severity(severity))))
    console.print(table)

    enabled = [p.name for p in result.protocols if p.enabled]
    if enabled:
        console.print("Protocolos habilitados: " + ", ".join(enabled))
    deprecated = [p.name for p in result.protocols if p.enabled and p.deprecated]
    if deprecated:
        console.print(f"[yellow]Protocolos obsoletos habilitados: {', '.join(deprecated)}[/yellow]")


@app.command()
def version() -> None:
    """Muestra la versión de PyTLSInspector."""
    console.print(f"PyTLSInspector {__version__}")


def main() -> None:
    """Punto de entrada de la CLI."""
    app()


if __name__ == "__main__":  # pragma: no cover
    main()
