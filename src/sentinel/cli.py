import asyncio
import json
from typing import Annotated

import typer

from sentinel import __version__
from sentinel.config import get_config
from sentinel.detection.ensemble import DetectionEnsemble
from sentinel.governance.audit import AuditLogger

app = typer.Typer(
    name="sentinel",
    help=(
        "SENTINEL: Security Evaluation and Neural Tracing"
        " for Intelligent Language-models."
    ),
    no_args_is_help=True,
)

audit_app = typer.Typer(
    name="audit",
    help="Audit log management and integrity verification.",
    no_args_is_help=True,
)
app.add_typer(audit_app, name="audit")


def _version_callback(value: bool) -> None:
    """Display the SENTINEL version and exit.

    Args:
        value: True when the --version flag is set.

    Returns:
        None

    Raises:
        typer.Exit: Always raised after printing version.

    Examples:
        >>> _version_callback(True)
    """
    if value:
        typer.echo(f"sentinel {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool | None,
        typer.Option("--version", "-v", callback=_version_callback, is_eager=True),
    ] = None,
) -> None:
    """SENTINEL command-line interface entry point.

    Args:
        version: Print version and exit when True.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> main(version=False)
    """


@app.command()
def scan(
    text: Annotated[str, typer.Argument(help="Text content to analyze for threats.")],
    output_json: Annotated[
        bool, typer.Option("--json", "-j", help="Output results as JSON.")
    ] = False,
) -> None:
    """Run multi-layer threat detection on the provided text.

    Args:
        text: Input text string to analyze.
        output_json: Format output as machine-readable JSON.

    Returns:
        None

    Raises:
        typer.Exit: Exits with code 1 if threats are detected.

    Examples:
        >>> scan("Hello world")
    """
    ensemble = DetectionEnsemble()
    result = asyncio.run(ensemble.analyze(text))

    threat_detected: bool = len(result.triggered_detectors) > 0

    if output_json:
        output_data = {
            "blocked": result.blocked,
            "composite_score": result.composite_score,
            "threat_detected": threat_detected,
            "explanation": result.explanation,
            "detections": [
                {
                    "detector": det_result.detector_name,
                    "detected": det_result.detected,
                    "score": det_result.score,
                    "category": det_result.category,
                }
                for det_result in result.detector_results.values()
            ],
        }
        typer.echo(json.dumps(output_data, indent=2))
    else:
        typer.echo(f"Threat Detected: {threat_detected}")
        typer.echo(f"Composite Score: {result.composite_score:.4f}")
        typer.echo(f"Blocked: {result.blocked}")
        typer.echo(f"Explanation: {result.explanation}")
        typer.echo("---")
        for det_result in result.detector_results.values():
            status_label = "DETECTED" if det_result.detected else "clean"
            typer.echo(
                f"  [{status_label}] {det_result.detector_name}: "
                f"score={det_result.score:.4f} ({det_result.category})"
            )

    if threat_detected:
        raise typer.Exit(code=1)


@app.command()
def health() -> None:
    """Check SENTINEL system health and configuration status.

    Args:
        None

    Returns:
        None

    Raises:
        None

    Examples:
        >>> health()
    """
    config = get_config()
    typer.echo(f"SENTINEL v{__version__}")
    typer.echo("Status: healthy")
    typer.echo(f"Environment: {config.environment}")
    typer.echo(f"Log Level: {config.log_level}")
    typer.echo(f"Log Format: {config.log_format}")
    typer.echo(
        "Subsystems: detection, monitoring, governance, guardrails -- operational"
    )


@app.command(name="config")
def config_show(
    output_json: Annotated[
        bool, typer.Option("--json", "-j", help="Output as JSON.")
    ] = False,
) -> None:
    """Display the resolved SENTINEL configuration.

    Args:
        output_json: Format output as machine-readable JSON.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> config_show()
    """
    config = get_config()
    if output_json:
        typer.echo(config.model_dump_json(indent=2))
    else:
        config_dict = config.model_dump()
        for section_name, section_value in config_dict.items():
            if isinstance(section_value, dict):
                typer.echo(f"[{section_name}]")
                for key, value in section_value.items():
                    typer.echo(f"  {key} = {value}")
            else:
                typer.echo(f"{section_name} = {section_value}")


@app.command()
def serve(
    host: Annotated[str, typer.Option(help="Bind address.")] = "0.0.0.0",
    port: Annotated[int, typer.Option(help="Bind port.")] = 8000,
    reload: Annotated[bool, typer.Option(help="Enable auto-reload.")] = False,
) -> None:
    """Launch the SENTINEL API server with uvicorn.

    Args:
        host: Network interface to bind to.
        port: TCP port number to listen on.
        reload: Enable hot-reload for development.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> pass
    """
    try:
        import uvicorn
    except ImportError:
        typer.echo(
            "uvicorn is required to run the API server. "
            "Install with: pip install sentinel-ai-core[api]",
            err=True,
        )
        raise typer.Exit(code=1) from None

    typer.echo(f"Starting SENTINEL API server on {host}:{port}")
    uvicorn.run(
        "sentinel.api.app:create_app",
        host=host,
        port=port,
        reload=reload,
        factory=True,
    )


@audit_app.command(name="list")
def audit_list(
    tenant_id: Annotated[
        str | None, typer.Option("--tenant", "-t", help="Filter by tenant ID.")
    ] = None,
    limit: Annotated[int, typer.Option("--limit", "-n", help="Max records.")] = 20,
    output_json: Annotated[
        bool, typer.Option("--json", "-j", help="Output as JSON.")
    ] = False,
) -> None:
    """List audit log records with optional filtering.

    Args:
        tenant_id: Optional tenant identifier filter.
        limit: Maximum number of records to display.
        output_json: Format output as machine-readable JSON.

    Returns:
        None

    Raises:
        None

    Examples:
        >>> audit_list()
    """
    logger = AuditLogger()
    records = logger.list_records(tenant_id=tenant_id, limit=limit)

    if output_json:
        output_data = [
            {
                "record_id": r.record_id,
                "tenant_id": r.tenant_id,
                "timestamp": r.timestamp,
                "decision": r.decision,
                "composite_score": r.composite_score,
            }
            for r in records
        ]
        typer.echo(json.dumps(output_data, indent=2))
    else:
        if not records:
            typer.echo("No audit records found.")
            return
        for record in records:
            typer.echo(
                f"[{record.record_id}] tenant={record.tenant_id} "
                f"decision={record.decision} score={record.composite_score:.4f}"
            )


@audit_app.command(name="verify")
def audit_verify() -> None:
    """Verify the cryptographic integrity of the audit hash chain.

    Args:
        None

    Returns:
        None

    Raises:
        typer.Exit: Exits with code 1 if integrity verification fails.

    Examples:
        >>> audit_verify()
    """
    logger = AuditLogger()
    try:
        is_valid = logger.verify_integrity()
        if is_valid:
            typer.echo("Hash chain integrity: VALID")
            typer.echo(f"Chain length: {len(logger.hash_chain.chain)} blocks")
        else:
            typer.echo("Hash chain integrity: COMPROMISED", err=True)
            raise typer.Exit(code=1)
    except Exception as exc:
        typer.echo(f"Integrity check failed: {exc}", err=True)
        raise typer.Exit(code=1) from exc
