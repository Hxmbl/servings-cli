"""Servings CLI - PXE/Boot server for Termux."""

from pathlib import Path

import typer

from src.logic import serve as _serve

app = typer.Typer()

# Termux storage paths in resolution order
_TERMUX_STORAGE_PATHS = [
    Path("/sdcard/Disk Images"),
    Path("/storage/emulated/0/Disk Images"),
]


def _resolve_boot_dir(explicit: str | None) -> str:
    """Resolve the boot directory.

    If the user passes --boot-dir, use that.
    Otherwise check common Termux storage paths, fall back to cwd.
    """
    if explicit:
        return explicit

    for candidate in _TERMUX_STORAGE_PATHS:
        if candidate.exists():
            return str(candidate)

    return "."


@app.command()
def serve(
    port: int = typer.Option(4011, help="ProxyDHCP UDP port"),
    tftp_port: int = typer.Option(6969, help="TFTP UDP port (use 69 on rooted devices)"),
    http_port: int = typer.Option(8080, help="HTTP TCP port for iPXE payloads"),
    boot_dir: str = typer.Option(None, help="Directory containing boot files (default: auto-detect Termux storage)"),
) -> None:
    """Start all three PXE boot servers (ProxyDHCP + TFTP + HTTP)."""
    resolved = _resolve_boot_dir(boot_dir)
    _serve(port=port, tftp_port=tftp_port, http_port=http_port, boot_dir=resolved)


if __name__ == "__main__":
    app()
