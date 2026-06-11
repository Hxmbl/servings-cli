"""Servings CLI - PXE/Boot server."""

from pathlib import Path

import typer

from src.server import serve as _serve

app = typer.Typer()

# Boot directory candidates in resolution order
_BOOT_DIR_CANDIDATES = [
    # Termux / Android paths
    Path("/sdcard/Disk Images"),
    Path("/storage/emulated/0/Disk Images"),
    # Linux paths
    Path.home() / "boot",
    Path("/srv/tftp"),
    Path("/var/lib/tftpboot"),
]


def _resolve_boot_dir(explicit: str | None) -> str:
    """Resolve the boot directory.

    If the user passes --boot-dir, use that.
    Otherwise check common platform paths, fall back to cwd.
    """
    if explicit:
        return explicit

    for candidate in _BOOT_DIR_CANDIDATES:
        if candidate.exists():
            return str(candidate)

    return "."


@app.command()
def serve(
    port: int = typer.Option(4011, help="ProxyDHCP UDP port"),
    tftp_port: int = typer.Option(6969, help="TFTP UDP port (use 69 on rooted devices)"),
    http_port: int = typer.Option(8080, help="HTTP TCP port for iPXE payloads"),
    boot_dir: str = typer.Option(None, help="Directory containing boot files (default: auto-detect)"),
) -> None:
    """Start all three PXE boot servers (ProxyDHCP + TFTP + HTTP)."""
    resolved = _resolve_boot_dir(boot_dir)
    _serve(port=port, tftp_port=tftp_port, http_port=http_port, boot_dir=resolved)


if __name__ == "__main__":
    app()
