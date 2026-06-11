"""Servings CLI — PXE/Boot server.

Run as root for full USB tethering PXE support:
  su -c killall dnsmasq
  python src/main.py serve --root

Without root, the server runs in limited ProxyDHCP mode. Android's built-in
DHCP doesn't advertise PXE options, so the PC won't discover the boot server.
"""

import sys
from pathlib import Path

# Ensure the project root is on sys.path so absolute package imports
# (from src.xxx import yyy) work regardless of invocation method.
_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

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
    port: int = typer.Option(4011, help="ProxyDHCP UDP port (non-root mode)"),
    tftp_port: int = typer.Option(6969, help="TFTP UDP port (use 69 on rooted devices)"),
    http_port: int = typer.Option(8080, help="HTTP TCP port for iPXE payloads"),
    boot_dir: str = typer.Option(None, help="Directory containing boot files (default: auto-detect)"),
    root: bool = typer.Option(False, "--root", "-r", help="Root mode: full DHCP server on port 67"),
    server_ip: str = typer.Option("192.168.42.129", help="Phone's IP on USB network (root mode)"),
    boot_file: str = typer.Option("undionly.kpxe", help="Boot file to serve (root mode)"),
) -> None:
    """Start PXE boot servers.

    Root mode (requires su):
      Kill Android's dnsmasq first, then run with --root.
      The server binds port 67 and handles full DHCP + PXE.

    Non-root mode:
      ProxyDHCP on port 4011. Limited — Android's DHCP doesn't
      advertise PXE options, so the PC may not discover this server.

    Examples:
      servings serve --root
      servings serve --root --server-ip 192.168.42.129
      servings serve  # non-root, limited
    """
    resolved = _resolve_boot_dir(boot_dir)
    _serve(
        port=port,
        tftp_port=tftp_port,
        http_port=http_port,
        boot_dir=resolved,
        root_mode=root,
        server_ip=server_ip,
        boot_file=boot_file,
    )


if __name__ == "__main__":
    app()
