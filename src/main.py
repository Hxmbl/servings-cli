"""servings-cli — Portable PXE/Boot server.

Root mode is the default (full DHCP on port 67, TFTP on port 69).
Use --no-root for ProxyDHCP on port 4011 (works alongside your existing DHCP).
Use --android for Termux/Android-specific paths and IP auto-detection.
"""

import os
import sys
from pathlib import Path

_project_root = str(Path(__file__).resolve().parent.parent)
if _project_root not in sys.path:
    sys.path.insert(0, _project_root)

import typer

from src.server import serve as _serve

app = typer.Typer()

_BOOT_DIR_CANDIDATES = [
    Path.home() / "servings-boot",
    Path.home() / "tftp",
    Path("/srv/tftp"),
    Path("/var/lib/tftpboot"),
]

_ANDROID_BOOT_DIR_CANDIDATES = [
    Path("/sdcard/Disk Images"),
    Path("/storage/emulated/0/Disk Images"),
]


def _resolve_boot_dir(explicit: str | None, android: bool = False) -> str:
    if explicit:
        return explicit
    candidates = list(_BOOT_DIR_CANDIDATES)
    if android:
        candidates.extend(_ANDROID_BOOT_DIR_CANDIDATES)
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return "."


def _detect_android_ip() -> str | None:
    import subprocess
    for iface in ("rndis0", "usb0", "eth0"):
        try:
            out = subprocess.check_output(
                ["ip", "-4", "addr", "show", iface],
                stderr=subprocess.DEVNULL, timeout=3,
            ).decode()
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    return line.split()[1].split("/")[0]
        except (subprocess.CalledProcessError, FileNotFoundError, OSError):
            continue
    return None


@app.command()
def serve(
    port: int = typer.Option(4011, help="DHCP/ProxyDHCP UDP port (only used with --no-root)"),
    tftp_port: int = typer.Option(6969, help="TFTP UDP port (only used with --no-root)"),
    http_port: int = typer.Option(8080, help="HTTP TCP port for iPXE payloads"),
    boot_dir: str = typer.Option(None, help="Directory containing boot files (default: auto-detect)"),
    no_root: bool = typer.Option(False, "--no-root", help="Non-root mode: ProxyDHCP on 4011 + TFTP on 6969"),
    server_ip: str = typer.Option(None, help="Server IP on the client network (default: 192.168.42.129)"),
    boot_file: str = typer.Option("undionly.kpxe", help="Boot file to serve"),
    android: bool = typer.Option(False, "--android", help="Android/Termux mode: scan shared storage, auto-detect USB IP"),
) -> None:
    """Start PXE boot servers.

    Root mode (default): full DHCP on port 67 + TFTP on port 69.
    Requires sudo/root on your machine.

    Non-root mode: ProxyDHCP on 4011 + TFTP on 6969.
    Works alongside your existing DHCP server.

    Examples:
      sudo servings-cli serve
      sudo servings-cli serve --server-ip 192.168.1.100
      servings-cli serve --no-root
      servings-cli serve --android --no-root
    """
    if not server_ip:
        if android:
            detected = _detect_android_ip()
            if detected:
                server_ip = detected
                print(f"[*] Auto-detected Android USB tethering IP: {server_ip}")
            else:
                server_ip = "192.168.42.129"
        else:
            server_ip = "192.168.42.129"

    resolved = _resolve_boot_dir(boot_dir, android=android)
    _serve(
        port=port,
        tftp_port=tftp_port,
        http_port=http_port,
        boot_dir=resolved,
        root_mode=not no_root,
        server_ip=server_ip,
        boot_file=boot_file,
        android=android,
    )


def entry_point() -> None:
    args = sys.argv[1:]
    if args and not args[0].startswith("-"):
        args = args[1:]
    app(args)


if __name__ == "__main__":
    entry_point()
