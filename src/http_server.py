"""HTTP server — streams boot payloads (kernel, initrd, ISOs) to iPXE clients.

This is the third stage of PXE boot:
1. iPXE loads from TFTP (port 6969)
2. iPXE fetches boot.cfg from this HTTP server (port 8080)
3. boot.cfg tells iPXE which kernel/initrd/ISO to load
4. iPXE loads the OS image via HTTP

HTTP is used for heavy payloads — TFTP is too slow for kernels/ISOs.
"""

import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


# File extensions → MIME types — iPXE needs correct Content-Type to load files
MIME_TYPES = {
    ".kernel": "application/octet-stream",
    ".bzImage": "application/octet-stream",
    ".vmlinuz": "application/octet-stream",
    ".initrd": "application/octet-stream",
    ".img": "application/octet-stream",
    ".squashfs": "application/octet-stream",
    ".iso": "application/x-iso9660-image",
    ".kpxe": "application/octet-stream",
    ".efi": "application/octet-stream",
    ".pxe": "application/octet-stream",
    ".cfg": "text/plain",
    ".conf": "text/plain",
}


class BootHTTPHandler(BaseHTTPRequestHandler):
    """Serves boot assets from the configured boot directory."""

    boot_root: Path = Path(".")

    def do_GET(self) -> None:
        path = self.path.lstrip("/")
        if not path:
            self.send_error(404)
            return

        full_path = (self.boot_root / path).resolve()
        if not str(full_path).startswith(str(self.boot_root.resolve())):
            self.send_error(403)
            return

        if not full_path.exists() or full_path.is_dir():
            self.send_error(404)
            return

        try:
            data = full_path.read_bytes()
            ext = full_path.suffix.lower()
            content_type = MIME_TYPES.get(ext, "application/octet-stream")
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)
        except OSError as e:
            print(f"[!] HTTP: error serving {path}: {e}")
            self.send_error(500)

    def log_message(self, format: str, *args: object) -> None:
        print(f"[+] HTTP {args[0]}")


def _http_server(port: int, boot_root: Path, shutdown: threading.Event) -> None:
    """Start the HTTP file server."""
    BootHTTPHandler.boot_root = boot_root
    server = HTTPServer(("0.0.0.0", port), BootHTTPHandler)
    server.timeout = 1.0
    print(f"[*] HTTP listening on TCP {port} (root: {boot_root})")
    while not shutdown.is_set():
        server.handle_request()
