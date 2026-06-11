"""HTTP server — streams boot payloads (kernel, initrd, ISOs) to iPXE clients."""

from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path


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


def _http_server(port: int, boot_root: Path) -> None:
    """Start the HTTP file server."""
    BootHTTPHandler.boot_root = boot_root
    server = HTTPServer(("0.0.0.0", port), BootHTTPHandler)
    print(f"[*] HTTP listening on TCP {port} (root: {boot_root})")
    server.serve_forever()
